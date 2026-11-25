// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

var errShutdown = errors.New("shutting down")

// queryCancelled queries r with a context that is cancelled, with no deadline,
// after a short wait, and fails unless the query returns soon after.
func queryCancelled(t *testing.T, r Resolver) {
	t.Helper()
	q, err := NewQuestion("example.com.", dnsmessage.TypeA)
	require.NoError(t, err)
	const wait = 50 * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	start := time.Now()
	time.AfterFunc(wait, func() { cancel(errShutdown) })
	errc := make(chan error, 1)
	go func() {
		_, err := r.Query(ctx, *q)
		errc <- err
	}()
	select {
	case err := <-errc:
		// Still waiting when cancelled, and failed because it was.
		require.GreaterOrEqual(t, time.Since(start), wait)
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, errShutdown)
		require.ErrorIs(t, err, ErrReceive)
	case <-time.After(5 * time.Second):
		t.Fatal("the query was still waiting for an answer long after its context was cancelled")
	}
}

// A resolver that never answers mustn't hold a query whose context is
// cancelled without a deadline, as DNS-over-TLS and -TCP did.
func TestStreamResolverCancelledWithoutDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	queryCancelled(t, NewTCPResolver(&transport.TCPDialer{}, ln.Addr().String()))
}

func TestUDPResolverCancelledWithoutDeadline(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()
	queryCancelled(t, NewUDPResolver(&transport.UDPDialer{}, pc.LocalAddr().String()))
}

// A DNS-over-HTTPS resolver closes a connection that has been idle for
// httpsIdleConnTimeout, rather than holding it until the server does.
func TestHTTPSResolverClosesIdleConnections(t *testing.T) {
	saved := httpsIdleConnTimeout
	httpsIdleConnTimeout = 100 * time.Millisecond
	defer func() { httpsIdleConnTimeout = saved }()

	closed := make(chan struct{})
	// The handler runs off the test goroutine, so it reports errors with
	// t.Errorf and http.Error rather than require.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := answerDNS(r.Body)
		if err != nil {
			t.Errorf("DoH handler: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	}))
	var once sync.Once
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			once.Do(func() { close(closed) })
		}
	}
	srv.Start()
	defer srv.Close()

	r := NewHTTPSResolver(&transport.TCPDialer{}, srv.Listener.Addr().String(), srv.URL+"/dns-query")
	q, err := NewQuestion("example.com.", dnsmessage.TypeA)
	require.NoError(t, err)
	_, err = r.Query(context.Background(), *q)
	require.NoError(t, err)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the resolver kept its idle connection open")
	}
}

// answerDNS answers the DNS query in body with one A record.
func answerDNS(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	var req dnsmessage.Message
	if err := req.Unpack(data); err != nil {
		return nil, err
	}
	resp, err := newMessageResponse(req, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}, 60)
	if err != nil {
		return nil, err
	}
	return resp.Pack()
}

// A DNS-over-TLS resolver whose handshake fails closes the TCP connection
// it dialed, rather than leaving it to the server.
func TestTLSResolverClosesConnectionOnHandshakeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	closed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Not TLS, so the client's handshake fails at once.
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		io.Copy(io.Discard, conn)
		close(closed)
	}()
	q, err := NewQuestion("example.com.", dnsmessage.TypeA)
	require.NoError(t, err)
	_, err = NewTLSResolver(&transport.TCPDialer{}, ln.Addr().String(), "dns.example").Query(context.Background(), *q)
	require.Error(t, err)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the resolver left the connection of a failed handshake open")
	}
}

// A query whose context reached its deadline reports it, even when the conn's
// deadline fires before the context's own timer.
func TestWithCancelCauseDeadlinePassed(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	timeout := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	require.ErrorIs(t, withCancelCause(ctx, timeout), context.DeadlineExceeded)
	// Not a timeout: left alone.
	require.Equal(t, io.EOF, withCancelCause(ctx, io.EOF))
	// A live context: left alone.
	require.Equal(t, error(timeout), withCancelCause(context.Background(), timeout))
}
