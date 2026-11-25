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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// queryCancelled queries r with a context that is cancelled, with no deadline,
// after a short wait, and fails unless the query returns soon after.
func queryCancelled(t *testing.T, r Resolver) {
	t.Helper()
	q, err := NewQuestion("example.com.", dnsmessage.TypeA)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	errc := make(chan error, 1)
	go func() {
		_, err := r.Query(ctx, *q)
		errc <- err
	}()
	select {
	case err := <-errc:
		require.Error(t, err)
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
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req dnsmessage.Message
		require.NoError(t, req.Unpack(body))
		resp, err := newMessageResponse(req, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}, 60)
		require.NoError(t, err)
		wire, err := resp.Pack()
		require.NoError(t, err)
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
