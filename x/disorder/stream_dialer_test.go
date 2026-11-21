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

package disorder

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"
)

// trackedConn wraps the socket as a dialer's connection tracker does: its
// type isn't *net.TCPConn, and NetConn returns the socket.
type trackedConn struct{ *net.TCPConn }

func (c trackedConn) NetConn() net.Conn { return c.TCPConn }

type wrappingDialer struct{ wrap bool }

func (d wrappingDialer) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	conn, err := (&transport.TCPDialer{}).DialStream(ctx, addr)
	if err != nil || !d.wrap {
		return conn, err
	}
	return trackedConn{conn.(*net.TCPConn)}, nil
}

func TestDisorderOverWrappedConn(t *testing.T) {
	for _, wrap := range []bool{false, true} {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		received := make(chan []byte, 1)
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			b, _ := io.ReadAll(c)
			received <- b
		}()

		dialer, err := NewStreamDialer(wrappingDialer{wrap: wrap}, 1)
		require.NoError(t, err)
		conn, err := dialer.DialStream(context.Background(), l.Addr().String())
		require.NoError(t, err, "wrap=%v", wrap)
		_, err = conn.Write([]byte("hello"))
		require.NoError(t, err)
		_, err = conn.Write([]byte(" world"))
		require.NoError(t, err)
		require.NoError(t, conn.CloseWrite())
		require.Equal(t, "hello world", string(<-received), "wrap=%v", wrap)
		conn.Close()
		l.Close()
	}
}
