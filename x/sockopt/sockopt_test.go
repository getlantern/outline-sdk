// Copyright 2024 The Outline Authors
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

package sockopt

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTCPOptions(t *testing.T) {
	type Params struct {
		Net  string
		Addr string
	}
	for _, params := range []Params{{Net: "tcp4", Addr: "127.0.0.1:0"}, {Net: "tcp6", Addr: "[::1]:0"}} {
		l, err := net.Listen(params.Net, params.Addr)
		require.NoError(t, err)
		defer l.Close()

		conn, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)
		tcpConn, ok := conn.(*net.TCPConn)
		require.True(t, ok)

		opts, err := NewTCPOptions(tcpConn)
		require.NoError(t, err)

		require.NoError(t, opts.SetHopLimit(1))

		hoplim, err := opts.HopLimit()
		require.NoError(t, err)
		require.Equal(t, 1, hoplim)

		require.NoError(t, opts.SetHopLimit(20))

		hoplim, err = opts.HopLimit()
		require.NoError(t, err)
		require.Equal(t, 20, hoplim)
	}
}

// wrappedConn hides the socket's type, as a dialer's connection tracker does,
// and gives it back through NetConn.
type wrappedConn struct{ net.Conn }

func (c wrappedConn) NetConn() net.Conn { return c.Conn }

// selfConn reports itself as what it wraps, which must not loop. Its slice
// field makes it uncomparable, which must not panic.
type selfConn struct {
	net.Conn
	_ []string
}

func (c selfConn) NetConn() net.Conn { return c }

func TestTCPConnOf(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	tcp := conn.(*net.TCPConn)

	for name, c := range map[string]net.Conn{
		"bare":          tcp,
		"wrapped":       wrappedConn{tcp},
		"wrapped twice": wrappedConn{wrappedConn{tcp}},
	} {
		got, ok := TCPConnOf(c)
		require.True(t, ok, name)
		require.Same(t, tcp, got, name)
	}

	// The socket is found under exactly maxWrapperDepth wrappers, not one more.
	var atLimit net.Conn = tcp
	for range maxWrapperDepth {
		atLimit = wrappedConn{atLimit}
	}
	got, ok := TCPConnOf(atLimit)
	require.True(t, ok, "at the wrapper limit")
	require.Same(t, tcp, got)
	_, ok = TCPConnOf(wrappedConn{atLimit})
	require.False(t, ok, "past the wrapper limit")

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udp.Close()
	for name, c := range map[string]net.Conn{
		"not TCP":         udp,
		"wrapped not TCP": wrappedConn{udp},
		"self":            selfConn{Conn: udp},
		"nil":             nil,
	} {
		_, ok := TCPConnOf(c)
		require.False(t, ok, name)
	}
}
