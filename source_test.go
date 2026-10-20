package main

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/ipn"
)

type queuedListener struct {
	net.Listener
	conns chan net.Conn
}

func (l *queuedListener) Accept() (net.Conn, error) {
	conn, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

type closeRecorder struct {
	net.Conn
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}

func funnelConn(source string) (*tls.Conn, *closeRecorder) {
	recorder := &closeRecorder{}
	funnel := &ipn.FunnelConn{Conn: recorder, Src: netip.MustParseAddrPort(source)}
	return tls.Server(funnel, &tls.Config{}), recorder
}

func TestSourceFilter(t *testing.T) {
	refused, refusedRecorder := funnelConn("203.0.113.9:40000")
	mapped, _ := funnelConn("[::ffff:50.17.50.37]:40000")
	allowed, _ := funnelConn("50.17.50.37:40000")
	notFunnel := &closeRecorder{}

	conns := make(chan net.Conn, 4)
	conns <- refused
	conns <- notFunnel
	conns <- mapped
	conns <- allowed
	close(conns)

	filter := &sourceFilter{
		Listener: &queuedListener{conns: conns},
		allowed:  []netip.Prefix{netip.MustParsePrefix("50.17.50.37/32")},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	for _, want := range []net.Conn{mapped, allowed} {
		got, err := filter.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if got != want {
			t.Fatalf("accepted %v, want %v", got, want)
		}
	}
	if !refusedRecorder.closed || !notFunnel.closed {
		t.Fatal("connections from other sources were not closed")
	}
	if _, err := filter.Accept(); err != net.ErrClosed {
		t.Fatalf("accept after queue = %v, want net.ErrClosed", err)
	}
}

func TestEvervaultSources(t *testing.T) {
	prefixes, err := parsePrefixes(evervaultSources)
	if err != nil {
		t.Fatalf("parsePrefixes: %v", err)
	}
	for _, prefix := range prefixes {
		if !prefix.Addr().Is4() || prefix.Bits() != 32 || !isPublic(prefix.Addr()) {
			t.Errorf("%s is not a single public IPv4 address", prefix)
		}
	}
}

func TestParsePrefixes(t *testing.T) {
	prefixes, err := parsePrefixes("50.17.50.37, 10.1.2.3/8,2001:db8::1")
	if err != nil {
		t.Fatalf("parsePrefixes: %v", err)
	}
	want := []string{"50.17.50.37/32", "10.0.0.0/8", "2001:db8::1/128"}
	for i, prefix := range prefixes {
		if prefix.String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, prefix, want[i])
		}
	}

	if _, err := parsePrefixes("not-an-ip"); err == nil {
		t.Fatal("parsePrefixes accepted an invalid address")
	}
}
