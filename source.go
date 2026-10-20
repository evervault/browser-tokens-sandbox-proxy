package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"

	"tailscale.com/ipn"
)

// sourceFilter closes Funnel connections whose client address is outside allowed,
// before the TLS handshake.
type sourceFilter struct {
	net.Listener
	allowed []netip.Prefix
	logger  *slog.Logger
}

func (f *sourceFilter) Accept() (net.Conn, error) {
	for {
		conn, err := f.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source, ok := funnelSource(conn)
		if ok && f.permits(source) {
			return conn, nil
		}
		conn.Close()
		f.logger.Warn("refused", "reason", "source not allowed", "source", source)
	}
}

func (f *sourceFilter) permits(source netip.Addr) bool {
	for _, prefix := range f.allowed {
		if prefix.Contains(source) {
			return true
		}
	}
	return false
}

func funnelSource(conn net.Conn) (netip.Addr, bool) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	funnel, ok := conn.(*ipn.FunnelConn)
	if !ok {
		return netip.Addr{}, false
	}
	return funnel.Src.Addr().Unmap(), true
}
