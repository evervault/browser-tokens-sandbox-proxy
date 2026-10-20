package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const dialTimeout = 10 * time.Second

var errRefusedAddress = errors.New("not on the public internet")

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type proxy struct {
	username     string
	password     string
	allowedPorts []uint16
	resolver     resolver
	permit       func(netip.Addr) bool
	tunnels      chan struct{}
	idleTimeout  time.Duration
	maxDuration  time.Duration
	logger       *slog.Logger
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorised(r.Header.Get("Proxy-Authorization")) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		p.logger.Warn("refused", "reason", "authentication", "remote", r.RemoteAddr)
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}

	host, port, err := p.target(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		p.logger.Warn("refused", "target", r.Host, "reason", err)
		return
	}

	select {
	case p.tunnels <- struct{}{}:
		defer func() { <-p.tunnels }()
	default:
		http.Error(w, "too many open tunnels", http.StatusServiceUnavailable)
		p.logger.Warn("refused", "target", r.Host, "reason", "tunnel limit")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	upstream, err := p.dial(ctx, host, port)
	cancel()
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errRefusedAddress) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		p.logger.Warn("refused", "target", r.Host, "reason", err)
		return
	}
	defer upstream.Close()

	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		p.logger.Error("hijack failed", "error", err)
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	started := time.Now()
	deadline := &tunnelDeadline{
		conns: []net.Conn{client, upstream},
		idle:  p.idleTimeout,
		end:   started.Add(p.maxDuration),
	}
	sent, received := relay(client, buffered, upstream, deadline)
	p.logger.Info("tunnel closed",
		"target", r.Host,
		"upstream", upstream.RemoteAddr().String(),
		"sent", sent,
		"received", received,
		"duration", time.Since(started).Round(time.Millisecond).String(),
	)
}

func (p *proxy) authorised(header string) bool {
	encoded, ok := strings.CutPrefix(header, "Basic ")
	if !ok {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}

	usernameMatches := subtle.ConstantTimeCompare([]byte(username), []byte(p.username))
	passwordMatches := subtle.ConstantTimeCompare([]byte(password), []byte(p.password))
	return usernameMatches&passwordMatches == 1
}

func (p *proxy) target(authority string) (string, uint16, error) {
	host, rawPort, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, fmt.Errorf("target %q has no port", authority)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("target port %q is not a port", rawPort)
	}
	if !slices.Contains(p.allowedPorts, uint16(port)) {
		return "", 0, fmt.Errorf("target port %d is not allowed", port)
	}
	return host, uint16(port), nil
}

// dial resolves host, refuses it if any address is not public, and connects
// only to the addresses it checked.
func (p *proxy) dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	addresses, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%s did not resolve", host)
	}
	for i, address := range addresses {
		addresses[i] = address.Unmap()
	}
	for _, address := range addresses {
		if !p.permit(address) {
			return nil, fmt.Errorf("%s resolves to %s, which is %w", host, address, errRefusedAddress)
		}
	}

	var dialer net.Dialer
	var lastErr error
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(address, port).String())
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func relay(client net.Conn, buffered io.Reader, upstream net.Conn, deadline *tunnelDeadline) (sent, received int64) {
	deadline.extend()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sent, _ = io.Copy(upstream, activityReader{buffered, deadline})
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		received, _ = io.Copy(client, activityReader{upstream, deadline})
		closeWrite(client)
	}()
	wg.Wait()
	return sent, received
}

// tunnelDeadline closes a tunnel once it has been idle for idle, or at end,
// whichever comes first.
type tunnelDeadline struct {
	conns []net.Conn
	idle  time.Duration
	end   time.Time
}

func (d *tunnelDeadline) extend() {
	next := time.Now().Add(d.idle)
	if next.After(d.end) {
		next = d.end
	}
	for _, conn := range d.conns {
		_ = conn.SetDeadline(next)
	}
}

type activityReader struct {
	io.Reader
	deadline *tunnelDeadline
}

func (r activityReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 {
		r.deadline.extend()
	}
	return n, err
}

func closeWrite(conn net.Conn) {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
		return
	}
	_ = conn.Close()
}
