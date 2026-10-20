package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testUsername = "evervault"
	testPassword = "correct-horse"
)

type fixedResolver map[string][]netip.Addr

func (r fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addresses, ok := r[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	return addresses, nil
}

type testProxy struct {
	address string
}

func newProxy(resolver resolver, permit func(netip.Addr) bool, ports ...uint16) *proxy {
	return &proxy{
		username:     testUsername,
		password:     testPassword,
		allowedPorts: ports,
		resolver:     resolver,
		permit:       permit,
		tunnels:      make(chan struct{}, 4),
		idleTimeout:  time.Minute,
		maxDuration:  time.Hour,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func startProxy(t *testing.T, resolver resolver, permit func(netip.Addr) bool, ports ...uint16) testProxy {
	t.Helper()
	return serve(t, newProxy(resolver, permit, ports...))
}

func serve(t *testing.T, handler *proxy) testProxy {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return testProxy{address: server.Listener.Addr().String()}
}

func credentials(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func connect(t *testing.T, proxyAddress, target, authorization string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if authorization != "" {
		request += "Proxy-Authorization: " + authorization + "\r\n"
	}
	if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return conn, reader, response
}

func startEcho(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func allowAll(netip.Addr) bool { return true }

func TestMissingCredentialsAreRefused(t *testing.T) {
	p := startProxy(t, fixedResolver{}, allowAll, 443)

	_, _, response := connect(t, p.address, "merchant.example:443", "")

	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", response.StatusCode)
	}
	if got := response.Header.Get("Proxy-Authenticate"); !strings.HasPrefix(got, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q, want a Basic challenge", got)
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	p := startProxy(t, fixedResolver{}, allowAll, 443)

	_, _, response := connect(t, p.address, "merchant.example:443", credentials(testUsername, "wrong"))

	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", response.StatusCode)
	}
}

func TestPlainRequestsAreRefused(t *testing.T) {
	p := startProxy(t, fixedResolver{}, allowAll, 443)

	request, _ := http.NewRequest(http.MethodGet, "http://"+p.address+"/", nil)
	request.Header.Set("Proxy-Authorization", credentials(testUsername, testPassword))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.StatusCode)
	}
}

func TestDisallowedPortIsRefused(t *testing.T) {
	p := startProxy(t, fixedResolver{}, allowAll, 443)

	_, _, response := connect(t, p.address, "merchant.example:22", credentials(testUsername, testPassword))

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
}

func TestHostResolvingToPrivateAddressIsRefused(t *testing.T) {
	resolver := fixedResolver{
		"router.example": {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.168.1.1")},
	}
	p := startProxy(t, resolver, isPublic, 443)

	_, _, response := connect(t, p.address, "router.example:443", credentials(testUsername, testPassword))

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
}

func TestPrivateLiteralIsRefused(t *testing.T) {
	p := startProxy(t, net.DefaultResolver, isPublic, 443)

	_, _, response := connect(t, p.address, "127.0.0.1:443", credentials(testUsername, testPassword))

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
}

func TestPermittedTargetIsTunnelled(t *testing.T) {
	echoPort := startEcho(t)
	resolver := fixedResolver{"merchant.example": {netip.MustParseAddr("127.0.0.1")}}
	p := startProxy(t, resolver, allowAll, echoPort)
	target := "merchant.example:" + strconv.Itoa(int(echoPort))

	conn, reader, response := connect(t, p.address, target, credentials(testUsername, testPassword))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	const payload = "hello through the tunnel"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(echoed) != payload {
		t.Fatalf("echoed %q, want %q", echoed, payload)
	}
}

func openTunnel(t *testing.T, handler *proxy, echoPort uint16) (net.Conn, *bufio.Reader) {
	t.Helper()
	p := serve(t, handler)
	target := "merchant.example:" + strconv.Itoa(int(echoPort))
	conn, reader, response := connect(t, p.address, target, credentials(testUsername, testPassword))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	return conn, reader
}

func waitForClose(t *testing.T, conn net.Conn, reader *bufio.Reader, within time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	_, err := reader.ReadByte()
	if err != io.EOF {
		t.Fatalf("read = %v, want the tunnel closed with EOF", err)
	}
}

func TestIdleTunnelIsClosed(t *testing.T) {
	echoPort := startEcho(t)
	handler := newProxy(fixedResolver{"merchant.example": {netip.MustParseAddr("127.0.0.1")}}, allowAll, echoPort)
	handler.idleTimeout = 100 * time.Millisecond

	conn, reader := openTunnel(t, handler, echoPort)

	waitForClose(t, conn, reader, 2*time.Second)
}

func TestBusyTunnelIsClosedAtMaxDuration(t *testing.T) {
	echoPort := startEcho(t)
	handler := newProxy(fixedResolver{"merchant.example": {netip.MustParseAddr("127.0.0.1")}}, allowAll, echoPort)
	handler.idleTimeout = 100 * time.Millisecond
	handler.maxDuration = 400 * time.Millisecond

	conn, reader := openTunnel(t, handler, echoPort)
	started := time.Now()
	for time.Since(started) < 300*time.Millisecond {
		if _, err := io.WriteString(conn, "x"); err != nil {
			t.Fatalf("write while busy: %v", err)
		}
		if _, err := reader.ReadByte(); err != nil {
			t.Fatalf("tunnel closed after %s while busy: %v", time.Since(started), err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	waitForClose(t, conn, reader, 2*time.Second)
}
