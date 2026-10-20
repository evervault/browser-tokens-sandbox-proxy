package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

// evervaultSources are the addresses Evervault's production browser proxy connects from.
const evervaultSources = "184.196.206.107/32,184.193.240.233/32," +
	"52.48.155.188/32,52.51.245.143/32"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	username := env("PROXY_USERNAME", "evervault")
	password := os.Getenv("PROXY_PASSWORD")
	if password == "" {
		return errors.New("PROXY_PASSWORD must be set")
	}

	allowedPorts, err := parsePorts(env("ALLOWED_PORTS", "443"))
	if err != nil {
		return err
	}
	allowedSources, err := parsePrefixes(env("ALLOWED_SOURCES", evervaultSources))
	if err != nil {
		return err
	}
	maxTunnels, err := strconv.Atoi(env("MAX_TUNNELS", "256"))
	if err != nil || maxTunnels < 1 {
		return fmt.Errorf("MAX_TUNNELS must be a positive number, got %q", os.Getenv("MAX_TUNNELS"))
	}
	idleTimeout, err := parseDuration("IDLE_TIMEOUT", "5m")
	if err != nil {
		return err
	}
	maxDuration, err := parseDuration("MAX_TUNNEL_DURATION", "1h")
	if err != nil {
		return err
	}

	logger.Warn("this proxy is for sandbox testing only, do not use it for production traffic")

	node := &tsnet.Server{
		Hostname: env("TS_HOSTNAME", "evervault-sandbox-proxy"),
		Dir:      os.Getenv("STATE_DIR"),
		UserLogf: func(format string, args ...any) {
			logger.Info(fmt.Sprintf(format, args...))
		},
	}
	defer node.Close()

	funnel, err := node.ListenFunnel("tcp", ":443", tsnet.FunnelOnly())
	if err != nil {
		return err
	}
	listener := &sourceFilter{Listener: funnel, allowed: allowedSources, logger: logger}

	handler := &proxy{
		username:     username,
		password:     password,
		allowedPorts: allowedPorts,
		resolver:     net.DefaultResolver,
		permit:       isPublic,
		tunnels:      make(chan struct{}, maxTunnels),
		idleTimeout:  idleTimeout,
		maxDuration:  maxDuration,
		logger:       logger,
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("listening",
		"hostname", strings.Join(node.CertDomains(), ","),
		"allowed_ports", allowedPorts,
		"allowed_sources", allowedSources,
	)
	return server.Serve(listener)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parsePorts(raw string) ([]uint16, error) {
	var ports []uint16
	for _, field := range strings.Split(raw, ",") {
		port, err := strconv.ParseUint(strings.TrimSpace(field), 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("ALLOWED_PORTS has an invalid port %q", field)
		}
		ports = append(ports, uint16(port))
	}
	return ports, nil
}

func parsePrefixes(raw string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			address, addrErr := netip.ParseAddr(field)
			if addrErr != nil {
				return nil, fmt.Errorf("ALLOWED_SOURCES has an invalid address or CIDR %q", field)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func parseDuration(key, fallback string) (time.Duration, error) {
	duration, err := time.ParseDuration(env(key, fallback))
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration such as 5m, got %q", key, os.Getenv(key))
	}
	return duration, nil
}
