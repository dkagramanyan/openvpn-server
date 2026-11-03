package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// RFC 9209 fields contain fixed tokens only, never network errors/credentials.
func reject(w http.ResponseWriter, r *http.Request, status int, reason, message, proxyError string) {
	f := flowFrom(r.Context())
	f.reason(reason)
	if f != nil {
		f.event.Status = status
		f.event.UpstreamError = proxyError
	}
	w.Header().Set("Proxy-Status", "openvpn-relay; error="+proxyError)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}
func connectionError(err error) string {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return "destination_ip_unroutable"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "connection_timeout"
	}
	return "connection_terminated"
}

// One retry before sending a successful CONNECT response or application data.
// Reuse only already validated numeric addresses, within one five-second budget.
func (s *relayServer) connectTCP(ctx context.Context, addresses []netip.AddrPort) (net.Conn, netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, addr, err := dialTCP(ctx, addresses)
	if err == nil || ctx.Err() != nil {
		return conn, addr, err
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return nil, addr, err
	}
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, addr, ctx.Err()
	case <-timer.C:
	}
	s.metrics.observe("tcp_setup_retries", time.Time{})
	return dialTCP(ctx, addresses)
}

type trafficWriter struct {
	writer io.Writer
	flow   *flowLog
	upload bool
}

func (w trafficWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if w.upload {
		w.flow.add(int64(n), 0)
	} else {
		w.flow.add(0, int64(n))
	}
	return n, err
}
