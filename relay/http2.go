package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, cidr := range strings.Fields(strings.ReplaceAll(value, ",", " ")) {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Bits() == 0 {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q; use specific proxy addresses", cidr)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("at least one trusted proxy CIDR is required")
	}
	return prefixes, nil
}

func trustedProxy(remote string, prefixes []netip.Prefix) bool {
	address, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address.Addr().Unmap()) {
			return true
		}
	}
	return false
}

// Traefik terminates TLS and forwards HTTP/2 bytes unchanged. Check the actual
// TCP peer before accepting bytes; forwarded headers never grant proxy trust.
func serveHTTP2(listener net.Listener, handler http.Handler, trusted []netip.Prefix) error {
	server := &http2.Server{MaxConcurrentStreams: 256, IdleTimeout: 90 * time.Second,
		ReadIdleTimeout: 10 * time.Second, PingTimeout: 5 * time.Second, WriteByteTimeout: 15 * time.Second,
		MaxUploadBufferPerConnection: 4 << 20, MaxUploadBufferPerStream: 256 << 10}
	maxConnections := 128
	if relay, ok := handler.(*relayServer); ok {
		if relay.h2ReadIdle > 0 {
			server.ReadIdleTimeout = relay.h2ReadIdle
		}
		if relay.h2PingTimeout > 0 {
			server.PingTimeout = relay.h2PingTimeout
		}
		if relay.maxH2Connections > 0 {
			maxConnections = relay.maxH2Connections
		}
		if relay.maxH2Streams > 0 {
			server.MaxConcurrentStreams = uint32(relay.maxH2Streams)
		}
	}
	connections := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		if !trustedProxy(conn.RemoteAddr().String(), trusted) {
			conn.Close()
			continue
		}
		select {
		case connections <- struct{}{}:
			go func() {
				defer func() { conn.Close(); <-connections }()
				server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler,
					BaseConfig: &http.Server{MaxHeaderBytes: 8192, ReadHeaderTimeout: 10 * time.Second}})
			}()
		default:
			conn.Close()
		}
	}
}

// Stop blocked writes on revocation, and join the watcher before returning the
// ResponseWriter to net/http. Normal completion must not reset a finished stream.
func (s *relayServer) watchHTTP2(w http.ResponseWriter, r *http.Request, conn net.Conn,
	token string, addr netip.Addr, origin string) (abort func(), finish func()) {
	ctx, cancel := context.WithCancel(r.Context())
	var complete atomic.Bool
	var once sync.Once
	abort = func() {
		once.Do(func() {
			conn.Close()
			r.Body.Close()
			if !complete.Load() {
				_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
			}
		})
	}
	done := make(chan struct{})
	go func() { defer close(done); s.watch(ctx, token, addr, origin, abort) }()
	finish = func() {
		complete.Store(true)
		cancel()
		<-done
	}
	return
}

type flushedWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (w flushedWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err == nil {
		err = w.rc.Flush()
	}
	return n, err
}

func (s *relayServer) proxyHTTP2TCP(w http.ResponseWriter, r *http.Request, conn *net.TCPConn,
	token string, addr netip.Addr, origin string) {
	abort, finish := s.watchHTTP2(w, r, conn, token, addr, origin)
	defer finish()
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if rc.Flush() != nil {
		abort()
		return
	}
	done := make(chan struct{})
	var responseDone atomic.Bool
	go func() {
		defer close(done)
		n, err := io.Copy(conn, r.Body)
		flowFrom(r.Context()).add(n, 0)
		_ = conn.CloseWrite()
		if err != nil && !responseDone.Load() {
			abort()
		}
	}()
	n, err := io.Copy(flushedWriter{w, rc}, conn)
	flowFrom(r.Context()).add(0, n)
	responseDone.Store(true)
	if err != nil {
		abort()
	}
	// Returning the handler sends END_STREAM; release the request reader first.
	r.Body.Close()
	conn.Close()
	<-done
}

const maxUDPPayload = 65507

// HTTP/2 carries RFC 9297 DATAGRAM capsules, including RFC 9298 context ID 0.
// Unknown capsules/contexts and oversized UDP datagrams are discarded without
// allocating according to an untrusted capsule length.
func capsulesToUDP(reader io.Reader, conn *net.UDPConn) error {
	parser := http3.NewCapsuleParser(reader)
	buffer := make([]byte, maxUDPPayload)
	for {
		kind, capsule, err := parser.Next()
		if err != nil {
			return err
		}
		if kind != 0 {
			if err := capsule.Discard(); err != nil {
				return err
			}
			continue
		}
		contextID, err := quicvarint.Read(capsule)
		if err != nil {
			return err
		}
		if contextID != 0 || capsule.Remaining() > maxUDPPayload {
			if err := capsule.Discard(); err != nil {
				return err
			}
			continue
		}
		payload := buffer[:int(capsule.Remaining())]
		if _, err := io.ReadFull(capsule, payload); err != nil {
			return err
		}
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	}
}

func (s *relayServer) proxyHTTP2UDP(w http.ResponseWriter, r *http.Request, conn *net.UDPConn,
	token string, addr netip.Addr, origin string) {
	abort, finish := s.watchHTTP2(w, r, conn, token, addr, origin)
	defer finish()
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if rc.Flush() != nil {
		abort()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = capsulesToUDP(r.Body, conn)
		conn.Close()
	}()
	buffer := make([]byte, 65536)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	writer := quicvarint.NewWriter(w)
	for {
		n, err := conn.Read(buffer[1:])
		if err != nil {
			break
		}
		if n > maxUDPPayload {
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		if err := http3.WriteCapsule(writer, 0, buffer[:n+1]); err != nil {
			break
		}
		if rc.Flush() != nil {
			break
		}
	}
	r.Body.Close()
	conn.Close()
	<-done
}
