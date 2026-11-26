package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
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
	return serveHTTP2Context(context.Background(), listener, handler, trusted)
}

func serveHTTP2Context(ctx context.Context, listener net.Listener, handler http.Handler, trusted []netip.Prefix) error {
	server := &http2.Server{MaxConcurrentStreams: 256, IdleTimeout: 90 * time.Second,
		ReadIdleTimeout: 10 * time.Second, PingTimeout: 5 * time.Second, WriteByteTimeout: 15 * time.Second,
		// An upload cannot go faster than its stream window per round trip:
		// 256 KB capped a phone at ~20 Mbit/s on a 100 ms path.
		// The connection's window is 16 stream windows, as before: a few
		// uploads to slow destinations must not stop the other flows.
		MaxUploadBufferPerConnection: 32 << 20, MaxUploadBufferPerStream: 2 << 20}
	protocolLogs := &transportLog{}
	maxConnections := 128
	if relay, ok := handler.(*relayServer); ok {
		protocolLogs.metrics = relay.metrics
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
	base := &http.Server{ErrorLog: log.New(protocolLogs, "", 0), MaxHeaderBytes: 8192, ReadHeaderTimeout: 10 * time.Second}
	// Register HTTP/2's shutdown hook even though Traefik supplies plain TCP
	// connections. It sends GOAWAY so clients know to open a new connection.
	if err := http2.ConfigureServer(base, server); err != nil {
		return err
	}
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-finished:
		}
	}()
	defer func() {
		if ctx.Err() != nil {
			// CONNECT streams can last indefinitely. Give clients time to see
			// GOAWAY, then end the old streams within Docker's stop deadline.
			_ = base.Shutdown(context.Background())
			drained := make(chan struct{})
			go func() { workers.Wait(); close(drained) }()
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-drained:
			case <-timer.C:
			}
			timer.Stop()
		}
		mu.Lock()
		for conn := range active {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()
	connections := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		// trusted == nil: devices connect directly over TLS (the relay's own
		// listener), so every source is accepted; behind a proxy only the proxy is.
		if trusted != nil {
			currentTrust := trusted
			if relay, ok := handler.(*relayServer); ok && relay.proxyConfig != "" {
				currentTrust = networkProxyTrust(relay.proxyConfig, trusted)
			}
			if !trustedProxy(conn.RemoteAddr().String(), currentTrust) {
				conn.Close()
				continue
			}
		}
		select {
		case connections <- struct{}{}:
			mu.Lock()
			active[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				opts := &http2.ServeConnOpts{Handler: handler, BaseConfig: base}
				defer func() {
					conn.Close()
					mu.Lock()
					delete(active, conn)
					mu.Unlock()
					<-connections
				}()
				if tc, ok := conn.(*tls.Conn); ok {
					// The handshake runs here, not in Accept: a slow client holds only its own slot.
					_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
					if err := tc.HandshakeContext(ctx); err != nil || tc.ConnectionState().NegotiatedProtocol != "h2" {
						return
					}
					_ = tc.SetDeadline(time.Time{})
					state := tc.ConnectionState()
					logClientCert("http2", conn.RemoteAddr().String(), &state)
					opts.Context = withConnectionDevice(context.Background(), &state)
				}
				server.ServeConn(conn, opts)
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
		_, err := io.Copy(trafficWriter{conn, flowFrom(r.Context()), true}, r.Body)
		_ = conn.CloseWrite()
		if err != nil && !responseDone.Load() {
			abort()
		}
	}()
	_, err := io.Copy(trafficWriter{flushedWriter{w, rc}, flowFrom(r.Context()), false}, conn)
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

var udpBuffers = sync.Pool{New: func() any { return make([]byte, 1+maxUDPPayload+1) }}

// HTTP/2 carries RFC 9297 DATAGRAM capsules, including RFC 9298 context ID 0.
// Unknown capsules/contexts and oversized UDP datagrams are discarded without
// allocating according to an untrusted capsule length.
func capsulesToUDP(reader io.Reader, conn *net.UDPConn) error {
	return countedCapsulesToUDP(reader, conn, nil)
}

func countedCapsulesToUDP(reader io.Reader, conn *net.UDPConn, flow *flowLog) error {
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
		n, err := conn.Write(payload)
		flow.add(int64(n), 0)
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(udpIdle))
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
		_ = countedCapsulesToUDP(r.Body, conn, flowFrom(r.Context()))
		conn.Close()
	}()
	// A burst (a QUIC download) arrives faster than one capsule per flush can
	// leave: read ahead into a small queue and flush once it is empty.
	_ = conn.SetReadBuffer(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(udpIdle))
	datagrams := make(chan []byte, 64)
	go func() {
		defer close(datagrams)
		for {
			buffer := udpBuffers.Get().([]byte)
			n, err := conn.Read(buffer[1:])
			if err != nil {
				udpBuffers.Put(buffer)
				return
			}
			if n > maxUDPPayload {
				udpBuffers.Put(buffer)
				continue
			}
			_ = conn.SetReadDeadline(time.Now().Add(udpIdle))
			datagrams <- buffer[:n+1]
		}
	}()
	writer := quicvarint.NewWriter(w)
	send := func(datagram []byte) error {
		datagram[0] = 0 // context ID 0
		err := http3.WriteCapsule(writer, 0, datagram)
		flowFrom(r.Context()).add(0, int64(len(datagram)-1))
		udpBuffers.Put(datagram[:cap(datagram)])
		return err
	}
relay:
	for datagram := range datagrams {
		if send(datagram) != nil {
			break
		}
		for more := true; more; {
			select {
			case next, ok := <-datagrams:
				if !ok || send(next) != nil {
					break relay
				}
			default:
				more = false
			}
		}
		if rc.Flush() != nil {
			break
		}
	}
	r.Body.Close()
	conn.Close()
	for range datagrams {
	}
	<-done
}

// Reload private UI settings for new connections; malformed saved data denies access.
func networkProxyTrust(path string, fallback []netip.Prefix) []netip.Prefix {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return fallback
	}
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "PROXY_CIDRS="); ok {
			prefixes, err := parseTrustedProxies(value)
			if err == nil {
				return prefixes
			}
			return nil
		}
	}
	return nil
}
