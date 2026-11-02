// Apple Network Relay. Credentials and destination policy belong to the VPN UI;
// this process never needs the VPN CA key or write access to its state.
package main

import (
	"context"
	"crypto/tls"
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

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const udpPath = "/.well-known/masque/udp/{target_host}/{target_port}/"

type relayServer struct {
	api       string
	client    *http.Client
	slots     chan struct{}
	recheck   time.Duration
	policyTTL time.Duration
	authMu    sync.Mutex
	policies  map[[32]byte]*policyEntry
}

// Revalidate live tunnels as well as new requests. Policy changes, expiry,
// revocation and an unavailable UI all close active flows within ~9 seconds.
func (s *relayServer) watch(ctx context.Context, token string, addr netip.Addr, origin string, closeFlow func()) {
	ticker := time.NewTicker(s.recheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			closeFlow()
			return
		case <-ticker.C:
			p, err := s.authorize(ctx, token)
			if err != nil || p.URL != origin || !p.allows(addr) {
				closeFlow()
				return
			}
		}
	}
}

func (s *relayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", 405)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "Relay busy", 503)
		return
	}
	token := r.Header.Get("Authorization")
	p, err := s.authorize(r.Context(), token)
	if err != nil {
		http.Error(w, "Relay access denied", 403)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var udpReq *masque.ProxyRequest
	target := r.Host
	protocol := r.Proto
	if r.ProtoMajor == 2 {
		protocol = r.Header.Get(":protocol")
	}
	if protocol == "connect-udp" {
		template, err := uritemplate.New(p.URL + udpPath)
		if err != nil {
			http.Error(w, "Invalid relay configuration", 503)
			return
		}
		request := r.Clone(ctx)
		request.Proto = "connect-udp" // masque-go's HTTP/3 representation
		udpReq, err = masque.ParseProxyRequest(request, template)
		if err != nil {
			http.Error(w, "Invalid UDP request", 400)
			return
		}
		target = udpReq.Target
	} else if !((r.ProtoMajor == 2 && protocol == "") || r.Proto == "HTTP/3.0") {
		http.Error(w, "Unsupported CONNECT protocol", 400)
		return
	}
	addresses, err := resolveAll(ctx, target, p)
	if err != nil {
		http.Error(w, "Destination unavailable or denied", 403)
		return
	}
	// Dial the numeric address we checked, never resolve a hostname twice.
	if udpReq != nil {
		var conn *net.UDPConn
		var addr netip.AddrPort
		for _, candidate := range addresses {
			conn, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(candidate))
			if err == nil {
				addr = candidate
				break
			}
		}
		if err != nil {
			http.Error(w, "Destination unavailable", 502)
			return
		}
		defer conn.Close()
		if r.ProtoMajor == 2 {
			s.proxyHTTP2UDP(w, r, conn, token, addr.Addr(), p.URL)
			return
		}
		proxy := &masque.Proxy{}
		var once sync.Once
		closeProxy := func() { once.Do(func() { proxy.Close() }) }
		defer closeProxy()
		go s.watch(ctx, token, addr.Addr(), p.URL, closeProxy)
		_ = proxy.ProxyConnectedSocket(w, udpReq, conn)
		return
	}
	conn, addr, err := dialTCP(ctx, addresses)
	if err != nil {
		http.Error(w, "Destination unavailable", 502)
		return
	}
	defer conn.Close()
	if r.ProtoMajor == 2 {
		s.proxyHTTP2TCP(w, r, conn.(*net.TCPConn), token, addr.Addr(), p.URL)
		return
	}
	stream := w.(http3.HTTPStreamer).HTTPStream()
	var outputComplete atomic.Bool
	closeFlow := func() {
		conn.Close()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
		// Resetting a successfully closed QUIC write side discards queued final
		// packets. Let its FIN/data be acknowledged after the handler returns.
		if !outputComplete.Load() {
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeConnectError))
		}
	}
	defer closeFlow()
	w.WriteHeader(http.StatusOK)
	go s.watch(ctx, token, addr.Addr(), p.URL, closeFlow)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := io.Copy(conn, stream)
		_ = conn.(*net.TCPConn).CloseWrite()
		if err != nil {
			closeFlow()
		}
	}()
	if _, err := io.Copy(stream, conn); err != nil {
		closeFlow()
	} else {
		outputComplete.Store(true)
		_ = stream.Close()
	}
	<-done
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func main() {
	handler := &relayServer{
		api: env("RELAY_AUTH_URL", "http://127.0.0.1:8080/api/relay/authorize"),
		client: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 32, IdleConnTimeout: 90 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		slots: make(chan struct{}, 256), recheck: 5 * time.Second, policyTTL: time.Second,
	}
	mode := env("RELAY_TRANSPORT", "http2")
	if mode == "http2" {
		if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
			log.Fatal("HTTP/2 relay requires GODEBUG=http2xconnect=1 (set by the Docker image)")
		}
		trusted, err := parseTrustedProxies(env("RELAY_TRUSTED_PROXIES", "127.0.0.1/32 ::1/128"))
		if err != nil {
			log.Fatal(err)
		}
		listener, err := net.Listen("tcp", env("RELAY_HTTP2_BIND", ":8444"))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Apple Network Relay HTTP/2 backend listening on %s; TLS terminates at the trusted proxy", listener.Addr())
		log.Fatal(serveHTTP2(listener, handler, trusted))
	}
	if mode != "http3" {
		log.Fatal("RELAY_TRANSPORT must be http2 or http3")
	}
	cert, err := tls.LoadX509KeyPair("/tls/fullchain.pem", "/tls/privkey.pem")
	if err != nil {
		log.Fatalf("HTTP/3 TLS setup required: put fullchain.pem and privkey.pem in APPLE_RELAY_TLS_DIR, readable by UID 65532: %v", err)
	}
	server := &http3.Server{
		Addr: env("RELAY_BIND", ":8443"), Handler: handler, EnableDatagrams: true,
		TLSConfig:      http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}),
		MaxHeaderBytes: 8192,
		QUICConfig:     &quic.Config{KeepAlivePeriod: 20 * time.Second, MaxIdleTimeout: 90 * time.Second},
	}
	log.Printf("Apple Network Relay listening on %s/udp", server.Addr)
	log.Fatal(server.ListenAndServe())
}
