// Apple Network Relay. Credentials and destination policy belong to the VPN UI;
// this process never needs the VPN CA key or write access to its state.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const udpPath = "/.well-known/masque/udp/{target_host}/{target_port}/"

type relayServer struct {
	api              string
	client           *http.Client
	slots            chan struct{}
	recheck          time.Duration
	policyTTL        time.Duration
	authMu           sync.Mutex
	policies         map[[32]byte]*policyEntry
	activity         *activityLog
	quota            *flowQuota
	authSlots        chan struct{}
	metrics          *relayMetrics
	maxH2Connections int
	maxH2Streams     int
	h2ReadIdle       time.Duration
	h2PingTimeout    time.Duration
	proxyConfig      string
	udpRefused       []netip.Prefix
}

// Revalidate live tunnels as well as new requests. Policy changes, expiry,
// revocation and unavailable policy state close active flows within ~9 seconds.
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
			if ctx.Err() != nil {
				closeFlow()
				return
			}
			if err != nil || p.URL != origin || !(p.allows(addr) || s.portalFlow(ctx, addr, p)) {
				reason := "access_revoked"
				if err != nil && !errors.Is(err, errAccessDenied) {
					reason = "authorization_unavailable"
				}
				flowFrom(ctx).reason(reason)
				closeFlow()
				return
			}
		}
	}
}

func (s *relayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flow := s.activity.begin()
	defer flow.finish()
	r = r.WithContext(context.WithValue(r.Context(), flowKey{}, flow))
	logClientCertRequest(r)
	if flow != nil {
		flow.event.Transport = "http3"
		if r.ProtoMajor == 2 {
			flow.event.Transport = "http2"
		}
		flow.event.Method = r.Method
		if len(flow.event.Method) > 32 {
			flow.event.Method = "OTHER"
		}
	}
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", "CONNECT")
		reject(w, r, 405, "unsupported_method", "CONNECT required", "http_request_error")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		reject(w, r, 503, "capacity_reached", "Relay busy", "connection_limit_reached")
		return
	}
	token := withDevice(r.Header.Get("Authorization"), requestDevice(r))
	p, err := s.authorize(r.Context(), token)
	if err != nil {
		if errors.Is(err, errAccessDenied) {
			reject(w, r, 403, "authorization_denied", "Relay access denied", "http_request_denied")
		} else {
			w.Header().Set("Retry-After", "1")
			reject(w, r, 503, "authorization_unavailable", "Relay authorization temporarily unavailable", "proxy_internal_error")
		}
		return
	}
	if flow != nil {
		flow.event.Client, flow.event.Guest = p.Client, p.Guest
		flow.identity = p.CredentialID
	}
	identity := p.Client
	if identity == "" {
		identity = token
	}
	release, ok := s.quota.acquire(identity)
	if !ok {
		w.Header().Set("Retry-After", "1")
		reject(w, r, 503, "client_capacity_reached", "Client relay capacity reached", "connection_limit_reached")
		return
	}
	defer release()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var udpReq *masque.ProxyRequest
	target := r.Host
	protocol := r.Proto
	if r.ProtoMajor == 2 {
		protocol = r.Header.Get(":protocol")
	}
	if protocol == "connect-udp" {
		if flow != nil {
			flow.event.Protocol = "UDP"
		}
		template, err := uritemplate.New(p.URL + udpPath)
		if err != nil {
			reject(w, r, 503, "invalid_configuration", "Invalid relay configuration", "proxy_configuration_error")
			return
		}
		request := r.Clone(ctx)
		request.Proto = "connect-udp" // masque-go's HTTP/3 representation
		udpReq, err = masque.ParseProxyRequest(request, template)
		if err != nil {
			reject(w, r, 400, "invalid_udp_request", "Invalid UDP request", "http_request_error")
			return
		}
		target = udpReq.Target
	} else if !((r.ProtoMajor == 2 && protocol == "") || r.Proto == "HTTP/3.0") {
		reject(w, r, 400, "unsupported_protocol", "Unsupported CONNECT protocol", "http_request_error")
		return
	} else if flow != nil {
		flow.event.Protocol = "TCP"
	}
	if flow != nil {
		if host, port, err := net.SplitHostPort(target); err == nil && len(host) <= 253 && len(port) <= 5 {
			flow.event.Target = net.JoinHostPort(host, port)
		}
		flow.event.Counted = true
	}
	resolved := time.Now()
	ctx, addresses, err := s.resolveDestination(ctx, target, p, udpReq == nil)
	r = r.WithContext(ctx)
	s.metrics.observe("dns_lookups", resolved)
	if err != nil {
		switch {
		case errors.Is(err, errInvalidTarget):
			reject(w, r, 400, "invalid_target", "Invalid target", "http_request_error")
		case errors.Is(err, errDNSFailed):
			reject(w, r, 502, "dns_failed", "Destination DNS unavailable", "dns_error")
		default:
			reject(w, r, 403, "destination_denied", "Destination denied", "destination_ip_prohibited")
		}
		return
	}
	// Dial the numeric address we checked, never resolve a hostname twice.
	if udpReq != nil {
		// A UDP socket opens to anything, so a range that never answers UDP (the
		// LAN router's FakeIP proxy) is refused here: the app goes to TCP at once.
		addresses = slices.DeleteFunc(addresses, func(a netip.AddrPort) bool {
			return slices.ContainsFunc(s.udpRefused, func(p netip.Prefix) bool { return p.Contains(a.Addr()) })
		})
		if len(addresses) == 0 {
			reject(w, r, 502, "udp_unavailable", "UDP unavailable for this destination", "destination_ip_unroutable")
			return
		}
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
			reject(w, r, 502, "destination_unreachable", "Destination unavailable", connectionError(err))
			return
		}
		defer conn.Close()
		flow.dialled(addr)
		flow.connected()
		if r.ProtoMajor == 2 {
			s.proxyHTTP2UDP(w, r, conn, token, addr.Addr(), p.URL)
			return
		}
		s.proxyHTTP3UDP(ctx, w, conn, token, addr.Addr(), p.URL)
		return
	}
	dialStarted := time.Now()
	conn, addr, err := s.connectTCP(ctx, addresses)
	s.metrics.observe("tcp_dials", dialStarted)
	if err != nil {
		reject(w, r, 502, "destination_unreachable", "Destination unavailable", connectionError(err))
		return
	}
	defer conn.Close()
	flow.dialled(addr)
	flow.connected()
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
		_, err := io.Copy(trafficWriter{conn, flow, true}, stream)
		_ = conn.(*net.TCPConn).CloseWrite()
		if err != nil && !outputComplete.Load() {
			closeFlow()
		}
	}()
	_, err = io.Copy(trafficWriter{stream, flow, false}, conn)
	if err != nil {
		closeFlow()
	} else {
		outputComplete.Store(true)
		_ = stream.Close()
	}
	conn.Close() // Release an upload that remains open after the destination's FIN.
	<-done
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func main() {
	maximum, err := limitEnv("RELAY_MAX_FLOWS", 2048, 65536)
	if err != nil {
		log.Fatal(err)
	}
	perClient, err := limitEnv("RELAY_MAX_FLOWS_PER_CLIENT", min(512, maximum), maximum)
	if err != nil {
		log.Fatal(err)
	}
	authChecks, err := limitEnv("RELAY_MAX_AUTH_CHECKS", 64, 4096)
	if err != nil {
		log.Fatal(err)
	}
	h2Connections, err := limitEnv("RELAY_MAX_H2_CONNECTIONS", 128, 4096)
	if err != nil {
		log.Fatal(err)
	}
	h2Streams, err := limitEnv("RELAY_MAX_H2_STREAMS", 512, 65536)
	if err != nil {
		log.Fatal(err)
	}
	readIdle, err := durationEnv("RELAY_H2_READ_IDLE", 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	pingTimeout, err := durationEnv("RELAY_H2_PING_TIMEOUT", 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	// Destinations that take TCP but drop UDP; "off" refuses none.
	var udpRefused []netip.Prefix
	if value := env("RELAY_UDP_REFUSED", "198.18.0.0/15"); value != "off" {
		for _, cidr := range strings.Fields(value) {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				log.Fatalf("RELAY_UDP_REFUSED: %v", err)
			}
			udpRefused = append(udpRefused, prefix.Masked())
		}
	}
	handler := &relayServer{
		udpRefused:  udpRefused,
		proxyConfig: os.Getenv("RELAY_NETWORK_CONFIG"),
		api:         env("RELAY_AUTH_URL", "http://127.0.0.1:8447/api/relay/authorize"),
		client: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 32, IdleConnTimeout: 90 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		slots: make(chan struct{}, maximum), recheck: 5 * time.Second, policyTTL: time.Second,
		quota: &flowQuota{maximum: perClient}, authSlots: make(chan struct{}, authChecks), metrics: &relayMetrics{},
		maxH2Connections: h2Connections, maxH2Streams: h2Streams, h2ReadIdle: readIdle, h2PingTimeout: pingTimeout,
	}
	// "http2+http3" serves both at once: profiles that carry both URLs use
	// HTTP/3 and fall back to HTTP/2, and HTTP/2-only profiles keep working.
	mode := env("RELAY_TRANSPORT", "http2")
	if mode == "both" {
		mode = "http2+http3"
	}
	if mode != "http2" && mode != "http3" && mode != "http2+http3" {
		log.Fatal("RELAY_TRANSPORT must be http2, http3 or http2+http3")
	}
	useHTTP2, useHTTP3 := mode != "http3", mode != "http2"
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handler.activity = newActivity(mode)
	handler.activity.runtime = handler.metrics
	handler.activity.limits = map[string]int{"flows": maximum, "per_client": perClient, "auth_checks": authChecks, "h2_connections": h2Connections, "h2_streams": h2Streams}
	// Ready = the policy answers AND a client listener is open. /readyz
	// opens before the listeners, and waitForPolicy polls only once a second,
	// so without the second condition a check could pass before the relay
	// accepts connections.
	var http2Up, http2Direct, http3Up atomic.Bool
	handler.activity.listening = func() map[string]bool {
		return map[string]bool{"http2": http2Up.Load() || http2Direct.Load(), "http2_direct": http2Direct.Load(), "http3": http3Up.Load()}
	}
	// One certificate for HTTP/3 and the direct HTTP/2 listener, reloaded within 30 s when renewed.
	files := &certificateFiles{chain: "/tls/fullchain.pem", key: "/tls/privkey.pem"}
	handler.activity.certificate = files.details
	handler.activity.readiness = func(ctx context.Context) error {
		if !http2Up.Load() && !http2Direct.Load() && !http3Up.Load() {
			return errAuthUnavailable
		}
		return handler.checkReadiness(ctx)
	}
	admin, err := handler.activity.listen(env("RELAY_ADMIN_BIND", "127.0.0.1:8446"))
	if err != nil {
		log.Fatal(err)
	}
	defer admin.Close()
	// Docker can restart containers concurrently after a host reboot. Do not
	// accept client connections until the persistent policy state is ready.
	log.Print("Waiting for relay policy and database readiness")
	if err := handler.waitForPolicy(ctx); err != nil {
		return
	}
	failed := make(chan error, 2)
	var listeners sync.WaitGroup
	if useHTTP3 {
		if mode == "http3" {
			if _, err := files.get(); err != nil {
				log.Fatalf("HTTP/3 TLS setup required: put fullchain.pem and privkey.pem in APPLE_RELAY_TLS_DIR, readable by UID 65532: %v", err)
			}
		}
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			for {
				err := handler.serveHTTP3(ctx, env("RELAY_BIND", ":8443"), files, http3Up.Store)
				if ctx.Err() != nil {
					return
				}
				if !useHTTP2 {
					failed <- err
					return
				}
				// Installed profiles use HTTP/2: an HTTP/3 fault (a busy UDP
				// port, for example) must not take that down with it.
				log.Printf("HTTP/3 listener stopped, retrying in 30 s: %v", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
		}()
	}
	if useHTTP2 {
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
		http2Up.Store(true)
		log.Printf("Apple Network Relay HTTP/2 backend listening on %s; TLS terminates at the trusted proxy", listener.Addr())
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			if err := serveHTTP2Context(ctx, listener, handler, trusted); err != nil && ctx.Err() == nil {
				failed <- err
			}
		}()
		// HTTP/2 straight from the devices, over TLS with the relay's own certificate
		// (the same TCP port number as HTTP/3's UDP one). "off" leaves it to the proxy.
		if bind := env("RELAY_HTTP2_TLS_BIND", "off"); bind != "off" {
			if _, err := files.get(); err != nil {
				log.Printf("HTTP/2 over TLS on %s is waiting for /tls/fullchain.pem and /tls/privkey.pem (readable by UID 65532): %v", bind, err)
			}
			listeners.Add(1)
			go func() {
				defer listeners.Done()
				// Like HTTP/3, a fault here (the port taken by a proxy on the same host,
				// for example) never stops the gateway's backend: retry every 30 s.
				for {
					direct, err := net.Listen("tcp", bind)
					if err == nil {
						http2Direct.Store(true)
						log.Printf("Apple Network Relay HTTP/2 listening on %s (TLS, the relay's own certificate)", direct.Addr())
						err = serveHTTP2Context(ctx, tls.NewListener(direct, files.tlsConfig("h2")), handler, nil)
						http2Direct.Store(false)
					}
					if ctx.Err() != nil {
						return
					}
					log.Printf("HTTP/2 over TLS on %s stopped, retrying in 30 s: %v", bind, err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(30 * time.Second):
					}
				}
			}()
		}
	}
	select {
	case err := <-failed:
		log.Fatal(err)
	case <-ctx.Done():
	}
	listeners.Wait()
}
