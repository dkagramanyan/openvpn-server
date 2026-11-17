package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

func writeCertificate(t *testing.T, dir string, cert tls.Certificate) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{"fullchain.pem": {Type: "CERTIFICATE", Bytes: cert.Certificate[0]},
		"privkey.pem": {Type: "PRIVATE KEY", Bytes: key}} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// One relay process serves an HTTP/2-only profile and an HTTP/3 profile with
// the same credential, starts HTTP/3 once the certificate appears, and counts
// HTTP/3 UDP payload bytes.
func TestHTTP2AndHTTP3TogetherWithOneCredential(t *testing.T) {
	ip := localIP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsServer.Close()
	clientTLS := tlsServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	free, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := free.LocalAddr().String()
	free.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Both transports are published under one origin (TCP and UDP of one port).
	origin := "https://" + address
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer alice:secret" {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(policy{Client: "alice", CredentialID: "c1", URL: origin, CIDRs: []string{ip + "/32"}})
	}))
	defer auth.Close()
	s := &relayServer{api: auth.URL, client: auth.Client(), slots: make(chan struct{}, 32), recheck: time.Second,
		policyTTL: time.Second, activity: newActivity("http2+http3"), quota: &flowQuota{maximum: 32}}
	trusted, _ := parseTrustedProxies("127.0.0.1/32")
	go serveHTTP2(listener, s, trusted)

	dir := t.TempDir()
	files := &certificateFiles{chain: filepath.Join(dir, "fullchain.pem"), key: filepath.Join(dir, "privkey.pem")}
	if _, err := files.get(); err == nil {
		t.Fatal("certificate before the files exist")
	}
	writeCertificate(t, dir, tlsServer.TLS.Certificates[0])
	files.checked = time.Time{}
	var up atomic.Bool
	h3ctx, stopHTTP3 := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- s.serveHTTP3(h3ctx, address, files, up.Store) }()
	for range 200 {
		if up.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !up.Load() {
		t.Fatal("HTTP/3 did not start")
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFromUDP(b)
			if err != nil {
				return
			}
			udp.WriteToUDP(b[:n], addr)
		}
	}()
	tcp, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	// HTTP/3 profile: CONNECT-UDP.
	tr := &masque.Transport{TLSClientConfig: clientTLS}
	request, err := masque.NewRequest(ctx, uritemplate.MustNew(origin+udpPath), udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	request.Header().Set("Authorization", "Bearer alice:secret")
	flow, response, err := tr.Dial(request)
	if err != nil {
		t.Fatalf("HTTP/3 UDP: %v (%v)", err, response)
	}
	defer flow.Close()
	if response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		t.Errorf("HTTP/3 CONNECT-UDP answered without Capsule-Protocol: %v", response.Header)
	}
	flow.SetDeadline(time.Now().Add(3 * time.Second))
	payload := make([]byte, 1000)
	for range 3 {
		if _, err := flow.WriteTo(payload, flow.RemoteAddr()); err != nil {
			t.Fatal(err)
		}
		if n, _, err := flow.ReadFrom(make([]byte, 2000)); err != nil || n != 1000 {
			t.Fatalf("HTTP/3 UDP echo: %d %v", n, err)
		}
	}

	// HTTP/2-only profile (installed before the upgrade): same credential, TCP.
	h2 := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}}
	defer h2.CloseIdleConnections()
	input, output := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+listener.Addr().String(), input)
	req.Host = tcp.Addr().String()
	req.Header.Set("Authorization", "Bearer alice:secret")
	resp, err := h2.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("HTTP/2 TCP: %v %v", resp, err)
	}
	go output.Write([]byte("tcp-echo"))
	if _, err := io.ReadFull(resp.Body, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}

	state := readActivity(t, s.activity, "/status")
	seen := map[string]flowEvent{}
	for _, f := range state.Active {
		seen[f.Transport] = f
	}
	if f := seen["http3"]; f.Protocol != "UDP" || f.BytesUp != 3000 || f.BytesDown != 3000 || !f.Counted || f.Client != "alice" {
		t.Fatalf("HTTP/3 UDP flow is not counted: %+v", f)
	}
	if f := seen["http2"]; f.Protocol != "TCP" || f.BytesDown != 8 || f.SessionID != seen["http3"].SessionID {
		t.Fatalf("HTTP/2 flow: %+v (HTTP/3 session %s)", f, seen["http3"].SessionID)
	}
	// The numeric destination actually dialled, for classifying the traffic.
	if seen["http3"].Address != udp.LocalAddr().String() || seen["http2"].Address != tcp.Addr().String() {
		t.Fatalf("dialled addresses: %q %q", seen["http3"].Address, seen["http2"].Address)
	}
	output.Close()
	resp.Body.Close()

	// Stopping HTTP/3 ends its flows and leaves HTTP/2 serving.
	stopHTTP3()
	if err := <-served; !errors.Is(err, context.Canceled) {
		t.Fatalf("HTTP/3 stop: %v", err)
	}
	if up.Load() {
		t.Fatal("HTTP/3 still reported as listening")
	}
	flow.SetDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := flow.ReadFrom(make([]byte, 10)); err == nil {
		t.Fatal("HTTP/3 flow survived its server")
	}
}

func TestRenewedCertificateIsLoadedWithoutRestart(t *testing.T) {
	first, second := httptest.NewTLSServer(nil), httptest.NewUnstartedServer(nil)
	defer first.Close()
	second.StartTLS()
	defer second.Close()
	dir := t.TempDir()
	files := &certificateFiles{chain: filepath.Join(dir, "fullchain.pem"), key: filepath.Join(dir, "privkey.pem")}
	writeCertificate(t, dir, first.TLS.Certificates[0])
	a, err := files.get()
	if err != nil {
		t.Fatal(err)
	}
	// A half-written pair keeps the certificate in use.
	if err := os.WriteFile(files.key, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	os.Chtimes(files.key, later, later)
	files.checked = time.Time{}
	if b, err := files.get(); err != nil || b != a {
		t.Fatalf("broken pair replaced the certificate: %v", err)
	}
	writeCertificate(t, dir, second.TLS.Certificates[0])
	later = later.Add(time.Minute)
	os.Chtimes(files.key, later, later)
	files.checked = time.Time{}
	b, err := files.get()
	if err != nil || b == a {
		t.Fatalf("renewed certificate not loaded: %v", err)
	}
}

func TestLookupsAreSharedAndExpire(t *testing.T) {
	var queries atomic.Int32
	release := make(chan struct{})
	cache := &dnsCache{query: func(ctx context.Context, host string) ([]netip.Addr, error) {
		queries.Add(1)
		<-release
		if host == "missing.example" {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}}
	results := make(chan error, 20)
	for range 20 {
		go func() {
			addrs, err := cache.resolve(context.Background(), "Example.COM.")
			if err == nil && (len(addrs) != 1 || addrs[0].String() != "203.0.113.7") {
				err = errors.New("wrong answer")
			}
			results <- err
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	for range 20 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if queries.Load() != 1 {
		t.Fatalf("%d lookups for 20 simultaneous flows", queries.Load())
	}
	if _, err := cache.resolve(context.Background(), "example.com"); err != nil || queries.Load() != 1 {
		t.Fatal("cached answer not reused")
	}
	cache.mu.Lock()
	cache.entries["example.com"].expires = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	if _, err := cache.resolve(context.Background(), "example.com"); err != nil || queries.Load() != 2 {
		t.Fatal("expired answer reused")
	}
	// Failures are not kept; literal addresses need no lookup.
	for range 2 {
		if _, err := cache.resolve(context.Background(), "missing.example"); err == nil {
			t.Fatal("failure expected")
		}
	}
	if queries.Load() != 4 {
		t.Fatalf("failed lookup was cached: %d", queries.Load())
	}
	if addrs, err := cache.resolve(context.Background(), "192.0.2.1"); err != nil || len(addrs) != 1 || queries.Load() != 4 {
		t.Fatal("literal address was looked up")
	}
}
