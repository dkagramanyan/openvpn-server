package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// RELAY_CLIENT_CERTS=log: both transports ask for a client certificate, accept
// connections without one, and log what each connection presented.
func TestClientCertificatesAreLogged(t *testing.T) {
	t.Setenv("RELAY_CLIENT_CERTS", "log")
	var logs syncBuffer
	log.SetOutput(&logs)
	defer log.SetOutput(log.Writer())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsServer.Close()
	dir := t.TempDir()
	writeCertificate(t, dir, tlsServer.TLS.Certificates[0])
	files := &certificateFiles{chain: filepath.Join(dir, "fullchain.pem"), key: filepath.Join(dir, "privkey.pem")}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer auth.Close()
	s := &relayServer{api: auth.URL, client: auth.Client(), slots: make(chan struct{}, 32), recheck: time.Second,
		policyTTL: time.Second, activity: newActivity("http2+http3"), quota: &flowQuota{maximum: 32}}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveHTTP2Context(ctx, tls.NewListener(raw, files.tlsConfig("h2")), s, nil)
	free, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := free.LocalAddr().String()
	free.Close()
	var up atomic.Bool
	go s.serveHTTP3(ctx, address, files, up.Store)
	for i := 0; i < 200 && !up.Load(); i++ {
		time.Sleep(10 * time.Millisecond)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(0xbeef), Subject: pkix.Name{CommonName: "iphone-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	identity := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	base := tlsServer.Client().Transport.(*http.Transport).TLSClientConfig

	connect := func(rt http.RoundTripper, origin string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, origin, nil)
		req.Host = "192.0.2.1:443"
		req.Header.Set("Authorization", "Bearer alice:wrong")
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	// One session cache for all connections, as a phone keeps: a connection without a
	// certificate first, then one with it, must not resume the first one's session.
	base = base.Clone()
	base.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	for _, present := range []bool{false, true} {
		c := base.Clone()
		if present {
			c.Certificates = []tls.Certificate{identity}
		}
		c.NextProtos = []string{"h2"}
		h2 := &http2.Transport{TLSClientConfig: c}
		connect(h2, "https://"+raw.Addr().String())
		h2.CloseIdleConnections()
		c3 := c.Clone()
		c3.NextProtos = []string{http3.NextProtoH3}
		h3 := &http3.Transport{TLSClientConfig: c3}
		connect(h3, "https://"+address)
		h3.Close()
	}
	out := logs.String()
	for _, want := range []string{"transport=http2", "transport=http3"} {
		var with, without bool
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, want) {
				with = with || strings.Contains(line, `resumed=false present=true chain=1 subject="CN=iphone-test"`) && strings.Contains(line, "serial=beef")
				without = without || strings.Contains(line, "present=false")
			}
		}
		if !with || !without {
			t.Fatalf("%s: with=%v without=%v\n%s", want, with, without, out)
		}
	}
}

// The device a request is checked with comes from the TLS handshake only: the
// policy service gets the certificate's SHA-256 over HTTP/2 and HTTP/3, nothing
// without a certificate, and the same device again on a resumed TLS session.
func TestDeviceComesFromTheHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsServer.Close()
	dir := t.TempDir()
	writeCertificate(t, dir, tlsServer.TLS.Certificates[0])
	files := &certificateFiles{chain: filepath.Join(dir, "fullchain.pem"), key: filepath.Join(dir, "privkey.pem")}
	var mu sync.Mutex
	var seen []string
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization")+"|"+r.Header.Get("X-Relay-Device"))
		mu.Unlock()
		w.WriteHeader(403)
	}))
	defer auth.Close()
	s := &relayServer{api: auth.URL, client: auth.Client(), slots: make(chan struct{}, 32), recheck: time.Second,
		activity: newActivity("http2+http3"), quota: &flowQuota{maximum: 32}}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveHTTP2Context(ctx, tls.NewListener(raw, files.tlsConfig("h2")), s, nil)
	free, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := free.LocalAddr().String()
	free.Close()
	var up atomic.Bool
	go s.serveHTTP3(ctx, address, files, up.Store)
	for i := 0; i < 200 && !up.Load(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "relay-device-x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	sum := sha256.Sum256(der)
	want := hex.EncodeToString(sum[:])
	identity := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	base := tlsServer.Client().Transport.(*http.Transport).TLSClientConfig

	resumed := 0
	connect := func(rt http.RoundTripper, origin, token string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, origin, nil)
		req.Host = "192.0.2.1:443"
		req.Header.Set("Authorization", token)
		// A phone cannot choose its device with a header.
		req.Header.Set("X-Relay-Device", strings.Repeat("f", 64))
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.TLS != nil && resp.TLS.DidResume && strings.HasSuffix(token, "-true") {
			resumed++
		}
		resp.Body.Close()
	}
	cache := tls.NewLRUClientSessionCache(8)
	for _, present := range []bool{true, false} {
		c := base.Clone()
		if present {
			c.Certificates = []tls.Certificate{identity}
			c.ClientSessionCache = cache
		}
		c.NextProtos = []string{"h2"}
		for range 2 { // the second connection resumes the first one's session
			h2 := &http2.Transport{TLSClientConfig: c}
			connect(h2, "https://"+raw.Addr().String(), fmt.Sprintf("Bearer device:h2-%t", present))
			h2.CloseIdleConnections()
		}
		c3 := c.Clone()
		c3.NextProtos = []string{http3.NextProtoH3}
		h3 := &http3.Transport{TLSClientConfig: c3}
		connect(h3, "https://"+address, fmt.Sprintf("Bearer device:h3-%t", present))
		h3.Close()
	}
	if resumed == 0 {
		t.Fatal("no TLS session was resumed: the resumed case went untested")
	}
	mu.Lock()
	defer mu.Unlock()
	counts := map[string]int{}
	for _, line := range seen {
		counts[line]++
	}
	for line, n := range map[string]int{
		"Bearer device:h2-true|" + want: 2, "Bearer device:h3-true|" + want: 1,
		"Bearer device:h2-false|": 2, "Bearer device:h3-false|": 1} {
		if counts[line] != n {
			t.Fatalf("%q seen %d times, want %d: %v", line, counts[line], n, seen)
		}
	}
}
