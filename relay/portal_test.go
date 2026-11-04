package main

import (
	"context"
	"encoding/json"
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
)

func TestGuestReachesOnlyThePortal(t *testing.T) {
	portal, err := parseGuestPortal(portalConfig{Host: "OpenVPN.Example.test", Target: "192.0.2.13:9443"})
	if err != nil {
		t.Fatal(err)
	}
	s := &relayServer{}
	p := policy{Portal: &portalConfig{Host: "openvpn.example.test", Target: portal.target.String()}, Guest: true}
	for _, target := range []string{"openvpn.example.test:443", "OPENVPN.EXAMPLE.TEST.:443"} {
		ctx, addresses, err := s.resolveDestination(context.Background(), target, p, true)
		if err != nil || len(addresses) != 1 || addresses[0] != portal.target || !s.portalFlow(ctx, portal.target.Addr(), p) {
			t.Fatalf("portal %s: %v %v", target, addresses, err)
		}
		if s.portalFlow(ctx, netip.MustParseAddr("192.0.2.30"), p) {
			t.Fatal("portal flow escaped its pinned destination")
		}
	}
	// No internet, no LAN, no other port or protocol, not even the portal's own addresses.
	for _, target := range []string{"example.com:443", "8.8.8.8:443", "192.0.2.13:443", "192.0.2.13:9443", "openvpn.example.test:80", "openvpn.example.test:8443", "127.0.0.1:443"} {
		if _, _, err := s.resolveDestination(context.Background(), target, p, true); err == nil {
			t.Fatalf("guest allowed %s", target)
		}
	}
	if _, _, err := s.resolveDestination(context.Background(), "openvpn.example.test:443", p, false); err == nil {
		t.Fatal("guest allowed UDP to the portal")
	}
	if s.portalFlow(context.Background(), portal.target.Addr(), p) {
		t.Fatal("a flow without the pinned portal target passed")
	}
	noPortal := policy{Guest: true}
	if _, _, err := s.resolveDestination(context.Background(), "openvpn.example.test:443", noPortal, true); err == nil {
		t.Fatal("guest without a configured portal reached it")
	}
	full := policy{CIDRs: []string{"0.0.0.0/0"}}
	_, addresses, err := s.resolveDestination(context.Background(), "192.0.2.13:443", full, true)
	if err != nil || addresses[0].Port() != 443 {
		t.Fatal("full-access route changed")
	}
}

func TestGuestPortalConfiguration(t *testing.T) {
	for _, target := range []string{"", "192.0.2.13:443", "127.0.0.1:9443", "169.254.169.254:9443", "0.0.0.0:9443", "[::1]:9443", "host:9443"} {
		if _, err := parseGuestPortal(portalConfig{Host: "openvpn.example.test", Target: target}); err == nil {
			t.Fatalf("accepted %s", target)
		}
	}
	for _, host := range []string{"", "https://openvpn.example.test", "openvpn.example.test:443"} {
		if _, err := parseGuestPortal(portalConfig{Host: host, Target: "192.0.2.13:9443"}); err == nil {
			t.Fatalf("accepted host %q", host)
		}
	}
	p := policy{Guest: true, Portal: &portalConfig{Host: "openvpn.example.test", Target: "bad"}}
	if p.compile() == nil {
		t.Fatal("malformed portal policy compiled")
	}
}

func TestGuestPortalStillRevalidatesAuthorization(t *testing.T) {
	var revoked atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(policy{Portal: &portalConfig{Host: "openvpn.example.test", Target: "192.0.2.13:9443"}, Client: "guest", Guest: true, URL: "https://relay.example.test"})
	}))
	defer api.Close()
	portal, _ := parseGuestPortal(portalConfig{Host: "openvpn.example.test", Target: "192.0.2.13:9443"})
	s := &relayServer{api: api.URL, client: api.Client(), recheck: 10 * time.Millisecond, policyTTL: time.Millisecond}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), portalFlowKey{}, portal.target))
	defer cancel()
	closed := make(chan struct{})
	go s.watch(ctx, "Bearer guest:secret", portal.target.Addr(), "https://relay.example.test", func() { close(closed) })
	select {
	case <-closed:
		t.Fatal("authorized portal flow closed")
	case <-time.After(100 * time.Millisecond):
	}
	revoked.Store(true)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("revoked portal flow stayed open")
	}
}

func TestHTTP2GuestPortalTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ip := localIP(t)
	destination, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	go func() {
		conn, err := destination.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(conn, conn)
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	origin, transport := h2Frontend(t, listener.Addr().String(), false)
	defer transport.CloseIdleConnections()
	var revoked atomic.Bool
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() || r.Header.Get("Authorization") != "Bearer guest:secret" {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(policy{Portal: &portalConfig{Host: "openvpn.example.test", Target: destination.Addr().String()}, Guest: true, Client: "guest", URL: origin})
	}))
	defer auth.Close()
	s := &relayServer{api: auth.URL, client: auth.Client(), slots: make(chan struct{}, 4), recheck: 10 * time.Millisecond, policyTTL: time.Millisecond}
	trusted, _ := parseTrustedProxies("127.0.0.1/32")
	go serveHTTP2(listener, s, trusted)
	for _, target := range []string{destination.Addr().String(), "openvpn.example.test:443"} {
		input, output := io.Pipe()
		req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, origin, input)
		req.Host = target
		req.Header.Set("Authorization", "Bearer guest:secret")
		resp, err := transport.RoundTrip(req)
		if err != nil {
			output.Close()
			t.Fatal(err)
		}
		if target == destination.Addr().String() {
			output.Close()
			resp.Body.Close()
			if resp.StatusCode != 403 {
				t.Fatal("direct LAN target accepted")
			}
			continue
		}
		defer output.Close()
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("portal CONNECT: %d", resp.StatusCode)
		}
		for range 2 {
			if _, err := output.Write([]byte("portal")); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 6)
			if _, err := io.ReadFull(resp.Body, data); err != nil || string(data) != "portal" {
				t.Fatalf("portal echo: %q %v", data, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		revoked.Store(true)
		closed := make(chan error, 1)
		go func() { _, err := resp.Body.Read(make([]byte, 1)); closed <- err }()
		select {
		case err := <-closed:
			if err == nil {
				t.Fatal("revocation left portal open")
			}
		case <-time.After(time.Second):
			t.Fatal("portal tunnel survived revocation")
		}
	}
}

func TestPrivateProxySettingsReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.conf")
	fallback, _ := parseTrustedProxies("127.0.0.1/32")
	if !trustedProxy("127.0.0.1:1234", networkProxyTrust(path, fallback)) {
		t.Fatal("bootstrap trust missing")
	}
	os.WriteFile(path, []byte("PROXY_CIDRS=192.0.2.10/32\n"), 0600)
	if !trustedProxy("192.0.2.10:1234", networkProxyTrust(path, fallback)) {
		t.Fatal("UI trust not loaded")
	}
	os.WriteFile(path, []byte("PROXY_CIDRS=0.0.0.0/0\n"), 0600)
	if len(networkProxyTrust(path, fallback)) != 0 {
		t.Fatal("malformed settings did not fail closed")
	}
}
