package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func TestDestinationPolicy(t *testing.T) {
	p := policy{CIDRs: []string{"192.168.1.0/24", "fd00::/64"}}
	for _, ip := range []string{"192.168.1.42", "::ffff:192.168.1.42", "fd00::12"} {
		if !p.allows(netip.MustParseAddr(ip)) {
			t.Errorf("denied %s", ip)
		}
	}
	for _, ip := range []string{"192.168.2.1", "8.8.8.8", "fd01::1"} {
		if p.allows(netip.MustParseAddr(ip)) {
			t.Errorf("allowed %s", ip)
		}
	}
	p.CIDRs = []string{"0.0.0.0/0", "::/0"}
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888", "192.0.2.1", "192.168.1.42", "fd00::12"} {
		if !p.allows(netip.MustParseAddr(ip)) {
			t.Errorf("full access denied internet or LAN destination %s", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::", "169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1"} {
		if p.allows(netip.MustParseAddr(ip)) {
			t.Errorf("allowed special address %s", ip)
		}
	}
	for _, target := range []string{"192.168.1.42:0", "192.168.1.42:65536", "localhost:80", "[::1]:80", "bad-target"} {
		if _, err := resolveAll(context.Background(), target, p); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}

// Use the host's LAN address for destinations so the integration test also
// exercises the production loopback prohibition. Traffic stays on this host.
func localIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addrs {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
			return prefix.Addr().String()
		}
	}
	t.Fatal("integration test needs a non-loopback IPv4 interface")
	return ""
}

func TestRelayTCPUDPAndRevocation(t *testing.T) {
	ip := localIP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// httptest supplies a test certificate; the client explicitly trusts it.
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsServer.Close()
	cert := tlsServer.TLS.Certificates[0]
	clientTLS := tlsServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	origin := "https://" + packet.LocalAddr().String()
	var revoked atomic.Bool
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() || r.Header.Get("Authorization") != "Bearer alice:secret" {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(policy{CIDRs: []string{ip + "/32"}, URL: origin})
	}))
	defer auth.Close()
	handler := &relayServer{api: auth.URL, client: &http.Client{Timeout: time.Second}, slots: make(chan struct{}, 32), recheck: 30 * time.Millisecond, policyTTL: 15 * time.Millisecond}
	server := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, EnableDatagrams: true}
	go server.Serve(packet)
	defer server.Close()
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
	tr := &masque.Transport{TLSClientConfig: clientTLS}
	template := uritemplate.MustNew(origin + udpPath)
	request, err := masque.NewRequest(ctx, template, udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	request.Header().Set("Authorization", "Bearer alice:secret")
	udpFlow, response, err := tr.Dial(request)
	if err != nil {
		t.Fatalf("UDP CONNECT: %v (%v)", err, response)
	}
	defer udpFlow.Close()
	udpFlow.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := udpFlow.WriteTo([]byte("udp-echo"), udpFlow.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 100)
	n, _, err := udpFlow.ReadFrom(b)
	if err != nil || string(b[:n]) != "udp-echo" {
		t.Fatalf("UDP echo: %q %v", b[:n], err)
	}
	// Plain CONNECT to a LAN TCP server over the same HTTP/3 protocol.
	qc, err := quic.DialAddr(ctx, packet.LocalAddr().String(), clientTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(0, "")
	h3 := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qc)
	stream, err := h3.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, origin, nil)
	req.Host = tcp.Addr().String()
	req.Header.Set("Authorization", "Bearer alice:secret")
	if err := stream.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := stream.ReadResponse()
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("TCP CONNECT: %v %v", resp, err)
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := stream.Write([]byte("tcp-echo")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, b[:8]); err != nil || string(b[:8]) != "tcp-echo" {
		t.Fatalf("TCP echo: %q %v", b[:8], err)
	}
	// Concurrent bulk streams share one QUIC connection. Half-closing the
	// upload must still permit the full response, without truncation or leaks.
	var transfers sync.WaitGroup
	for range 16 {
		transfers.Add(1)
		go func() {
			defer transfers.Done()
			flow, err := h3.OpenRequestStream(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer flow.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			if err = flow.SendRequestHeader(req); err != nil {
				t.Error(err)
				return
			}
			resp, err := flow.ReadResponse()
			if err != nil || resp.StatusCode != 200 {
				t.Errorf("bulk CONNECT: %v %v", resp, err)
				return
			}
			flow.SetDeadline(time.Now().Add(10 * time.Second))
			data := bytes.Repeat([]byte("relay-bulk-test!"), 65536)
			written := make(chan error, 1)
			go func() { _, err := flow.Write(data); flow.Close(); written <- err }()
			echoed, err := io.ReadAll(flow)
			if err != nil || !bytes.Equal(echoed, data) {
				t.Errorf("bulk transfer: got %d/%d bytes: %v", len(echoed), len(data), err)
			}
			if err = <-written; err != nil {
				t.Error(err)
			}
		}()
	}
	transfers.Wait()
	for _, target := range []string{"127.0.0.1:53", "8.8.8.8:53"} {
		r, _ := masque.NewRequest(ctx, template, target)
		r.Header().Set("Authorization", "Bearer alice:secret")
		_, resp, err := tr.Dial(r)
		if err == nil || resp == nil || resp.StatusCode != 403 {
			t.Fatalf("target %s: %v %v", target, resp, err)
		}
	}
	unauthorized, _ := masque.NewRequest(ctx, template, udp.LocalAddr().String())
	if _, resp, err := tr.Dial(unauthorized); err == nil || resp.StatusCode != 403 {
		t.Fatalf("unauthenticated: %v %v", resp, err)
	}
	revoked.Store(true)
	stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := stream.Read(b); err == nil {
		t.Fatal("TCP flow survived revocation")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("TCP revocation timed out")
	}
	udpFlow.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := udpFlow.ReadFrom(b); err == nil {
		t.Fatal("UDP flow survived revocation")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("UDP revocation timed out")
	}
}

func TestGuestPolicy(t *testing.T) {
	p := policy{Guest: true, CIDRs: []string{"0.0.0.0/0"}, Blocked: []string{"192.0.2.0/24", "203.0.113.0/24", "198.51.100.4/32"}}
	if p.allows(netip.MustParseAddr("198.51.100.4")) {
		t.Fatal("guest can loop back through the public reverse proxy")
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "::ffff:8.8.8.8"} {
		if !p.allows(netip.MustParseAddr(ip)) {
			t.Errorf("guest public destination denied: %s", ip)
		}
	}
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "192.0.2.1", "203.0.113.1", "::ffff:192.168.1.1", "64:ff9b::c0a8:101", "2002:c0a8:101::1", "2001:4860:4860::8888", "198.18.0.1", "240.0.0.1", localIP(t)} {
		if p.allows(netip.MustParseAddr(ip)) {
			t.Errorf("guest protected destination allowed: %s", ip)
		}
	}
	p.Blocked = []string{"invalid"}
	if p.allows(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("malformed block policy failed open")
	}
}

func TestTCPFallsBackToReachableAddress(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailable := netip.MustParseAddrPort(first.Addr().String())
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	first.Close()
	reachable := netip.MustParseAddrPort(second.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, used, err := dialTCP(ctx, []netip.AddrPort{unavailable, reachable})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if used != reachable {
		t.Fatalf("connected to %s, want %s", used, reachable)
	}
}

func TestAuthorizeFailsClosed(t *testing.T) {
	for _, status := range []int{403, 500, 302} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			s := &relayServer{api: server.URL, client: server.Client()}
			if _, err := s.authorize(context.Background(), "Bearer a:b"); err == nil {
				t.Fatal("allowed")
			}
		})
	}
	s := &relayServer{}
	for _, token := range []string{"", "Basic foo", "Bearer " + strings.Repeat("x", 513)} {
		if _, err := s.authorize(context.Background(), token); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
}
