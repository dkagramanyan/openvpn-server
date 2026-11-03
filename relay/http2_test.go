package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

func h2Frontend(t *testing.T, backend string, traefik bool) (string, *http2.Transport) {
	t.Helper()
	if !traefik {
		return "http://" + backend, &http2.Transport{AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, backend)
			}}
	}
	binary := os.Getenv("TRAEFIK_BIN")
	if binary == "" {
		t.Skip("set TRAEFIK_BIN to test through real Traefik TLS termination")
	}
	dir := t.TempDir()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(fixture.Close)
	cert := fixture.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := free.Addr().String()
	free.Close()
	dynamic := fmt.Sprintf(`tcp:
  routers:
    relay:
      entryPoints: [relay]
      rule: "HostSNI(%s)"
      service: relay
      tls:
        options: relay-http2
  services:
    relay:
      loadBalancer:
        servers:
          - address: %q
tls:
  options:
    relay-http2:
      minVersion: VersionTLS12
      alpnProtocols: [h2]
  certificates:
    - certFile: %q
      keyFile: %q
`, "`example.com`", backend, certPath, keyPath)
	dynamicPath := filepath.Join(dir, "dynamic.yml")
	staticPath := filepath.Join(dir, "traefik.yml")
	for path, content := range map[string]string{dynamicPath: dynamic,
		staticPath: fmt.Sprintf("entryPoints:\n  relay:\n    address: %q\nproviders:\n  file:\n    filename: %q\nlog:\n  level: ERROR\n", address, dynamicPath)} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "traefik.log")
	logs, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--configFile="+staticPath)
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		logs.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		logs.Close()
		if t.Failed() {
			output, _ := os.ReadFile(logPath)
			t.Logf("Traefik output: %s", output)
		}
	})
	clientTLS := fixture.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	clientTLS.ServerName = "example.com"
	clientTLS.NextProtos = []string{"h2"}
	ready := false
	for range 100 {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", address, clientTLS)
		if err == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		output, _ := os.ReadFile(logPath)
		t.Fatalf("Traefik did not listen: %s", output)
	}
	tr := &http2.Transport{TLSClientConfig: clientTLS,
		DialTLSContext: func(ctx context.Context, network, _ string, config *tls.Config) (net.Conn, error) {
			return (&tls.Dialer{Config: config}).DialContext(ctx, network, address)
		}}
	_, port, _ := net.SplitHostPort(address)
	return "https://example.com:" + port, tr
}

func TestHTTP2TCPUDPAndRevocation(t *testing.T) {
	for _, traefik := range []bool{false, true} {
		t.Run(fmt.Sprintf("traefik=%v", traefik), func(t *testing.T) {
			ip := localIP(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			origin, transport := h2Frontend(t, listener.Addr().String(), traefik)
			defer transport.CloseIdleConnections()
			var revoked atomic.Bool
			auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if revoked.Load() || r.Header.Get("Authorization") != "Bearer alice:secret" {
					w.WriteHeader(403)
					return
				}
				json.NewEncoder(w).Encode(policy{URL: origin, CIDRs: []string{ip + "/32"}})
			}))
			defer auth.Close()
			s := &relayServer{api: auth.URL, client: auth.Client(), slots: make(chan struct{}, 32),
				recheck: 30 * time.Millisecond, policyTTL: 15 * time.Millisecond, activity: newActivity("http2")}
			trusted, _ := parseTrustedProxies("127.0.0.1/32")
			go serveHTTP2(listener, s, trusted)
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
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				buffer := make([]byte, 65536)
				for {
					n, peer, err := udp.ReadFromUDP(buffer)
					if err != nil {
						return
					}
					udp.WriteToUDP(buffer[:n], peer)
				}
			}()
			connect := func(target string, udp bool, token string) (*http.Response, *io.PipeWriter, error) {
				input, output := io.Pipe()
				url := origin
				if udp {
					host, port, _ := net.SplitHostPort(target)
					url += "/.well-known/masque/udp/" + host + "/" + port + "/"
				}
				req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, url, input)
				req.Header.Set("Authorization", token)
				if udp {
					req.Header.Set(":protocol", "connect-udp")
					req.Header.Set(http3.CapsuleProtocolHeader, "?1")
				} else {
					req.Host = target
				}
				response, err := transport.RoundTrip(req)
				if err != nil || response.StatusCode != 200 {
					output.Close()
				}
				return response, output, err
			}
			// Many bidirectional streams, including upload EOF followed by response EOF.
			var transfers sync.WaitGroup
			for range 8 {
				transfers.Add(1)
				go func() {
					defer transfers.Done()
					resp, writer, err := connect(tcp.Addr().String(), false, "Bearer alice:secret")
					if err != nil || resp.StatusCode != 200 {
						t.Errorf("TCP CONNECT: %v %v", resp, err)
						return
					}
					defer resp.Body.Close()
					data := bytes.Repeat([]byte("http2-bulk-test!"), 65536)
					written := make(chan error, 1)
					go func() { _, err := writer.Write(data); writer.Close(); written <- err }()
					echo, err := io.ReadAll(resp.Body)
					if err != nil || !bytes.Equal(echo, data) {
						t.Errorf("TCP echo: %d/%d bytes, %v", len(echo), len(data), err)
					}
					if err := <-written; err != nil {
						t.Error(err)
					}
				}()
			}
			transfers.Wait()
			resp, writer, err := connect(udp.LocalAddr().String(), true, "Bearer alice:secret")
			if err != nil || resp.StatusCode != 200 || resp.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
				t.Fatalf("UDP CONNECT: %v %v", resp, err)
			}
			defer resp.Body.Close()
			defer writer.Close()
			capsuleWriter := quicvarint.NewWriter(writer)
			// Unknown capsule/context and an oversized datagram must not desynchronize parsing.
			http3.WriteCapsule(capsuleWriter, 42, []byte("unknown capsule"))
			http3.WriteCapsule(capsuleWriter, 0, []byte{1, 99})
			http3.WriteCapsule(capsuleWriter, 0, make([]byte, maxUDPPayload+2))
			parser := http3.NewCapsuleParser(resp.Body)
			for _, payload := range [][]byte{[]byte("udp-echo"), {}, bytes.Repeat([]byte("d"), 4096)} {
				if err := http3.WriteCapsule(capsuleWriter, 0, append([]byte{0}, payload...)); err != nil {
					t.Fatal(err)
				}
				kind, capsule, err := parser.Next()
				if err != nil || kind != 0 {
					t.Fatalf("UDP response: %v %v", kind, err)
				}
				got, err := io.ReadAll(capsule)
				if err != nil || !bytes.Equal(got, append([]byte{0}, payload...)) {
					t.Fatalf("UDP echo: %d bytes, %v", len(got), err)
				}
			}
			// Check live payload counters before the UDP flow is closed.
			var counted bool
			for attempt := 0; attempt < 20; attempt++ {
				for _, f := range readActivity(t, s.activity, "/status").Active {
					if f.Protocol == "UDP" && f.Counted && f.BytesUp == 4104 && f.BytesDown == 4104 {
						counted = true
					}
				}
				if counted {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !counted {
				t.Fatal("live HTTP/2 UDP payload counts did not match echoed datagrams")
			}
			for _, udp := range []bool{false, true} {
				for _, test := range []struct{ target, token string }{{"127.0.0.1:80", "Bearer alice:secret"}, {"8.8.8.8:53", "Bearer alice:secret"}, {tcp.Addr().String(), ""}} {
					r, output, err := connect(test.target, udp, test.token)
					output.Close()
					if err != nil || r.StatusCode != 403 {
						t.Fatalf("denied CONNECT: %v %v", r, err)
					}
					r.Body.Close()
				}
			}
			activeTCP, tcpWriter, err := connect(tcp.Addr().String(), false, "Bearer alice:secret")
			if err != nil || activeTCP.StatusCode != 200 {
				t.Fatalf("active TCP: %v %v", activeTCP, err)
			}
			defer activeTCP.Body.Close()
			defer tcpWriter.Close()
			// A client that stops reading exhausts its HTTP/2 flow-control window.
			// Revocation must release the blocked handler and its connection slot.
			flood, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer flood.Close()
			go func() {
				c, err := flood.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				chunk := make([]byte, 65536)
				for range 1024 {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}()
			blocked, blockedWriter, err := connect(flood.Addr().String(), false, "Bearer alice:secret")
			if err != nil || blocked.StatusCode != 200 {
				t.Fatalf("blocked TCP: %v %v", blocked, err)
			}
			defer blocked.Body.Close()
			defer blockedWriter.Close()
			time.Sleep(100 * time.Millisecond)
			revoked.Store(true)
			for _, body := range []io.Reader{resp.Body, activeTCP.Body} {
				closed := make(chan error, 1)
				go func() { b := make([]byte, 1); _, err := body.Read(b); closed <- err }()
				select {
				case err := <-closed:
					if err == nil {
						t.Fatal("flow survived revocation")
					}
				case <-time.After(2 * time.Second):
					t.Fatal("revocation timed out")
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for len(s.slots) != 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if len(s.slots) != 0 {
				t.Fatal("revocation leaked a blocked handler")
			}
		})
	}
}

func TestHTTP2ProxyTrust(t *testing.T) {
	for _, invalid := range []string{"", "0.0.0.0/0", "::/0", "invalid"} {
		if _, err := parseTrustedProxies(invalid); err == nil {
			t.Errorf("accepted proxy trust %q", invalid)
		}
	}
	trusted, err := parseTrustedProxies("192.0.2.13/32,::1/128")
	if err != nil || !trustedProxy("192.0.2.13:9999", trusted) || !trustedProxy("[::1]:9999", trusted) || trustedProxy("192.0.2.99:9999", trusted) {
		t.Fatal("proxy trust does not match actual peer addresses")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	go serveHTTP2(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), trusted)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	origin, transport := h2Frontend(t, listener.Addr().String(), false)
	defer transport.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", origin, nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.13")
	if _, err := transport.RoundTrip(req); err == nil || calls.Load() != 0 {
		t.Fatal("untrusted TCP peer reached the handler")
	}
}

func TestMalformedDatagramCapsule(t *testing.T) {
	for _, data := range [][]byte{{0, 0}, {0, 2, 0}, {0x40}} {
		if err := capsulesToUDP(bytes.NewReader(data), nil); err == nil {
			t.Fatal("malformed capsule accepted")
		}
	}
}
