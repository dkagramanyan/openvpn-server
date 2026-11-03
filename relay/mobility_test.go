package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// Drop bytes as a vanished Wi-Fi path would, without delivering TCP FIN/RST.
type lostPath struct {
	net.Conn
	lost atomic.Bool
	done chan struct{}
	once sync.Once
}

func (c *lostPath) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.lost.Load() {
		<-c.done
		return 0, net.ErrClosed
	}
	return n, err
}
func (c *lostPath) Write(p []byte) (int, error) {
	if c.lost.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}
func (c *lostPath) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func TestLostMobilePathReleasesCapacityAndReconnects(t *testing.T) {
	ip := localIP(t)
	destination, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	go func() {
		for {
			c, e := destination.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(policy{Client: "alice", CIDRs: []string{ip + "/32"}, URL: "https://relay.example"})
	}))
	defer api.Close()
	s := &relayServer{api: api.URL, client: api.Client(), slots: make(chan struct{}, 2), quota: &flowQuota{maximum: 1},
		recheck: 50 * time.Millisecond, policyTTL: 10 * time.Millisecond, h2ReadIdle: 100 * time.Millisecond, h2PingTimeout: 100 * time.Millisecond}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	trusted, _ := parseTrustedProxies("127.0.0.1/32")
	go serveHTTP2(listener, s, trusted)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var oldPath *lostPath
	first := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if e != nil {
			return nil, e
		}
		oldPath = &lostPath{Conn: c, done: make(chan struct{})}
		return oldPath, nil
	}}
	open := func(transport *http2.Transport) (*http.Response, *io.PipeWriter, error) {
		reader, writer := io.Pipe()
		request, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+listener.Addr().String(), reader)
		request.Host = destination.Addr().String()
		request.Header.Set("Authorization", "Bearer alice:secret")
		response, e := transport.RoundTrip(request)
		return response, writer, e
	}
	response, writer, err := open(first)
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("initial connection: %v %v", response, err)
	}
	defer response.Body.Close()
	defer writer.Close()
	defer oldPath.Close()
	if _, err := writer.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 6)
	if _, err := io.ReadFull(response.Body, buffer); err != nil {
		t.Fatal(err)
	}
	oldPath.lost.Store(true)
	// A different transport is the replacement network; never reuse the old socket.
	next := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}
	defer next.CloseIdleConnections()
	deadline := time.Now().Add(4 * time.Second)
	var recovered bool
	for time.Now().Before(deadline) {
		r, w, e := open(next)
		if e == nil && r.StatusCode == 200 {
			_, e = w.Write([]byte("after!"))
			if e == nil {
				_, e = io.ReadFull(r.Body, buffer)
			}
			recovered = e == nil && string(buffer) == "after!"
			w.Close()
			r.Body.Close()
			break
		}
		if r != nil {
			r.Body.Close()
		}
		w.Close()
		time.Sleep(30 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("lost network path retained flow capacity and blocked the replacement transport")
	}
}

func TestFairQuotaDoesNotBlockAnotherClient(t *testing.T) {
	q := &flowQuota{maximum: 1}
	release, ok := q.acquire("alice")
	if !ok {
		t.Fatal("initial quota")
	}
	if _, ok := q.acquire("alice"); ok {
		t.Fatal("client exceeded quota")
	}
	other, ok := q.acquire("bob")
	if !ok {
		t.Fatal("busy client blocked another client")
	}
	other()
	release()
	release()
	next, ok := q.acquire("alice")
	if !ok {
		t.Fatal("quota leaked after disconnect")
	}
	next()
	if len(q.used) != 0 {
		t.Fatal("identity retention after all flows close")
	}
}

func TestBackendOutageIsRetryableNotCredentialDenial(t *testing.T) {
	for _, status := range []int{403, 503} {
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		server := &relayServer{api: api.URL, client: api.Client(), slots: make(chan struct{}, 2), activity: newActivity("http2")}
		request := httptest.NewRequest(http.MethodConnect, "http://relay.example", nil)
		request.Header.Set("Authorization", "Bearer alice:secret")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		api.Close()
		if response.Code != status {
			t.Fatalf("backend %d became %d", status, response.Code)
		}
		if strings.Contains(response.Body.String(), "alice:secret") {
			t.Fatal("credential in response")
		}
	}
}
