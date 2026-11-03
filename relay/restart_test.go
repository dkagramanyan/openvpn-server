package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestPlannedHTTP2RestartSendsGoAwayAndKeepsCredential(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	trusted, _ := parseTrustedProxies("127.0.0.1/32")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer alice:existing-secret" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if r.Header.Get("Hold-Open") == "yes" {
			<-r.Context().Done()
		}
	})
	go func() { done <- serveHTTP2Context(ctx, listener, handler, trusted) }()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "destination.example:443"},
		{Name: "authorization", Value: "Bearer alice:existing-secret"}, {Name: "hold-open", Value: "yes"},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := frame.(*http2.HeadersFrame); ok {
			break
		}
	}
	cancel()
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatalf("connection closed without GOAWAY: %v", err)
		}
		if goaway, ok := frame.(*http2.GoAwayFrame); ok {
			if goaway.ErrCode != http2.ErrCodeNo {
				t.Fatalf("shutdown reported a protocol failure: %v", goaway.ErrCode)
			}
			break
		}
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("long-lived CONNECT prevented bounded shutdown")
	}
	replacement, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	go serveHTTP2(replacement, handler, trusted)
	url, transport := h2Frontend(t, address, false)
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequest(http.MethodConnect, url, nil)
	request.Host = "destination.example:443"
	request.Header.Set("Authorization", "Bearer alice:existing-secret")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("old profile credential rejected after listener restart")
	}
}

func TestRebootWaitsForPolicyAndDatabaseReadiness(t *testing.T) {
	checks := make(chan struct{}, 10)
	ready := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected startup request path: %s", r.URL.Path)
		}
		select {
		case checks <- struct{}{}:
		default:
		}
		select {
		case <-ready:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer api.Close()
	server := &relayServer{api: api.URL + "/api/relay/authorize", client: api.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.waitForPolicy(ctx) }()
	select {
	case <-checks:
	case <-ctx.Done():
		t.Fatal("startup did not check policy readiness")
	}
	select {
	case <-done:
		t.Fatal("startup accepted unavailable policy state")
	default:
	}
	close(ready)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := server.waitForPolicy(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown while waiting: %v", err)
	}
}
