package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentAuthorizationCoalescesAndExpires(t *testing.T) {
	var calls atomic.Int32
	var revoked atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if revoked.Load() {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(policy{CIDRs: []string{"192.168.1.0/24"}})
	}))
	defer api.Close()
	s := &relayServer{api: api.URL, client: api.Client(), policyTTL: time.Second}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			p, err := s.authorize(context.Background(), "Bearer alice:secret")
			if err != nil || len(p.CIDRs) != 1 {
				t.Errorf("authorization: %v %v", p, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("100 simultaneous checks made %d API requests, want 1", calls.Load())
	}
	if _, err := s.authorize(context.Background(), "Bearer bob:other"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("different credentials shared a policy")
	}
	s.authMu.Lock()
	for _, entry := range s.policies {
		entry.expires = time.Now().Add(-time.Second)
	}
	s.authMu.Unlock()
	revoked.Store(true)
	for range 2 {
		if _, err := s.authorize(context.Background(), "Bearer alice:secret"); err == nil {
			t.Fatal("served stale policy after revocation")
		}
	}
	if calls.Load() != 4 {
		t.Fatal("failed checks must not be cached")
	}
}
