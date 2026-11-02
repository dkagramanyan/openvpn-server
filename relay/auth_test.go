package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedAuthorizationSurvivesCallerCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
			json.NewEncoder(w).Encode(policy{CIDRs: []string{"192.168.1.0/24"}})
		case <-r.Context().Done():
		}
	}))
	defer api.Close()
	defer unblock()
	s := &relayServer{api: api.URL, client: api.Client(), policyTTL: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	firstCtx, closeFirst := context.WithCancel(ctx)
	defer closeFirst()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, err := s.authorize(firstCtx, "Bearer alice:secret"); first <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("authorization did not start")
	}
	go func() { _, err := s.authorize(ctx, "Bearer alice:secret"); second <- err }()
	closeFirst()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled caller: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller waited for backend completion")
	}
	unblock()
	if err := <-second; err != nil {
		t.Fatalf("closing first flow broke the other flow: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("closing first flow discarded the shared authorization request")
	}
}

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
