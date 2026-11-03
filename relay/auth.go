package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type policyEntry struct {
	ready   chan struct{}
	policy  policy
	err     error
	expires time.Time
}

// Coalesce simultaneous checks for one credential and reuse successful results
// for at most one second. Never serve expired policy during an API outage.
func (s *relayServer) authorize(ctx context.Context, token string) (policy, error) {
	if !strings.HasPrefix(token, "Bearer ") || len(token) > 512 {
		return policy{}, errors.New("missing credential")
	}
	if s.policyTTL <= 0 {
		return s.authorizeBackend(ctx, token)
	}
	key := sha256.Sum256([]byte(token))
	s.authMu.Lock()
	if entry := s.policies[key]; entry != nil && (entry.expires.IsZero() || time.Now().Before(entry.expires)) {
		s.authMu.Unlock()
		select {
		case <-ctx.Done():
			return policy{}, ctx.Err()
		case <-entry.ready:
			return entry.policy, entry.err
		}
	}
	if s.policies == nil {
		s.policies = make(map[[32]byte]*policyEntry)
	}
	if len(s.policies) >= 1024 {
		for k, entry := range s.policies {
			if !entry.expires.IsZero() && !time.Now().Before(entry.expires) {
				delete(s.policies, k)
			}
		}
		if len(s.policies) >= 1024 {
			s.authMu.Unlock()
			return s.authorizeBackend(ctx, token)
		}
	}
	entry := &policyEntry{ready: make(chan struct{})}
	s.policies[key] = entry
	s.authMu.Unlock()
	// A shared check belongs to all waiting flows. Closing its first caller
	// must not cancel authorization for the other connections using this token.
	go func() {
		checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		p, err := s.authorizeBackend(checkCtx, token)
		s.authMu.Lock()
		entry.policy, entry.err = p, err
		entry.expires = time.Now().Add(s.policyTTL)
		if err != nil {
			delete(s.policies, key)
		}
		close(entry.ready)
		s.authMu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return policy{}, ctx.Err()
	case <-entry.ready:
		return entry.policy, entry.err
	}
}

func (s *relayServer) authorizeBackend(ctx context.Context, token string) (policy, error) {
	var p policy
	if !strings.HasPrefix(token, "Bearer ") || len(token) > 512 {
		return p, errors.New("missing credential")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for attempt := range 3 {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.api, nil)
		if err != nil {
			return p, err
		}
		req.Header.Set("Authorization", token)
		resp, err := s.client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				err := json.NewDecoder(io.LimitReader(resp.Body, 32768)).Decode(&p)
				resp.Body.Close()
				return p, err
			}
			resp.Body.Close()
			if resp.StatusCode != 502 && resp.StatusCode != 503 && resp.StatusCode != 504 {
				return p, errors.New("access denied")
			}
		}
		if attempt == 2 {
			return p, errors.New("authorization service unavailable")
		}
		// Retry short transport/proxy outages within the same deadline. An
		// explicit denial is final and expired cached policy is never reused.
		timer := time.NewTimer(time.Duration(150+attempt*250) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return p, ctx.Err()
		case <-timer.C:
		}
	}
	return p, errors.New("authorization service unavailable")
}
