package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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
		return policy{}, errAccessDenied
	}
	if s.policyTTL <= 0 {
		return s.authorizeBackend(ctx, token)
	}
	key := sha256.Sum256([]byte(token))
	s.authMu.Lock()
	if entry := s.policies[key]; entry != nil && (entry.expires.IsZero() || time.Now().Before(entry.expires)) {
		s.authMu.Unlock()
		s.metrics.observe("authorization_cache_hits", time.Time{})
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
	started := time.Now()
	defer s.metrics.observe("authorization_checks", started)
	var p policy
	if s.authSlots != nil {
		select {
		case s.authSlots <- struct{}{}:
			defer func() { <-s.authSlots }()
		default:
			s.metrics.observe("authorization_capacity_errors", time.Time{})
			return p, errAuthUnavailable
		}
	}
	if !strings.HasPrefix(token, "Bearer ") || len(token) > 512 {
		return p, errAccessDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for attempt := range 3 {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.api, nil)
		if err != nil {
			return p, errAuthUnavailable
		}
		req.Header.Set("Authorization", token)
		resp, err := s.client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				err := json.NewDecoder(io.LimitReader(resp.Body, 32768)).Decode(&p)
				resp.Body.Close()
				if err != nil {
					s.metrics.observe("authorization_errors", time.Time{})
					return p, errAuthUnavailable
				}
				if err := p.compile(); err != nil {
					return p, errAuthUnavailable
				}
				return p, nil
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				s.metrics.observe("authorization_denials", time.Time{})
				return p, errAccessDenied
			}
			if resp.StatusCode != 502 && resp.StatusCode != 503 && resp.StatusCode != 504 {
				return p, errAuthUnavailable
			}
		}
		if attempt == 2 {
			s.metrics.observe("authorization_errors", time.Time{})
			return p, errAuthUnavailable
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
	return p, errAuthUnavailable
}

// Readiness checks the independent evaluator, not the UI collector or a public destination.
func (s *relayServer) checkReadiness(ctx context.Context) error {
	endpoint, err := url.Parse(s.api)
	if err != nil {
		return errAuthUnavailable
	}
	endpoint.Path, endpoint.RawQuery, endpoint.Fragment = "/healthz", "", ""
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errAuthUnavailable
	}
	response, err := s.client.Do(request)
	if err != nil {
		return errAuthUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errAuthUnavailable
	}
	return nil
}
