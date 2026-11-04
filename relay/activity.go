package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type activityLog struct {
	mu              sync.Mutex
	started         int64
	instance        string
	sessionSequence uint64
	sessions        map[string]*relaySession
	currentSessions map[string]string
	transport       string
	reasons         map[string]uint64
	bytesUp         int64
	bytesDown       int64
	tcpUp           int64
	tcpDown         int64
	runtime         *relayMetrics
	limits          map[string]int
	readiness       func(context.Context) error
	clients         map[string]*clientActivity
	sequence        uint64
	events          []flowEvent
	next            int
	active          map[uint64]*flowLog
	total           uint64
	denied          uint64
	failed          uint64
	logSecond       int64
	logCount        int
	logsSuppressed  uint64
}

type flowEvent struct {
	SessionID     string `json:"session_id,omitempty"`
	ID            uint64 `json:"id"`
	Method        string `json:"method"`
	Status        int    `json:"status"`
	UpstreamError string `json:"upstream_error,omitempty"`
	Time          int64  `json:"ts"`
	Kind          string `json:"kind"`
	Client        string `json:"client"`
	Guest         bool   `json:"guest"`
	Protocol      string `json:"protocol"`
	Target        string `json:"target"`
	Reason        string `json:"reason"`
	Duration      int64  `json:"duration_ms"`
	BytesUp       int64  `json:"bytes_up"`
	BytesDown     int64  `json:"bytes_down"`
	Counted       bool   `json:"bytes_counted"`
}

type flowLog struct {
	identity string
	log      *activityLog
	mu       sync.Mutex
	event    flowEvent
	start    time.Time
	opened   bool
	ended    bool
	up       atomic.Int64
	down     atomic.Int64
}

type flowKey struct{}

func flowFrom(ctx context.Context) *flowLog {
	f, _ := ctx.Value(flowKey{}).(*flowLog)
	return f
}

func (f *flowLog) reason(reason string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ended {
		f.event.Reason = reason
	}
}

func (f *flowLog) add(up, down int64) {
	if f == nil {
		return
	}
	f.up.Add(up)
	f.down.Add(down)
}

func newActivity(mode string) *activityLog {
	return &activityLog{started: time.Now().Unix(), instance: sessionInstance(), transport: mode, active: make(map[uint64]*flowLog), reasons: make(map[string]uint64)}
}

func (a *activityLog) begin() *flowLog {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sequence++
	return &flowLog{log: a, start: time.Now(), event: flowEvent{ID: a.sequence, Reason: "request_rejected"}}
}

func (f *flowLog) connected() {
	if f == nil {
		return
	}
	f.opened = true
	f.event.Reason = "connection_closed"
	f.event.Status = 200
	f.log.mu.Lock()
	if session := f.log.sessionLocked(f, f.start.Unix()); session != nil {
		session.Active++
		session.Accepted++
	}
	f.log.active[f.event.ID] = f
	f.log.total++
	client := f.log.clientLocked(f.event)
	client.Accepted++
	client.open++
	client.Guest = f.event.Guest
	f.log.mu.Unlock()
	f.log.record(f.snapshot("connected"))
}

func (f *flowLog) snapshot(kind string) flowEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.event
	e.Kind, e.Time, e.Duration = kind, time.Now().Unix(), time.Since(f.start).Milliseconds()
	if kind == "connected" {
		e.Reason, e.Time = "connection_opened", f.start.Unix()
	}
	e.BytesUp, e.BytesDown = f.up.Load(), f.down.Load()
	return e
}

func (a *activityLog) record(e flowEvent) {
	a.mu.Lock()
	if len(a.events) < 500 {
		a.events = append(a.events, e)
	} else {
		a.events[a.next] = e
		a.next = (a.next + 1) % 500
	}
	// Keep every event in the bounded UI ring, but cap repeated failure logs.
	second := time.Now().Unix()
	if a.logSecond != second {
		a.logSecond, a.logCount = second, 0
	}
	emit := e.Kind != "connected"
	if emit && e.Kind != "closed" && a.logCount >= 20 {
		a.logsSuppressed++
		emit = false
	}
	if emit && e.Kind != "closed" {
		a.logCount++
	}
	a.mu.Unlock()
	if !emit {
		return
	}
	data, _ := json.Marshal(e)
	log.Printf("relay %s", data)
}

func (f *flowLog) finish() {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.ended {
		f.mu.Unlock()
		return
	}
	f.ended = true
	f.mu.Unlock()
	kind := "closed"
	f.log.mu.Lock()
	delete(f.log.active, f.event.ID)
	if !f.opened {
		if f.event.Status >= 500 {
			kind = "failed"
			f.log.failed++
		} else {
			kind = "denied"
			f.log.denied++
		}
	}
	f.log.reasons[f.snapshot(kind).Reason]++
	f.log.bytesUp += f.up.Load()
	f.log.bytesDown += f.down.Load()
	if f.event.Protocol == "TCP" {
		f.log.tcpUp += f.up.Load()
		f.log.tcpDown += f.down.Load()
	}
	client := f.log.clientLocked(f.event)
	if kind != "closed" {
		client.Guest = f.event.Guest
	}
	if kind == "denied" {
		client.Denied++
	} else if kind == "failed" {
		client.Failed++
	}
	if f.event.Counted {
		client.BytesUp += f.up.Load()
		client.BytesDown += f.down.Load()
	} else if f.opened {
		client.Uncounted++
	}
	if kind != "closed" || f.event.Reason != "connection_closed" {
		client.LastError, client.LastErrorAt = f.event.Reason, time.Now().Unix()
	}
	if f.opened {
		client.open--
	}
	if session := f.log.sessionLocked(f, time.Now().Unix()); session != nil {
		session.LastSeen = time.Now().Unix()
		if f.opened {
			session.Active--
		}
		if kind == "denied" {
			session.Denied++
		}
		if kind == "failed" {
			session.Failed++
		}
		if f.event.Counted {
			session.BytesUp += f.up.Load()
			session.BytesDown += f.down.Load()
		} else if f.opened {
			session.Uncounted++
		}
	}
	if len(f.log.clients) > maxClientHistory && client.open == 0 {
		delete(f.log.clients, f.event.Client)
	}
	f.log.mu.Unlock()
	f.log.record(f.snapshot(kind))
}

func (a *activityLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet || (r.URL.Path != "/status" && r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && r.URL.Path != "/metrics") {
		http.Error(w, "Not found", 404)
		return
	}
	if r.URL.Path == "/metrics" {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		a.metrics(w)
		return
	}
	policyReady := true
	if a.readiness != nil && r.URL.Path != "/healthz" {
		policyReady = a.readiness(r.Context()) == nil
	}
	if r.URL.Path == "/readyz" {
		if !policyReady {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": policyReady})
		return
	}
	if r.URL.Path == "/healthz" {
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	selected := r.URL.Query().Get("client")
	a.mu.Lock()
	events := append([]flowEvent{}, a.events[a.next:]...)
	events = append(events, a.events[:a.next]...)
	if selected != "" {
		filtered := make([]flowEvent, 0)
		for _, e := range events {
			if e.Client == selected {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}
	active := make([]flowEvent, 0, len(a.active))
	for _, f := range a.active {
		if selected == "" || f.event.Client == selected {
			active = append(active, f.snapshot("connected"))
		}
	}
	total, denied, failed, suppressed := a.total, a.denied, a.failed, a.logsSuppressed
	history := make([]clientActivity, 0, len(a.clients))
	for _, c := range a.clients {
		if selected == "" || c.Client == selected {
			history = append(history, *c)
		}
	}
	sessions := make([]relaySession, 0, len(a.sessions))
	for _, row := range a.sessions {
		if selected == "" || row.Client == selected {
			sessions = append(sessions, *row)
		}
	}
	a.mu.Unlock()
	clients := summarizeClients(history, active)
	json.NewEncoder(w).Encode(map[string]any{"ready": true, "transport": a.transport, "started_at": a.started,
		"total": total, "denied": denied, "failed": failed, "logs_suppressed": suppressed, "clients": clients, "active": active, "events": events, "sessions": sessionSnapshot(sessions, active, time.Now().Unix()), "session_idle_seconds": relaySessionIdleSeconds, "instance": a.instance, "policy_ready": policyReady, "limits": a.limits, "metrics": a.runtime.snapshot()})
}

func (a *activityLog) listen(address string) (*http.Server, error) {
	addr, err := netip.ParseAddrPort(address)
	if err != nil || !addr.Addr().IsLoopback() {
		return nil, fmt.Errorf("relay diagnostics must bind a loopback IP")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: a, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("relay diagnostics: %v", err)
		}
	}()
	return server, nil
}
