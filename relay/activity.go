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
	mu        sync.Mutex
	started   int64
	transport string
	reasons   map[string]uint64
	bytesUp   int64
	bytesDown int64
	runtime   *relayMetrics
	limits    map[string]int
	readiness func(context.Context) error
	sequence  uint64
	events    []flowEvent
	next      int
	active    map[uint64]*flowLog
	total     uint64
	denied    uint64
}

type flowEvent struct {
	ID        uint64 `json:"id"`
	Time      int64  `json:"ts"`
	Kind      string `json:"kind"`
	Client    string `json:"client"`
	Guest     bool   `json:"guest"`
	Protocol  string `json:"protocol"`
	Target    string `json:"target"`
	Reason    string `json:"reason"`
	Duration  int64  `json:"duration_ms"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	Counted   bool   `json:"bytes_counted"`
}

type flowLog struct {
	log    *activityLog
	mu     sync.Mutex
	event  flowEvent
	start  time.Time
	opened bool
	ended  bool
	up     atomic.Int64
	down   atomic.Int64
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
	return &activityLog{started: time.Now().Unix(), transport: mode, active: make(map[uint64]*flowLog), reasons: make(map[string]uint64)}
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
	f.log.mu.Lock()
	f.log.active[f.event.ID] = f
	f.log.total++
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
	a.mu.Unlock()
	data, _ := json.Marshal(e)
	log.Printf("relay %s", data)
}

func (f *flowLog) finish() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.ended = true
	f.mu.Unlock()
	kind := "closed"
	f.log.mu.Lock()
	delete(f.log.active, f.event.ID)
	if !f.opened {
		kind = "denied"
		f.log.denied++
	}
	f.log.reasons[f.snapshot(kind).Reason]++
	f.log.bytesUp += f.up.Load()
	f.log.bytesDown += f.down.Load()
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
	a.mu.Lock()
	events := append([]flowEvent{}, a.events[a.next:]...)
	events = append(events, a.events[:a.next]...)
	flows := make([]*flowLog, 0, len(a.active))
	for _, f := range a.active {
		flows = append(flows, f)
	}
	total, denied := a.total, a.denied
	a.mu.Unlock()
	active := make([]flowEvent, 0, len(flows))
	for _, f := range flows {
		active = append(active, f.snapshot("connected"))
	}
	json.NewEncoder(w).Encode(map[string]any{"ready": true, "transport": a.transport, "started_at": a.started,
		"total": total, "denied": denied, "active": active, "events": events, "policy_ready": policyReady, "limits": a.limits, "metrics": a.runtime.snapshot()})
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
