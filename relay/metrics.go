package main

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Fixed internal names only: no credential, identity or destination labels.
type relayMetrics struct {
	mu        sync.Mutex
	counts    map[string]uint64
	durations map[string]time.Duration
}

func (m *relayMetrics) observe(name string, started time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = make(map[string]uint64)
		m.durations = make(map[string]time.Duration)
	}
	m.counts[name]++
	if !started.IsZero() {
		m.durations[name] += time.Since(started)
	}
}

func (m *relayMetrics) snapshot() map[string]any {
	result := make(map[string]any)
	if m == nil {
		return result
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, count := range m.counts {
		result[name+"_total"] = count
		if duration, ok := m.durations[name]; ok {
			result[name+"_seconds_total"] = duration.Seconds()
		}
	}
	return result
}

func (a *activityLog) metrics(w io.Writer) {
	a.mu.Lock()
	active, total, denied := len(a.active), a.total, a.denied
	reasons := make(map[string]uint64, len(a.reasons))
	for reason, value := range a.reasons {
		reasons[reason] = value
	}
	up, down, failed, suppressed := a.tcpUp, a.tcpDown, a.failed, a.logsSuppressed
	payloadUp, payloadDown := a.bytesUp, a.bytesDown
	a.mu.Unlock()
	fmt.Fprintf(w, "# TYPE relay_active_flows gauge\nrelay_active_flows %d\n# TYPE relay_connections_total counter\nrelay_connections_total %d\n# TYPE relay_rejected_total counter\nrelay_rejected_total %d\n", active, total, denied+failed)
	fmt.Fprintf(w, "# TYPE relay_completed_tcp_bytes_total counter\nrelay_completed_tcp_bytes_total{direction=\"upload\"} %d\nrelay_completed_tcp_bytes_total{direction=\"download\"} %d\n", up, down)
	fmt.Fprintf(w, "# TYPE relay_failures_total counter\nrelay_failures_total %d\n# TYPE relay_logs_suppressed_total counter\nrelay_logs_suppressed_total %d\n", failed, suppressed)
	fmt.Fprintf(w, "# TYPE relay_completed_payload_bytes_total counter\nrelay_completed_payload_bytes_total{direction=\"upload\"} %d\nrelay_completed_payload_bytes_total{direction=\"download\"} %d\n", payloadUp, payloadDown)
	fmt.Fprintln(w, "# TYPE relay_flow_endings_total counter")
	for reason, value := range reasons {
		fmt.Fprintf(w, "relay_flow_endings_total{reason=%q} %d\n", reason, value)
	}
	for name, value := range a.runtime.snapshot() {
		fmt.Fprintf(w, "# TYPE relay_%s counter\nrelay_%s %v\n", name, name, value)
	}
	for name, value := range a.limits {
		fmt.Fprintf(w, "# TYPE relay_limit_%s gauge\nrelay_limit_%s %d\n", name, name, value)
	}
}
