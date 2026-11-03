package main

import (
	"log"
	"sync"
	"time"
)

// HTTP/2 library errors can quote a malformed preface containing a URL/token.
// Count every error, but log only a fixed, rate-limited transport notice.
type transportLog struct {
	mu      sync.Mutex
	last    time.Time
	metrics *relayMetrics
}

func (w *transportLog) Write(data []byte) (int, error) {
	w.metrics.observe("http2_transport_errors", time.Time{})
	w.mu.Lock()
	emit := time.Since(w.last) >= time.Second
	if emit {
		w.last = time.Now()
	}
	w.mu.Unlock()
	if emit {
		log.Print("relay HTTP/2 transport error; request bytes suppressed")
	}
	return len(data), nil
}
