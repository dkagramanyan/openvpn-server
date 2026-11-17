package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestActivityTracksConnectionsWithoutCredentials(t *testing.T) {
	a := newActivity("http2")
	f := a.begin()
	f.event.Client, f.event.Target, f.event.Protocol, f.event.Counted = "alice", "nas.home.arpa:443", "TCP", true
	f.connected()
	f.add(10, 20)
	read := func() map[string]any {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(w.Body.String(), "Bearer") {
			t.Fatal("credential in activity")
		}
		return body
	}
	if len(read()["active"].([]any)) != 1 {
		t.Fatal("connection not active")
	}
	f.reason("access_revoked_or_unavailable")
	f.finish()
	denied := a.begin()
	denied.reason("authorization_denied")
	denied.finish()
	body := read()
	if len(body["active"].([]any)) != 0 || body["total"].(float64) != 1 || body["denied"].(float64) != 1 {
		t.Fatal("incorrect counters")
	}
	closed := body["events"].([]any)[1].(map[string]any)
	if closed["bytes_up"].(float64) != 10 || closed["bytes_down"].(float64) != 20 {
		t.Fatal("incorrect traffic")
	}
	if _, err := a.listen("0.0.0.0:0"); err == nil {
		t.Fatal("diagnostics exposed outside loopback")
	}
}

func TestActivityRetentionIsBounded(t *testing.T) {
	a := newActivity("http2")
	for range eventRing + 50 {
		a.record(flowEvent{Kind: "test"})
	}
	a.record(flowEvent{Kind: "test"})
	if len(a.events) != eventRing {
		t.Fatal("unbounded activity retention")
	}
	// The page gets the latest events; the UI's saver continues after a position.
	if state := readActivity(t, a, "/status"); len(state.Events) != statusEvents || state.Events[statusEvents-1].Seq != eventRing+51 {
		t.Fatalf("status events: %d, last %d", len(state.Events), state.Events[len(state.Events)-1].Seq)
	}
	state := readActivity(t, a, "/status?since=4000")
	if len(state.Events) != eventRing+51-4000 || state.Events[0].Seq != 4001 {
		t.Fatalf("since: %d events from %d", len(state.Events), state.Events[0].Seq)
	}
	if state := readActivity(t, a, "/status?since=99999"); len(state.Events) != 0 {
		t.Fatal("events after the end of the log")
	}
}
