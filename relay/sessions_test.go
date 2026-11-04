package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func readSessions(t *testing.T, a *activityLog) []relaySession {
	t.Helper()
	response := httptest.NewRecorder()
	a.ServeHTTP(response, httptest.NewRequest("GET", "/status", nil))
	var status struct {
		Sessions []relaySession `json:"sessions"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	return status.Sessions
}

func TestRelaySessionsAggregateLiveAndClosedFlowsOnce(t *testing.T) {
	a := newActivity("http2")
	flow := func() *flowLog {
		f := a.begin()
		f.event.Client = "alice"
		f.identity = "profile-identity"
		f.event.Counted = true
		f.connected()
		return f
	}
	first := flow()
	first.add(10, 20)
	second := flow()
	second.add(30, 40)
	check := func(active int) {
		rows := readSessions(t, a)
		if len(rows) != 1 || rows[0].Accepted != 2 || rows[0].Active != active || rows[0].BytesUp != 40 || rows[0].BytesDown != 60 {
			t.Fatalf("wrong session: %+v", rows)
		}
	}
	check(2)
	first.finish()
	first.finish()
	check(1)
	second.finish()
	check(0)
	denied := a.begin()
	denied.event.Client = "alice"
	denied.identity = "profile-identity"
	denied.finish()
	if readSessions(t, a)[0].Denied != 1 {
		t.Fatal("authenticated denial missing")
	}
	anonymous := a.begin()
	anonymous.finish()
	if len(readSessions(t, a)) != 1 {
		t.Fatal("anonymous request created session")
	}
}

func TestRelaySessionsSplitAfterIdleAndCredentialChange(t *testing.T) {
	a := newActivity("http2")
	f := a.begin()
	f.event.Client = "alice"
	f.identity = "first"
	f.connected()
	f.finish()
	a.sessions[f.event.SessionID].LastSeen = time.Now().Unix() - relaySessionIdleSeconds - 1
	next := a.begin()
	next.event.Client = "alice"
	next.identity = "first"
	next.connected()
	next.finish()
	changed := a.begin()
	changed.event.Client = "alice"
	changed.identity = "second"
	changed.connected()
	changed.finish()
	rows := readSessions(t, a)
	if len(rows) != 3 || f.event.SessionID == next.event.SessionID || next.event.SessionID == changed.event.SessionID {
		t.Fatalf("visits not separated: %+v", rows)
	}
	ended := 0
	for _, row := range rows {
		if row.State == "ended" && row.EndedAt > 0 {
			ended++
		}
	}
	if ended != 1 {
		t.Fatalf("wrong ended sessions: %+v", rows)
	}
}

func TestRelaySessionsStayTogetherWhileLongFlowIsActive(t *testing.T) {
	a := newActivity("http2")
	f := a.begin()
	f.event.Client = "alice"
	f.connected()
	a.sessions[f.event.SessionID].LastSeen = time.Now().Unix() - 2*relaySessionIdleSeconds
	next := a.begin()
	next.event.Client = "alice"
	next.connected()
	if next.event.SessionID != f.event.SessionID {
		t.Fatal("split a visit with active flow")
	}
	f.finish()
	next.finish()
}
