package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

type activityState struct {
	Clients []clientActivity `json:"clients"`
	Active  []flowEvent      `json:"active"`
	Events  []flowEvent      `json:"events"`
	Failed  uint64           `json:"failed"`
}

func readActivity(t *testing.T, a *activityLog, path string) activityState {
	t.Helper()
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	var state activityState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	return state
}
func TestClientAggregationCountsLiveAndCompletedTrafficOnce(t *testing.T) {
	a := newActivity("http2")
	open := func(client, protocol, target string) *flowLog {
		f := a.begin()
		f.event.Client = client
		f.event.Protocol = protocol
		f.event.Target = target
		f.event.Counted = true
		f.connected()
		return f
	}
	tcp := open("alice", "TCP", "nas.home:443")
	tcp.add(10, 20)
	udp := open("alice", "UDP", "dns.home:53")
	udp.add(30, 40)
	done := open("alice", "TCP", "old.home:80")
	done.add(50, 60)
	done.finish()
	bob := open("bob", "TCP", "other.home:80")
	bob.add(1000, 2000)
	defer bob.finish()
	fail := a.begin()
	fail.event.Client = "alice"
	fail.event.Status = 502
	fail.reason("destination_unreachable")
	fail.finish()
	denied := a.begin()
	denied.event.Client = "alice"
	denied.event.Status = 403
	denied.reason("destination_denied")
	denied.finish()
	state := readActivity(t, a, "/status?client=alice")
	if len(state.Clients) != 1 || len(state.Active) != 2 {
		t.Fatalf("client filter: %+v", state)
	}
	c := state.Clients[0]
	if c.Accepted != 3 || c.Active != 2 || c.TCP != 1 || c.UDP != 1 || c.Destinations != 2 || c.BytesUp != 90 || c.BytesDown != 120 || c.Denied != 1 || c.Failed != 1 {
		t.Fatalf("incorrect summary: %+v", c)
	}
	for _, e := range state.Events {
		if e.Client != "alice" {
			t.Fatal("another client's events exposed")
		}
	}
	tcp.finish()
	udp.finish()
	c = readActivity(t, a, "/status?client=alice").Clients[0]
	if c.Active != 0 || c.BytesUp != 90 || c.BytesDown != 120 {
		t.Fatalf("traffic was counted twice: %+v", c)
	}
	// The per-client totals outlive the short raw-event ring.
	for i := 0; i < 550; i++ {
		a.record(flowEvent{Kind: "test"})
	}
	if readActivity(t, a, "/status?client=alice").Clients[0].Accepted != 3 {
		t.Fatal("client totals lost when event ring rolled")
	}
}
func TestOlderClosingFlowDoesNotOverwriteNewAccessRole(t *testing.T) {
	a := newActivity("http2")
	old := a.begin()
	old.event.Client = "alice"
	old.connected()
	next := a.begin()
	next.event.Client = "alice"
	next.event.Guest = true
	next.connected()
	old.finish()
	if !readActivity(t, a, "/status?client=alice").Clients[0].Guest {
		t.Fatal("old full-access flow overwrote new guest role")
	}
	next.finish()
}
func TestMethodDiagnosticsAndProxyStatusDoNotLogRequestSecrets(t *testing.T) {
	a := newActivity("http2")
	s := &relayServer{activity: a}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://relay.example/?private-query-secret", nil)
	r.Header.Set("Authorization", "Bearer private-header-secret")
	s.ServeHTTP(w, r)
	if w.Code != 405 || !strings.Contains(w.Header().Get("Proxy-Status"), "http_request_error") {
		t.Fatal("missing method/proxy diagnostics")
	}
	state := readActivity(t, a, "/status")
	data, _ := json.Marshal(state)
	if strings.Contains(string(data), "private-") {
		t.Fatal("request secrets in diagnostic output")
	}
	if state.Events[0].Method != "GET" || state.Events[0].Status != 405 {
		t.Fatal("request result not recorded")
	}
}
func TestTCPSetupRetriesRefusedConnectionWithoutReplayingData(t *testing.T) {
	initial, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := initial.Addr().String()
	initial.Close()
	ready := make(chan net.Listener, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		l, e := net.Listen("tcp", address)
		if e == nil {
			ready <- l
		} else {
			close(ready)
		}
	}()
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	s := &relayServer{metrics: &relayMetrics{}}
	conn, _, err := s.connectTCP(context.Background(), []netip.AddrPort{addr.AddrPort()})
	listener := <-ready
	if listener != nil {
		defer listener.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if s.metrics.snapshot()["tcp_setup_retries_total"] != uint64(1) {
		t.Fatal("retry not observed")
	}
	if connectionError(&net.OpError{Err: syscall.ECONNREFUSED}) != "connection_refused" || connectionError(context.DeadlineExceeded) != "connection_timeout" || connectionError(errors.New("private error detail")) != "connection_terminated" {
		t.Fatal("error classification")
	}
}

func TestTransportErrorsNeverEchoRequestBytes(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	metrics := &relayMetrics{}
	writer := &transportLog{metrics: metrics}
	for i := 0; i < 2; i++ {
		writer.Write([]byte("invalid preface GET /?private-token-sentinel"))
	}
	if strings.Contains(output.String(), "private-token-sentinel") || !strings.Contains(output.String(), "request bytes suppressed") {
		t.Fatal("unsafe transport logging")
	}
	if metrics.snapshot()["http2_transport_errors_total"] != uint64(2) {
		t.Fatal("transport errors not counted")
	}
}

func TestClientHistoryRemainsBoundedWithoutEvictingActiveClient(t *testing.T) {
	a := newActivity("http2")
	active := a.begin()
	active.event.Client = "active-alice"
	active.connected()
	defer active.finish()
	a.mu.Lock()
	a.clients["active-alice"].LastSeen = 1
	for i := 0; i < maxClientHistory+10; i++ {
		a.clientLocked(flowEvent{Client: fmt.Sprintf("inactive-%d", i)})
	}
	if len(a.clients) > maxClientHistory {
		t.Error("unbounded inactive client history")
	}
	if a.clients["active-alice"] == nil {
		t.Error("active client was evicted")
	}
	a.mu.Unlock()
}
