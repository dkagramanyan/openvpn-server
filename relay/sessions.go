package main

import (
	"crypto/rand"
	"fmt"
	"sort"
)

const relaySessionIdleSeconds int64 = 5 * 60
const maxSessionHistory = 2048

type relaySession struct {
	ID           string `json:"id"`
	Client       string `json:"client"`
	CredentialID string `json:"credential_id"`
	Transport    string `json:"transport"`
	StartedAt    int64  `json:"started_at"`
	LastSeen     int64  `json:"last_seen"`
	EndedAt      int64  `json:"ended_at,omitempty"`
	Active       int    `json:"active"`
	Accepted     uint64 `json:"accepted"`
	Denied       uint64 `json:"denied"`
	Failed       uint64 `json:"failed"`
	BytesUp      int64  `json:"bytes_up"`
	BytesDown    int64  `json:"bytes_down"`
	Uncounted    uint64 `json:"uncounted_flows"`
	State        string `json:"state"`
}

func sessionInstance() string { return rand.Text() }

// activity.mu is held by the caller. Profiles shared by several devices share
// a session; a new visit begins after five minutes without an active flow.
func (a *activityLog) sessionLocked(f *flowLog, now int64) *relaySession {
	if f.event.Client == "" {
		return nil
	}
	if f.event.SessionID != "" {
		return a.sessions[f.event.SessionID]
	}
	if a.sessions == nil {
		a.sessions = make(map[string]*relaySession)
		a.currentSessions = make(map[string]string)
	}
	key := f.event.Client + "\x00" + f.identity
	current := a.sessions[a.currentSessions[key]]
	if current == nil || (current.Active == 0 && now-current.LastSeen > relaySessionIdleSeconds) {
		if len(a.sessions) >= maxSessionHistory {
			var oldest *relaySession
			for _, row := range a.sessions {
				if row.Active == 0 && (oldest == nil || row.LastSeen < oldest.LastSeen) {
					oldest = row
				}
			}
			if oldest != nil {
				delete(a.sessions, oldest.ID)
				oldKey := oldest.Client + "\x00" + oldest.CredentialID
				if a.currentSessions[oldKey] == oldest.ID {
					delete(a.currentSessions, oldKey)
				}
			}
		}
		a.sessionSequence++
		current = &relaySession{ID: fmt.Sprintf("%s:%d", a.instance, a.sessionSequence), Client: f.event.Client,
			CredentialID: f.identity, Transport: a.transport, StartedAt: now, LastSeen: now}
		a.sessions[current.ID] = current
		a.currentSessions[key] = current.ID
	}
	f.event.SessionID = current.ID
	current.LastSeen = max(current.LastSeen, now)
	return current
}

func sessionSnapshot(history []relaySession, flows []flowEvent, now int64) []relaySession {
	rows := make(map[string]*relaySession)
	for i := range history {
		row := history[i]
		rows[row.ID] = &row
	}
	for _, flow := range flows {
		row := rows[flow.SessionID]
		if row == nil {
			continue
		}
		row.LastSeen = now
		if flow.Counted {
			row.BytesUp += flow.BytesUp
			row.BytesDown += flow.BytesDown
		} else {
			row.Uncounted++
		}
	}
	result := make([]relaySession, 0, len(rows))
	for _, row := range rows {
		row.State = "idle"
		if row.Active > 0 {
			row.State = "active"
		} else if now-row.LastSeen > relaySessionIdleSeconds {
			row.State = "ended"
			row.EndedAt = row.LastSeen
		}
		result = append(result, *row)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StartedAt > result[j].StartedAt })
	return result
}
