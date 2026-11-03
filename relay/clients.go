package main

import (
	"sort"
	"time"
)

const maxClientHistory = 2048

type clientActivity struct {
	open         int
	Client       string `json:"client"`
	Guest        bool   `json:"guest"`
	Active       int    `json:"active"`
	TCP          int    `json:"tcp"`
	UDP          int    `json:"udp"`
	Destinations int    `json:"destinations"`
	Accepted     uint64 `json:"accepted"`
	Denied       uint64 `json:"denied"`
	Failed       uint64 `json:"failed"`
	BytesUp      int64  `json:"bytes_up"`
	BytesDown    int64  `json:"bytes_down"`
	Uncounted    uint64 `json:"uncounted_flows"`
	LastSeen     int64  `json:"last_seen"`
	LastError    string `json:"last_error"`
	LastErrorAt  int64  `json:"last_error_at"`
}

// Called with activity.mu held. Retain bounded history; active clients are kept.
func (a *activityLog) clientLocked(e flowEvent) *clientActivity {
	if a.clients == nil {
		a.clients = make(map[string]*clientActivity)
	}
	if c := a.clients[e.Client]; c != nil {
		c.LastSeen = time.Now().Unix()
		return c
	}
	if len(a.clients) >= maxClientHistory {
		var oldest string
		var timestamp int64
		for name, c := range a.clients {
			if c.open == 0 && (timestamp == 0 || c.LastSeen < timestamp) {
				oldest, timestamp = name, c.LastSeen
			}
		}
		if timestamp != 0 {
			delete(a.clients, oldest)
		}
	}
	c := &clientActivity{Client: e.Client, Guest: e.Guest, LastSeen: time.Now().Unix()}
	a.clients[e.Client] = c
	return c
}

func summarizeClients(history []clientActivity, active []flowEvent) []clientActivity {
	rows := make(map[string]*clientActivity)
	for i := range history {
		row := history[i]
		rows[row.Client] = &row
	}
	destinations := make(map[string]map[string]bool)
	for _, f := range active {
		c := rows[f.Client]
		if c == nil {
			c = &clientActivity{Client: f.Client, Guest: f.Guest}
			rows[f.Client] = c
		}
		c.Active++
		if f.Protocol == "TCP" {
			c.TCP++
		} else if f.Protocol == "UDP" {
			c.UDP++
		}
		if f.Counted {
			c.BytesUp += f.BytesUp
			c.BytesDown += f.BytesDown
		} else {
			c.Uncounted++
		}
		if destinations[f.Client] == nil {
			destinations[f.Client] = make(map[string]bool)
		}
		destinations[f.Client][f.Target] = true
	}
	result := make([]clientActivity, 0, len(rows))
	for _, c := range rows {
		c.Destinations = len(destinations[c.Client])
		result = append(result, *c)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Active != result[j].Active {
			return result[i].Active > result[j].Active
		}
		if result[i].LastSeen != result[j].LastSeen {
			return result[i].LastSeen > result[j].LastSeen
		}
		return result[i].Client < result[j].Client
	})
	return result
}
