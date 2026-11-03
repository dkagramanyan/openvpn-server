package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

type flowQuota struct {
	mu      sync.Mutex
	maximum int
	used    map[[32]byte]int
}

func (q *flowQuota) acquire(identity string) (func(), bool) {
	if q == nil {
		return func() {}, true
	}
	key := sha256.Sum256([]byte(identity))
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.used[key] >= q.maximum {
		return nil, false
	}
	if q.used == nil {
		q.used = make(map[[32]byte]int)
	}
	q.used[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			q.mu.Lock()
			defer q.mu.Unlock()
			q.used[key]--
			if q.used[key] == 0 {
				delete(q.used, key)
			}
		})
	}, true
}

func limitEnv(name string, fallback, maximum int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > maximum {
		return 0, fmt.Errorf("%s must be between 1 and %d", name, maximum)
	}
	return n, nil
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 100*time.Millisecond || duration > time.Minute {
		return 0, fmt.Errorf("%s must be between 100ms and 1m", name)
	}
	return duration, nil
}
