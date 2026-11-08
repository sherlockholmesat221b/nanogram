// File: internal/limits/limits.go

// Package limits holds the small, per-process state for the abuse protection:
// token buckets, a replay cache of accepted PoW nonces, and per-username
// attempt counters. Everything is in memory and is cleared on restart; that
// is the design (see docs/PROTOCOL.md part 7).
package limits

import (
	"sync"
	"time"
)

// Buckets is a token-bucket limiter keyed on arbitrary bytes (a hashed
// identity). It never uses an IP address; see the spec.
type Buckets struct {
	mu       sync.Mutex
	capacity int
	refill   int
	period   time.Duration
	entries  map[string]*bucket
}

type bucket struct {
	tokens int
	last   time.Time
}

// NewBuckets returns a limiter with the given capacity, refill rate and
// refill period. capacity is the maximum burst; refill tokens are added
// every period.
func NewBuckets(capacity, refill int, period time.Duration) *Buckets {
	return &Buckets{
		capacity: capacity,
		refill:   refill,
		period:   period,
		entries:  make(map[string]*bucket),
	}
}

// Allow consumes a token for key, and reports whether one was available.
// now is supplied by the caller so the store never reads the clock.
func (b *Buckets) Allow(key []byte, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	k := string(key)
	e, ok := b.entries[k]
	if !ok {
		e = &bucket{tokens: b.capacity, last: now}
		b.entries[k] = e
	} else if elapsed := now.Sub(e.last); elapsed >= b.period {
		refills := int(elapsed / b.period)
		e.tokens += refills * b.refill
		if e.tokens > b.capacity {
			e.tokens = b.capacity
		}
		e.last = e.last.Add(time.Duration(refills) * b.period)
	}

	if e.tokens <= 0 {
		return false
	}
	e.tokens--
	return true
}

// Clean removes buckets that have been idle long enough to have refilled
// fully and to have nothing left to remember.
func (b *Buckets) Clean(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	idle := b.period * 60 // 60 refill periods of inactivity
	for k, e := range b.entries {
		if now.Sub(e.last) > idle {
			delete(b.entries, k)
		}
	}
}

// ReplayCache rejects a nonce it has already accepted. It is a FIFO of
// capacity entries with a TTL: entries older than ttl are treated as
// unknown. Size the capacity to max_solve_rate * ttl * safety_margin (see
// the spec, "Replay cache").
type ReplayCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	order    []string
	entries  map[string]time.Time
}

// NewReplayCache returns a replay cache with the given capacity and TTL.
func NewReplayCache(capacity int, ttl time.Duration) *ReplayCache {
	return &ReplayCache{
		capacity: capacity,
		ttl:      ttl,
		order:    make([]string, 0, capacity),
		entries:  make(map[string]time.Time, capacity),
	}
}

// Accept records nonce if it has not been seen within the TTL, and returns
// true. If it has been seen, it returns false. This is atomic.
func (r *ReplayCache) Accept(nonce []byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	k := string(nonce)
	if seenAt, ok := r.entries[k]; ok {
		if now.Sub(seenAt) <= r.ttl {
			return false
		}
		// Stale entry: accept again (the window check has already run, so
		// this only happens for a challenge old enough that Verify rejected
		// it; kept for defensive symmetry).
	}
	r.entries[k] = now
	r.order = append(r.order, k)
	for len(r.entries) > r.capacity {
		old := r.order[0]
		r.order = r.order[1:]
		delete(r.entries, old)
	}
	return true
}

// Attempts is a bounded sliding window of timestamps per key (a hashed
// username). It is used both for the escalation difficulty and for the
// recent_failures field returned to the user.
type Attempts struct {
	mu       sync.Mutex
	capacity int
	window   time.Duration
	entries  map[string][]time.Time
}

// NewAttempts returns an Attempts with the given per-key capacity and window.
func NewAttempts(capacity int, window time.Duration) *Attempts {
	return &Attempts{
		capacity: capacity,
		window:   window,
		entries:  make(map[string][]time.Time),
	}
}

// Record appends an attempt for key at the given time, dropping any entry
// older than the window and capping the length to capacity.
func (a *Attempts) Record(key []byte, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	k := string(key)
	cutoff := now.Add(-a.window)

	list := a.entries[k]
	// Drop expired prefix.
	i := 0
	for i < len(list) && list[i].Before(cutoff) {
		i++
	}
	list = list[i:]
	if len(list) >= a.capacity {
		// Shift left; drop the oldest.
		list = append(list[:0], list[len(list)-a.capacity+1:]...)
	}
	list = append(list, now)
	a.entries[k] = list
}

// Count returns the number of attempts for key in the current window.
func (a *Attempts) Count(key []byte, now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-a.window)
	list := a.entries[string(key)]
	n := 0
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Before(cutoff) {
			break
		}
		n++
	}
	return n
}

// Span returns the count, the earliest and the latest attempt for key in
// the current window. The count is the same value Count returns; first and
// last are zero when the count is zero.
func (a *Attempts) Span(key []byte, now time.Time) (count int, first, last time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-a.window)
	list := a.entries[string(key)]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Before(cutoff) {
			break
		}
		count++
		if last.IsZero() {
			last = list[i]
		}
		first = list[i]
	}
	return count, first, last
}

// Clear removes every recorded attempt for key.
func (a *Attempts) Clear(key []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.entries, string(key))
}

// Clean removes entries whose every attempt is older than the window.
func (a *Attempts) Clean(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-a.window)
	for k, list := range a.entries {
		if len(list) == 0 || list[len(list)-1].Before(cutoff) {
			delete(a.entries, k)
		}
	}
}
