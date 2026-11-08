// File: internal/limits/limits_test.go

package limits

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestBucketsAllow(t *testing.T) {
	b := NewBuckets(3, 1, time.Minute)

	key := []byte("alice")
	for i := 0; i < 3; i++ {
		if !b.Allow(key, t0) {
			t.Fatalf("call %d: denied below capacity", i)
		}
	}
	if b.Allow(key, t0) {
		t.Fatal("allowed above capacity")
	}

	// Refill after one period.
	if !b.Allow(key, t0.Add(time.Minute)) {
		t.Fatal("did not refill after the period")
	}
	if b.Allow(key, t0.Add(time.Minute)) {
		t.Fatal("refilled more than one token")
	}

	// Different key is independent.
	if !b.Allow([]byte("bob"), t0.Add(time.Minute)) {
		t.Fatal("bob was denied because of alice")
	}
}

func TestReplayCacheAccept(t *testing.T) {
	r := NewReplayCache(2, time.Minute)

	if !r.Accept([]byte("a"), t0) {
		t.Fatal("first a rejected")
	}
	if r.Accept([]byte("a"), t0) {
		t.Fatal("duplicate a accepted")
	}

	if !r.Accept([]byte("b"), t0) {
		t.Fatal("first b rejected")
	}
	// Evict "a" by adding "c" beyond capacity.
	if !r.Accept([]byte("c"), t0) {
		t.Fatal("first c rejected")
	}
	// "a" was evicted; but it is also within the TTL. Eviction wins by
	// design: the LRU is the replay memory.
	if !r.Accept([]byte("a"), t0) {
		t.Fatal("evicted entry was still rejected")
	}
}

func TestAttemptsWindow(t *testing.T) {
	a := NewAttempts(32, 15*time.Minute)

	key := []byte("alice")
	a.Record(key, t0)
	a.Record(key, t0.Add(time.Minute))
	a.Record(key, t0.Add(2*time.Minute))

	if n := a.Count(key, t0.Add(3*time.Minute)); n != 3 {
		t.Fatalf("count = %d, want 3", n)
	}
	if n := a.Count(key, t0.Add(15*time.Minute+time.Nanosecond)); n != 2 {
		t.Fatalf("count after first expires = %d, want 2", n)
	}
	if n := a.Count(key, t0.Add(20*time.Minute)); n != 0 {
		t.Fatalf("count after all expire = %d, want 0", n)
	}
}

func TestAttemptsClear(t *testing.T) {
	a := NewAttempts(32, time.Minute)
	key := []byte("alice")

	a.Record(key, t0)
	a.Clear(key)

	if n := a.Count(key, t0); n != 0 {
		t.Fatalf("count after clear = %d, want 0", n)
	}
}

func TestAttemptsSpan(t *testing.T) {
	a := NewAttempts(32, time.Minute)
	key := []byte("alice")

	a.Record(key, t0)
	a.Record(key, t0.Add(10*time.Second))
	a.Record(key, t0.Add(20*time.Second))

	count, first, last := a.Span(key, t0.Add(30*time.Second))
	if count != 3 || !first.Equal(t0) || !last.Equal(t0.Add(20*time.Second)) {
		t.Fatalf("Span = %d, %v, %v", count, first, last)
	}
}
