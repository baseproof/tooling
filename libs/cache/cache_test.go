package cache

import (
	"sync"
	"testing"
	"time"
)

func TestCache_GetMiss(t *testing.T) {
	c := New[string]()
	if v, ok := c.Get("missing"); ok || v != "" {
		t.Errorf("Get on empty cache = (%q, %v), want (\"\", false)", v, ok)
	}
}

func TestCache_GetSetRoundTrip(t *testing.T) {
	c := New[int]()
	c.Set("k", 42, time.Hour)
	v, ok := c.Get("k")
	if !ok || v != 42 {
		t.Errorf("Get = (%d, %v), want (42, true)", v, ok)
	}
}

func TestCache_ZeroTTLNoOp(t *testing.T) {
	c := New[string]()
	c.Set("k", "v", 0)
	if _, ok := c.Get("k"); ok {
		t.Error("zero TTL should not store")
	}
	c.Set("k2", "v2", -time.Second)
	if _, ok := c.Get("k2"); ok {
		t.Error("negative TTL should not store")
	}
}

func TestCache_Expiry(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	clock := now
	c := NewWithClock[string](func() time.Time { return clock })

	c.Set("ephemeral", "x", 100*time.Millisecond)
	if v, ok := c.Get("ephemeral"); !ok || v != "x" {
		t.Fatalf("immediate Get = (%q, %v)", v, ok)
	}

	clock = now.Add(50 * time.Millisecond)
	if v, ok := c.Get("ephemeral"); !ok || v != "x" {
		t.Errorf("half-life Get = (%q, %v), want fresh", v, ok)
	}

	clock = now.Add(200 * time.Millisecond)
	if _, ok := c.Get("ephemeral"); ok {
		t.Error("post-expiry Get should miss")
	}
	// Lazy eviction kicked in.
	if c.Len() != 0 {
		t.Errorf("Len after expired Get = %d, want 0", c.Len())
	}
}

func TestCache_Replace(t *testing.T) {
	c := New[int]()
	c.Set("k", 1, time.Hour)
	c.Set("k", 2, time.Hour)
	v, _ := c.Get("k")
	if v != 2 {
		t.Errorf("after replace Get = %d, want 2", v)
	}
}

func TestCache_Delete(t *testing.T) {
	c := New[int]()
	c.Set("k", 1, time.Hour)
	c.Delete("k")
	if _, ok := c.Get("k"); ok {
		t.Error("Delete then Get should miss")
	}
	// Idempotent.
	c.Delete("k")
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := New[int]()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			c.Set("k", i, time.Minute)
		}(i)
		go func() {
			defer wg.Done()
			_, _ = c.Get("k")
		}()
	}
	wg.Wait()
	// No assertion beyond "didn't race / panic". With -race
	// the harness catches contention bugs.
}
