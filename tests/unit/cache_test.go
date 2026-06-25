package unit_test

import (
	"context"
	"testing"
	"time"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/cache"
	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

func makeAggResult(id string) *domainanalysis.AggregatedResult {
	return &domainanalysis.AggregatedResult{
		ID: id,
		Target: domainanalysis.Target{
			Type: domainanalysis.TargetTypeRepository,
			Path: "/fake/" + id,
		},
	}
}

func TestMemoryCache_SetAndGet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := cache.NewMemoryCache(ctx)
	val := makeAggResult("abc")

	if err := c.Set(ctx, "key1", val, time.Minute); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	got, ok := c.Get(ctx, "key1")
	if !ok {
		t.Fatal("Get() returned false for an existing key")
	}
	if got == nil {
		t.Fatal("Get() returned nil value")
	}
	if got.ID != "abc" {
		t.Errorf("Get() ID = %q, want %q", got.ID, "abc")
	}
}

func TestMemoryCache_GetMissingKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := cache.NewMemoryCache(ctx)

	got, ok := c.Get(ctx, "nonexistent")
	if ok {
		t.Error("Get() returned true for a missing key")
	}
	if got != nil {
		t.Error("Get() returned non-nil for a missing key")
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := cache.NewMemoryCache(ctx)
	_ = c.Set(ctx, "key-del", makeAggResult("del"), time.Minute)

	_, ok := c.Get(ctx, "key-del")
	if !ok {
		t.Fatal("key should exist before Delete")
	}

	if err := c.Delete(ctx, "key-del"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	_, ok = c.Get(ctx, "key-del")
	if ok {
		t.Error("Get() returned true after Delete")
	}
}

func TestMemoryCache_TTLExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := cache.NewMemoryCache(ctx)
	_ = c.Set(ctx, "expiring", makeAggResult("exp"), 50*time.Millisecond)

	// Confirm it is present immediately after set.
	_, ok := c.Get(ctx, "expiring")
	if !ok {
		t.Fatal("key should be present right after Set")
	}

	// Wait for TTL to expire (60ms > 50ms TTL).
	time.Sleep(60 * time.Millisecond)

	_, ok = c.Get(ctx, "expiring")
	if ok {
		t.Error("Get() returned true after TTL expiry")
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := cache.NewMemoryCache(ctx)
	_ = c.Set(ctx, "k1", makeAggResult("1"), time.Minute)
	_ = c.Set(ctx, "k2", makeAggResult("2"), time.Minute)

	if err := c.Clear(ctx); err != nil {
		t.Fatalf("Clear() error: %v", err)
	}

	for _, k := range []string{"k1", "k2"} {
		_, ok := c.Get(ctx, k)
		if ok {
			t.Errorf("Get(%q) returned true after Clear", k)
		}
	}
}
