// Package cache provides an in-memory implementation of the Cache port.
package cache

import (
	"context"
	"log/slog"
	"sync"
	"time"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
)

type entry struct {
	result    *domainanalysis.AggregatedResult
	expiresAt time.Time
}

// MemoryCache is a thread-safe, TTL-based in-memory cache.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]entry
}

// NewMemoryCache creates a MemoryCache and starts a background eviction goroutine.
func NewMemoryCache(ctx context.Context) *MemoryCache {
	c := &MemoryCache{entries: make(map[string]entry)}
	go c.evictLoop(ctx)
	return c
}

// Get retrieves a cached result by key.
func (c *MemoryCache) Get(_ context.Context, key string) (*domainanalysis.AggregatedResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.result, true
}

// Set stores a result with the given TTL.
func (c *MemoryCache) Set(ctx context.Context, key string, result *domainanalysis.AggregatedResult, ttl time.Duration) error {
	log := pkglogger.FromContext(ctx, slog.Default())
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = entry{result: result, expiresAt: time.Now().Add(ttl)}
	log.DebugContext(ctx, "cache set", slog.String("key", key), slog.Duration("ttl", ttl))
	return nil
}

// Delete removes a cached entry.
func (c *MemoryCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
	return nil
}

// Clear removes all cached entries.
func (c *MemoryCache) Clear(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]entry)
	return nil
}

// evictLoop removes expired entries every minute.
func (c *MemoryCache) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.evict()
		}
	}
}

func (c *MemoryCache) evict() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}
