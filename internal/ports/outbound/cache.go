package outbound

import (
	"context"
	"time"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

// Cache is the port for storing and retrieving analysis results.
type Cache interface {
	Get(ctx context.Context, key string) (*analysis.AggregatedResult, bool)
	Set(ctx context.Context, key string, result *analysis.AggregatedResult, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
}
