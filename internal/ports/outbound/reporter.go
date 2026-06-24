package outbound

import (
	"context"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

// Reporter is the port for formatting and rendering analysis output.
type Reporter interface {
	// Format returns the reporter's output format identifier (e.g. "json", "markdown", "sarif").
	Format() string
	// Render converts an AggregatedResult to the target format.
	Render(ctx context.Context, result *analysis.AggregatedResult) ([]byte, error)
}
