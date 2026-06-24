// Package reporters implements the Reporter port for multiple output formats.
package reporters

import (
	"context"
	"encoding/json"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

// JSONReporter renders analysis results as indented JSON.
type JSONReporter struct{}

// NewJSON creates a JSONReporter.
func NewJSON() *JSONReporter { return &JSONReporter{} }

func (r *JSONReporter) Format() string { return "json" }

// Render serializes the AggregatedResult to indented JSON bytes.
func (r *JSONReporter) Render(_ context.Context, result *domainanalysis.AggregatedResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
