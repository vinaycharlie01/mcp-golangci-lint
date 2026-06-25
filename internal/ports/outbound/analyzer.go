// Package outbound defines the outbound ports (secondary/driven adapters) that
// the application layer depends on. Implementations live in internal/adapters/.
package outbound

import (
	"context"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

// Rule describes a single linting rule supported by an analyzer.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Fixable     bool   `json:"fixable"`
	DocURL      string `json:"doc_url,omitempty"`
}

// AnalysisRequest is the input to an Analyzer.Run call.
type AnalysisRequest struct {
	Target  analysis.Target
	Options analysis.Options
}

// Analyzer is the port every static analysis adapter must implement.
// New analyzers are plugged in by implementing this interface; no existing
// business logic needs to change.
type Analyzer interface {
	// Name returns the unique, lowercase analyzer identifier (e.g. "golangci-lint").
	Name() string
	// Description returns a human-readable summary of what the analyzer checks.
	Description() string
	// Run executes the analysis against the target and returns findings.
	Run(ctx context.Context, req AnalysisRequest) (*analysis.Result, error)
	// SupportsAutoFix reports whether the analyzer can auto-fix findings.
	SupportsAutoFix() bool
	// ExplainFinding provides a detailed explanation for a specific finding.
	ExplainFinding(ctx context.Context, finding analysis.Finding) (string, error)
	// SupportedRules returns all rules this analyzer is capable of detecting.
	SupportedRules() []Rule
}
