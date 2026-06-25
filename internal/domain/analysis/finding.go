// Package analysis contains the core domain entities for static analysis results.
// This package has zero external dependencies – pure Go types only.
package analysis

import "time"

// Severity represents the issue severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Category classifies the nature of a finding.
type Category string

const (
	CategorySecurity        Category = "security"
	CategoryCorrectness     Category = "correctness"
	CategoryPerformance     Category = "performance"
	CategoryMaintainability Category = "maintainability"
	CategoryStyle           Category = "style"
)

// Location identifies the source position of a finding.
type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	EndLine int    `json:"end_line,omitempty"`
	EndCol  int    `json:"end_col,omitempty"`
}

// Finding represents a single static analysis result.
type Finding struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	Message     string    `json:"message"`
	Severity    Severity  `json:"severity"`
	Category    Category  `json:"category"`
	Location    Location  `json:"location"`
	Analyzer    string    `json:"analyzer"`
	Fixable     bool      `json:"fixable"`
	Explanation string    `json:"explanation,omitempty"`
	Suggestion  string    `json:"suggestion,omitempty"`
	SourceLines []string  `json:"source_lines,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// SeverityWeight returns a numeric weight for comparison / sorting.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// NormalizeSeverity maps common linter severity strings to a domain Severity.
func NormalizeSeverity(s string) Severity {
	switch s {
	case "critical", "CRITICAL":
		return SeverityCritical
	case "error", "ERROR", "high", "HIGH":
		return SeverityHigh
	case "warning", "WARNING", "medium", "MEDIUM":
		return SeverityMedium
	case "info", "INFO", "low", "LOW", "note", "NOTE":
		return SeverityLow
	default:
		return SeverityLow
	}
}
