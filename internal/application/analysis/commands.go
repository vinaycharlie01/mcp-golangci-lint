// Package analysis contains the application-layer use cases for Go static analysis.
package analysis

import "time"

// AnalyzeRepositoryCommand requests a full repository analysis.
type AnalyzeRepositoryCommand struct {
	Path      string
	Analyzers []string
	Format    string
	Timeout   time.Duration
	Config    string
}

// AnalyzeFileCommand requests analysis of a single Go source file.
type AnalyzeFileCommand struct {
	FilePath  string
	Analyzers []string
	Format    string
}

// RunGolangCICommand requests a raw golangci-lint execution.
type RunGolangCICommand struct {
	Path    string
	Linters []string
	Config  string
	Timeout time.Duration
}

// ExplainFindingCommand requests a detailed explanation for a rule finding.
type ExplainFindingCommand struct {
	RuleID   string
	Analyzer string
	Message  string
	Code     string
}

// SuggestFixCommand requests a fix suggestion for a specific finding.
type SuggestFixCommand struct {
	RuleID   string
	Analyzer string
	Code     string
	FilePath string
	Line     int
}

// GenerateConfigCommand requests golangci-lint config generation.
type GenerateConfigCommand struct {
	Analyzers []string
	Strict    bool
}
