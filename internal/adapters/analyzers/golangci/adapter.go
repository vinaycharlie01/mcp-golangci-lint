// Package golangci implements the Analyzer port using golangci-lint.
// golangci-lint is one adapter among many; swapping it out never touches
// business logic.
package golangci

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/ports/outbound"
	"github.com/vinaycharlie01/mcp-golangci-lint/pkg/executor"
	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
)

const (
	adapterName = "golangci-lint"
	adapterDesc = "golangci-lint meta-linter: aggregates govet, errcheck, gosec, revive, bodyclose, and 40+ more linters"
)

// golangCIOutput is the JSON structure produced by `golangci-lint run --out-format json`.
type golangCIOutput struct {
	Issues []golangCIIssue `json:"Issues"`
}

type golangCIIssue struct {
	FromLinter  string   `json:"FromLinter"`
	Text        string   `json:"Text"`
	SourceLines []string `json:"SourceLines"`
	Pos         struct {
		Filename string `json:"Filename"`
		Line     int    `json:"Line"`
		Column   int    `json:"Column"`
	} `json:"Pos"`
	Replacement *struct {
		Inline *struct {
			StartCol  int    `json:"StartCol"`
			Length    int    `json:"Length"`
			NewString string `json:"NewString"`
		} `json:"Inline"`
	} `json:"Replacement"`
}

// Adapter implements outbound.Analyzer using golangci-lint.
// No state other than immutable configuration is held.
type Adapter struct{}

// New creates a new golangci-lint Adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string          { return adapterName }
func (a *Adapter) Description() string   { return adapterDesc }
func (a *Adapter) SupportsAutoFix() bool { return true }

// Run executes golangci-lint and maps its JSON output to domain findings.
func (a *Adapter) Run(ctx context.Context, req outbound.AnalysisRequest) (*domainanalysis.Result, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	start := time.Now()

	timeout := req.Options.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	args := buildArgs(req)
	log.InfoContext(ctx, "running golangci-lint",
		slog.String("path", req.Target.Path),
		slog.Any("linters", req.Options.Analyzers),
	)

	res, err := executor.Run(ctx, executor.Options{
		Dir:     req.Target.Path,
		Timeout: timeout,
	}, "golangci-lint", args...)
	if err != nil {
		return failedResult(req.Target, start, err), nil
	}

	// Exit code 1 from golangci-lint means issues were found – not an error.
	if strings.TrimSpace(res.Stdout) == "" {
		return completedResult(req.Target, nil, start), nil
	}

	var output golangCIOutput
	if err := json.Unmarshal([]byte(res.Stdout), &output); err != nil {
		log.WarnContext(ctx, "failed to parse golangci-lint JSON output",
			slog.String("error", err.Error()),
			slog.String("stderr", res.Stderr),
		)
		return failedResult(req.Target, start, fmt.Errorf("parsing output: %w", err)), nil
	}

	findings := make([]domainanalysis.Finding, 0, len(output.Issues))
	for _, issue := range output.Issues {
		findings = append(findings, mapIssue(issue))
	}

	log.InfoContext(ctx, "golangci-lint complete",
		slog.Int("findings", len(findings)),
		slog.Duration("duration", time.Since(start)),
	)
	return completedResult(req.Target, findings, start), nil
}

// ExplainFinding returns a human-readable explanation for the given finding.
func (a *Adapter) ExplainFinding(_ context.Context, finding domainanalysis.Finding) (string, error) {
	explanations := map[string]string{
		"govet":         "go vet reports suspicious constructs such as Printf calls with wrong argument types, unreachable code, and misuse of sync primitives.",
		"errcheck":      "errcheck detects unchecked errors. Every error return value must be explicitly handled.",
		"gosec":         "gosec inspects source code for security problems including SQL injection, command injection, and insecure crypto.",
		"revive":        "revive is a fast, configurable, extensible linter enforcing Go coding style best practices.",
		"ineffassign":   "ineffassign detects assignments to existing variables that are never used afterwards.",
		"unused":        "unused checks for constants, variables, functions, and types that are declared but never used.",
		"bodyclose":     "bodyclose checks whether HTTP response bodies are properly closed to prevent resource leaks.",
		"noctx":         "noctx finds HTTP requests made without a context, preventing proper cancellation and timeout propagation.",
		"exhaustive":    "exhaustive checks that switch statements on enum types handle all cases.",
		"unconvert":     "unconvert detects unnecessary type conversions that can be removed.",
		"unparam":       "unparam reports function parameters that always receive the same constant value.",
		"wastedassign":  "wastedassign finds statements whose assigned values are never used.",
		"rowserrcheck":  "rowserrcheck verifies that sql.Rows.Err() is checked after row iteration.",
		"sqlclosecheck": "sqlclosecheck verifies that sql.Rows and sql.Stmt objects are properly closed.",
		"contextcheck":  "contextcheck verifies that context is propagated correctly through function calls.",
		"nolintlint":    "nolintlint validates that //nolint directives are properly formatted and justified.",
	}
	linter := finding.Analyzer
	if linter == adapterName {
		linter = finding.RuleID
	}
	if exp, ok := explanations[linter]; ok {
		return fmt.Sprintf("%s\n\nRule: %s\nMessage: %s", exp, finding.RuleID, finding.Message), nil
	}
	return fmt.Sprintf("golangci-lint/%s: %s", finding.RuleID, finding.Message), nil
}

// SupportedRules returns the primary rules this adapter detects.
func (a *Adapter) SupportedRules() []outbound.Rule {
	return []outbound.Rule{
		{ID: "govet", Name: "govet", Description: "Suspicious constructs detected by go vet", Severity: "high", Category: "correctness"},
		{ID: "errcheck", Name: "errcheck", Description: "Unchecked errors", Severity: "high", Category: "correctness"},
		{ID: "gosec", Name: "gosec", Description: "Security vulnerabilities", Severity: "high", Category: "security", DocURL: "https://github.com/securego/gosec"},
		{ID: "revive", Name: "revive", Description: "Go style and best practices", Severity: "low", Category: "style", DocURL: "https://revive.run"},
		{ID: "ineffassign", Name: "ineffassign", Description: "Ineffectual variable assignments", Severity: "low", Category: "maintainability"},
		{ID: "unused", Name: "unused", Description: "Unused code", Severity: "medium", Category: "maintainability"},
		{ID: "bodyclose", Name: "bodyclose", Description: "Unclosed HTTP response bodies", Severity: "high", Category: "correctness"},
		{ID: "noctx", Name: "noctx", Description: "HTTP requests without context", Severity: "medium", Category: "correctness"},
		{ID: "exhaustive", Name: "exhaustive", Description: "Non-exhaustive enum switches", Severity: "medium", Category: "correctness"},
		{ID: "unconvert", Name: "unconvert", Description: "Unnecessary type conversions", Severity: "low", Category: "performance"},
		{ID: "unparam", Name: "unparam", Description: "Unused function parameters", Severity: "low", Category: "maintainability"},
		{ID: "wastedassign", Name: "wastedassign", Description: "Wasted assignment statements", Severity: "low", Category: "maintainability"},
		{ID: "rowserrcheck", Name: "rowserrcheck", Description: "Unchecked sql.Rows.Err()", Severity: "high", Category: "correctness"},
		{ID: "sqlclosecheck", Name: "sqlclosecheck", Description: "Unclosed SQL rows/statements", Severity: "high", Category: "correctness"},
		{ID: "contextcheck", Name: "contextcheck", Description: "Incorrect context propagation", Severity: "medium", Category: "correctness"},
		{ID: "nolintlint", Name: "nolintlint", Description: "Malformed nolint directives", Severity: "low", Category: "style"},
	}
}

func buildArgs(req outbound.AnalysisRequest) []string {
	args := []string{"run", "--out-format", "json", "--allow-parallel-runners"}

	if req.Options.Config != "" {
		args = append(args, "--config", req.Options.Config)
	}

	if len(req.Options.Analyzers) > 0 {
		args = append(args, "--disable-all", "--enable", strings.Join(req.Options.Analyzers, ","))
	}

	if req.Options.Timeout > 0 {
		args = append(args, "--timeout", req.Options.Timeout.String())
	}

	if req.Target.Type == domainanalysis.TargetTypeFile {
		args = append(args, req.Target.Path)
	} else {
		args = append(args, "./...")
	}

	return args
}

func mapIssue(issue golangCIIssue) domainanalysis.Finding {
	fixable := issue.Replacement != nil && issue.Replacement.Inline != nil
	return domainanalysis.Finding{
		ID:       uuid.New().String(),
		RuleID:   issue.FromLinter,
		Message:  issue.Text,
		Severity: linterSeverity(issue.FromLinter),
		Category: linterCategory(issue.FromLinter),
		Location: domainanalysis.Location{
			File:   issue.Pos.Filename,
			Line:   issue.Pos.Line,
			Column: issue.Pos.Column,
		},
		Analyzer:    adapterName,
		Fixable:     fixable,
		SourceLines: issue.SourceLines,
		CreatedAt:   time.Now(),
	}
}

func linterSeverity(linter string) domainanalysis.Severity {
	switch linter {
	case "govet", "errcheck", "gosec", "bodyclose", "rowserrcheck", "sqlclosecheck":
		return domainanalysis.SeverityHigh
	case "noctx", "exhaustive", "contextcheck", "unused":
		return domainanalysis.SeverityMedium
	default:
		return domainanalysis.SeverityLow
	}
}

func linterCategory(linter string) domainanalysis.Category {
	switch linter {
	case "gosec":
		return domainanalysis.CategorySecurity
	case "unconvert":
		return domainanalysis.CategoryPerformance
	case "revive", "nolintlint":
		return domainanalysis.CategoryStyle
	case "ineffassign", "unused", "unparam", "wastedassign":
		return domainanalysis.CategoryMaintainability
	default:
		return domainanalysis.CategoryCorrectness
	}
}

func completedResult(target domainanalysis.Target, findings []domainanalysis.Finding, start time.Time) *domainanalysis.Result {
	now := time.Now()
	return &domainanalysis.Result{
		ID:        uuid.New().String(),
		Status:    domainanalysis.StatusCompleted,
		Target:    target,
		Findings:  findings,
		Analyzer:  adapterName,
		StartedAt: start,
		EndedAt:   now,
		Duration:  now.Sub(start),
	}
}

func failedResult(target domainanalysis.Target, start time.Time, err error) *domainanalysis.Result {
	now := time.Now()
	return &domainanalysis.Result{
		ID:        uuid.New().String(),
		Status:    domainanalysis.StatusFailed,
		Target:    target,
		Analyzer:  adapterName,
		StartedAt: start,
		EndedAt:   now,
		Duration:  now.Sub(start),
		Error:     err.Error(),
	}
}
