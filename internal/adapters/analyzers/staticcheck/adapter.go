// Package staticcheck implements the Analyzer port using the staticcheck tool.
package staticcheck

import (
	"bufio"
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
	adapterName = "staticcheck"
	adapterDesc = "staticcheck performs advanced static analysis of Go programs, detecting bugs and performance issues"
)

// staticcheckIssue represents one line of staticcheck's JSON output (JSONL format).
type staticcheckIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Location struct {
		File   string `json:"file"`
		Line   int    `json:"line"`
		Column int    `json:"column"`
	} `json:"location"`
	End struct {
		File   string `json:"file"`
		Line   int    `json:"line"`
		Column int    `json:"column"`
	} `json:"end"`
	Message string `json:"message"`
}

// Adapter implements outbound.Analyzer using staticcheck.
type Adapter struct{}

// New creates a new staticcheck Adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string         { return adapterName }
func (a *Adapter) Description() string  { return adapterDesc }
func (a *Adapter) SupportsAutoFix() bool { return false }

// Run executes staticcheck and parses its JSONL output.
func (a *Adapter) Run(ctx context.Context, req outbound.AnalysisRequest) (*domainanalysis.Result, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	start := time.Now()

	timeout := req.Options.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	target := "./..."
	if req.Target.Type == domainanalysis.TargetTypeFile {
		target = req.Target.Path
	}

	log.InfoContext(ctx, "running staticcheck", slog.String("target", target))

	res, err := executor.Run(ctx, executor.Options{
		Dir:     req.Target.Path,
		Timeout: timeout,
	}, "staticcheck", "-f", "json", target)
	if err != nil {
		return failedResult(req.Target, start, err), nil
	}

	findings := make([]domainanalysis.Finding, 0)
	scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var issue staticcheckIssue
		if err := json.Unmarshal([]byte(line), &issue); err != nil {
			log.WarnContext(ctx, "skipping unparseable staticcheck line",
				slog.String("line", line),
				slog.String("error", err.Error()),
			)
			continue
		}
		findings = append(findings, mapIssue(issue))
	}

	log.InfoContext(ctx, "staticcheck complete",
		slog.Int("findings", len(findings)),
		slog.Duration("duration", time.Since(start)),
	)
	return completedResult(req.Target, findings, start), nil
}

// ExplainFinding returns an explanation for a staticcheck finding code.
func (a *Adapter) ExplainFinding(_ context.Context, finding domainanalysis.Finding) (string, error) {
	prefix := ""
	if len(finding.RuleID) >= 2 {
		prefix = finding.RuleID[:2]
	}

	categories := map[string]string{
		"SA": "SA (staticcheck): Detects correctness problems and bugs that are never intentional.",
		"S":  "S (simple): Detects code that can be simplified.",
		"ST": "ST (stylecheck): Enforces style guide rules, similar to golint.",
		"QF": "QF (quickfix): Detects code patterns that can be refactored.",
	}

	desc := categories[prefix]
	if desc == "" {
		desc = "staticcheck finding"
	}

	return fmt.Sprintf("%s\n\nCode: %s\nMessage: %s\nSee: https://staticcheck.dev/docs/checks#%s",
		desc, finding.RuleID, finding.Message, strings.ToLower(finding.RuleID)), nil
}

// SupportedRules returns a representative set of staticcheck rules.
func (a *Adapter) SupportedRules() []outbound.Rule {
	return []outbound.Rule{
		{ID: "SA1000", Name: "SA1000", Description: "Invalid regular expression", Severity: "high", Category: "correctness", DocURL: "https://staticcheck.dev/docs/checks#SA1000"},
		{ID: "SA1006", Name: "SA1006", Description: "Printf with dynamic first argument", Severity: "high", Category: "correctness", DocURL: "https://staticcheck.dev/docs/checks#SA1006"},
		{ID: "SA4006", Name: "SA4006", Description: "Unused variable", Severity: "medium", Category: "maintainability", DocURL: "https://staticcheck.dev/docs/checks#SA4006"},
		{ID: "SA9003", Name: "SA9003", Description: "Empty body in if/else branch", Severity: "medium", Category: "correctness", DocURL: "https://staticcheck.dev/docs/checks#SA9003"},
		{ID: "S1000", Name: "S1000", Description: "Use plain channel send/receive", Severity: "low", Category: "style", DocURL: "https://staticcheck.dev/docs/checks#S1000"},
		{ID: "ST1000", Name: "ST1000", Description: "Package comment", Severity: "low", Category: "style", DocURL: "https://staticcheck.dev/docs/checks#ST1000"},
		{ID: "QF1001", Name: "QF1001", Description: "Apply De Morgan's law", Severity: "low", Category: "style", DocURL: "https://staticcheck.dev/docs/checks#QF1001"},
	}
}

func mapIssue(issue staticcheckIssue) domainanalysis.Finding {
	return domainanalysis.Finding{
		ID:       uuid.New().String(),
		RuleID:   issue.Code,
		Message:  issue.Message,
		Severity: codeToSeverity(issue.Code, issue.Severity),
		Category: codeToCategory(issue.Code),
		Location: domainanalysis.Location{
			File:    issue.Location.File,
			Line:    issue.Location.Line,
			Column:  issue.Location.Column,
			EndLine: issue.End.Line,
			EndCol:  issue.End.Column,
		},
		Analyzer:  adapterName,
		CreatedAt: time.Now(),
	}
}

func codeToSeverity(code, rawSeverity string) domainanalysis.Severity {
	if rawSeverity != "" {
		return domainanalysis.NormalizeSeverity(rawSeverity)
	}
	if strings.HasPrefix(code, "SA") {
		return domainanalysis.SeverityHigh
	}
	if strings.HasPrefix(code, "S") || strings.HasPrefix(code, "QF") {
		return domainanalysis.SeverityLow
	}
	return domainanalysis.SeverityMedium
}

func codeToCategory(code string) domainanalysis.Category {
	switch {
	case strings.HasPrefix(code, "SA"):
		return domainanalysis.CategoryCorrectness
	case strings.HasPrefix(code, "S"), strings.HasPrefix(code, "ST"), strings.HasPrefix(code, "QF"):
		return domainanalysis.CategoryStyle
	default:
		return domainanalysis.CategoryMaintainability
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
