// Package gosec implements the Analyzer port using the gosec security scanner.
package gosec

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/ports/outbound"
	"github.com/vinaycharlie01/mcp-golangci-lint/pkg/executor"
	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
)

const (
	adapterName = "gosec"
	adapterDesc = "gosec inspects Go source code for security vulnerabilities including SQL injection, " +
		"command injection, insecure crypto, hardcoded credentials, and SSRF"
)

// gosecOutput is the top-level JSON structure produced by `gosec -fmt json`.
type gosecOutput struct {
	Issues  []gosecIssue  `json:"Issues"`
	Metrics gosecMetrics  `json:"Metrics"`
}

type gosecIssue struct {
	Severity   string  `json:"severity"`
	Confidence string  `json:"confidence"`
	RuleID     string  `json:"rule_id"`
	Details    string  `json:"details"`
	File       string  `json:"file"`
	Line       string  `json:"line"`
	Column     string  `json:"column"`
	Code       string  `json:"code"`
	CWE        *gosecCWE `json:"cwe"`
}

type gosecCWE struct {
	ID  string `json:"ID"`
	URL string `json:"URL"`
}

type gosecMetrics struct {
	Files int `json:"files"`
	Lines int `json:"lines"`
	Found int `json:"found"`
}

// Adapter implements outbound.Analyzer using gosec.
type Adapter struct{}

// New creates a new gosec Adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) Name() string          { return adapterName }
func (a *Adapter) Description() string   { return adapterDesc }
func (a *Adapter) SupportsAutoFix() bool { return false }

// Run executes gosec and maps its JSON output to domain findings.
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

	log.InfoContext(ctx, "running gosec", slog.String("target", target))

	res, err := executor.Run(ctx, executor.Options{
		Dir:     req.Target.Path,
		Timeout: timeout,
	}, "gosec", "-fmt", "json", "-nosec", "-quiet", target)
	if err != nil {
		return failedResult(req.Target, start, err), nil
	}

	// gosec exits 1 when issues are found – this is normal
	if res.Stdout == "" {
		return completedResult(req.Target, nil, start), nil
	}

	var output gosecOutput
	if err := json.Unmarshal([]byte(res.Stdout), &output); err != nil {
		log.WarnContext(ctx, "failed to parse gosec JSON output",
			slog.String("error", err.Error()),
		)
		return failedResult(req.Target, start, fmt.Errorf("parsing output: %w", err)), nil
	}

	findings := make([]domainanalysis.Finding, 0, len(output.Issues))
	for _, issue := range output.Issues {
		findings = append(findings, mapIssue(issue))
	}

	log.InfoContext(ctx, "gosec complete",
		slog.Int("findings", len(findings)),
		slog.Duration("duration", time.Since(start)),
	)
	return completedResult(req.Target, findings, start), nil
}

// ExplainFinding provides security-focused context for a gosec finding.
func (a *Adapter) ExplainFinding(_ context.Context, finding domainanalysis.Finding) (string, error) {
	ruleExplain := map[string]string{
		"G101": "Hardcoded credentials detected. Credentials must never be committed to source code.",
		"G102": "Network binding to all interfaces (0.0.0.0) may expose unintended services.",
		"G103": "Use of unsafe package bypasses Go memory safety guarantees.",
		"G104": "Errors unhandled. Ignoring errors can mask security-relevant failures.",
		"G106": "Use of ssh.InsecureIgnoreHostKey disables host verification, enabling MITM attacks.",
		"G107": "URL provided to HTTP request as a variable – potential SSRF vulnerability.",
		"G108": "Profiling endpoint exposed automatically. Restrict access in production.",
		"G112": "Insufficient TLS minimum version configured.",
		"G201": "SQL query formatted using string interpolation – potential SQL injection.",
		"G202": "SQL query built using string concatenation – potential SQL injection.",
		"G204": "User-supplied input passed to exec.Command – potential command injection.",
		"G304": "File path provided as taint input – potential path traversal.",
		"G401": "Use of weak cryptographic algorithm (MD5/SHA1).",
		"G402": "TLS InsecureSkipVerify set to true – disables certificate verification.",
		"G403": "RSA key length < 2048 bits is insufficient.",
		"G404": "Weak random number generator (math/rand) used for security-sensitive operations.",
		"G501": "Blocked import (crypto/md5) – use crypto/sha256 or better.",
		"G601": "Implicit memory aliasing in for-loop range.",
	}

	if exp, ok := ruleExplain[finding.RuleID]; ok {
		return fmt.Sprintf("Security Issue: %s\n\nRule: %s\nDetails: %s\n\nSee: https://github.com/securego/gosec/blob/main/rules",
			exp, finding.RuleID, finding.Message), nil
	}
	return fmt.Sprintf("gosec/%s: %s\n\nSee: https://github.com/securego/gosec",
		finding.RuleID, finding.Message), nil
}

// SupportedRules returns the security rules gosec enforces.
func (a *Adapter) SupportedRules() []outbound.Rule {
	return []outbound.Rule{
		{ID: "G101", Name: "G101", Description: "Hardcoded credentials", Severity: "critical", Category: "security", DocURL: "https://github.com/securego/gosec"},
		{ID: "G102", Name: "G102", Description: "Bind to all interfaces", Severity: "medium", Category: "security"},
		{ID: "G103", Name: "G103", Description: "Use of unsafe package", Severity: "medium", Category: "security"},
		{ID: "G104", Name: "G104", Description: "Errors unhandled", Severity: "high", Category: "correctness"},
		{ID: "G107", Name: "G107", Description: "SSRF via user-controlled URL", Severity: "high", Category: "security"},
		{ID: "G201", Name: "G201", Description: "SQL injection via string format", Severity: "critical", Category: "security"},
		{ID: "G202", Name: "G202", Description: "SQL injection via concatenation", Severity: "critical", Category: "security"},
		{ID: "G204", Name: "G204", Description: "Command injection", Severity: "critical", Category: "security"},
		{ID: "G304", Name: "G304", Description: "Path traversal", Severity: "high", Category: "security"},
		{ID: "G401", Name: "G401", Description: "Weak hash algorithm", Severity: "high", Category: "security"},
		{ID: "G402", Name: "G402", Description: "TLS InsecureSkipVerify", Severity: "critical", Category: "security"},
		{ID: "G404", Name: "G404", Description: "Weak random number generator", Severity: "high", Category: "security"},
	}
}

func mapIssue(issue gosecIssue) domainanalysis.Finding {
	line, _ := strconv.Atoi(issue.Line)
	col, _ := strconv.Atoi(issue.Column)

	suggestion := ""
	if issue.CWE != nil {
		suggestion = fmt.Sprintf("CWE-%s: %s", issue.CWE.ID, issue.CWE.URL)
	}

	return domainanalysis.Finding{
		ID:         uuid.New().String(),
		RuleID:     issue.RuleID,
		Message:    issue.Details,
		Severity:   domainanalysis.NormalizeSeverity(issue.Severity),
		Category:   domainanalysis.CategorySecurity,
		Location: domainanalysis.Location{
			File:   issue.File,
			Line:   line,
			Column: col,
		},
		Analyzer:    adapterName,
		Suggestion:  suggestion,
		SourceLines: []string{issue.Code},
		CreatedAt:   time.Now(),
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
