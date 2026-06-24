package reporters

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

// MarkdownReporter renders analysis results as a Markdown report.
type MarkdownReporter struct{}

// NewMarkdown creates a MarkdownReporter.
func NewMarkdown() *MarkdownReporter { return &MarkdownReporter{} }

func (r *MarkdownReporter) Format() string { return "markdown" }

// Render produces a human-readable Markdown report.
func (r *MarkdownReporter) Render(_ context.Context, result *domainanalysis.AggregatedResult) ([]byte, error) {
	var b bytes.Buffer

	fmt.Fprintf(&b, "# Go Static Analysis Report\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`  \n", result.Target.Path)
	fmt.Fprintf(&b, "**Type:** %s  \n", result.Target.Type)
	fmt.Fprintf(&b, "**Duration:** %s  \n\n", result.Duration.Round(1000000))

	// Summary table
	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Metric | Count |\n|--------|-------|\n")
	fmt.Fprintf(&b, "| Total findings | **%d** |\n", result.Summary.Total)
	fmt.Fprintf(&b, "| Auto-fixable | %d |\n", result.Summary.Fixable)

	for sev, count := range result.Summary.BySeverity {
		fmt.Fprintf(&b, "| %s | %d |\n", strings.Title(sev), count) //nolint:staticcheck
	}
	b.WriteString("\n")

	// Findings grouped by severity
	findings := result.AllFindings()
	bySeverity := groupBySeverity(findings)

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		group := bySeverity[sev]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s Severity (%d)\n\n", strings.Title(sev), len(group)) //nolint:staticcheck
		for _, f := range group {
			fmt.Fprintf(&b, "### `%s` — %s\n\n", f.RuleID, f.Analyzer)
			fmt.Fprintf(&b, "**File:** `%s:%d`  \n", f.Location.File, f.Location.Line)
			fmt.Fprintf(&b, "**Message:** %s  \n", f.Message)
			if f.Fixable {
				fmt.Fprintf(&b, "**Auto-fixable:** ✓  \n")
			}
			if len(f.SourceLines) > 0 {
				fmt.Fprintf(&b, "\n```go\n%s\n```\n", strings.Join(f.SourceLines, "\n"))
			}
			b.WriteString("\n---\n\n")
		}
	}

	return b.Bytes(), nil
}

func groupBySeverity(findings []domainanalysis.Finding) map[string][]domainanalysis.Finding {
	m := make(map[string][]domainanalysis.Finding)
	for _, f := range findings {
		key := string(f.Severity)
		m[key] = append(m[key], f)
	}
	return m
}
