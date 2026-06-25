package benchmarks_test

import (
	"testing"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

// makeFinding creates a finding with the given severity for benchmark use.
func makeFinding(sev domainanalysis.Severity, fixable bool) domainanalysis.Finding {
	return domainanalysis.Finding{
		RuleID:   "bench-rule",
		Message:  "benchmark finding",
		Severity: sev,
		Category: domainanalysis.CategoryCorrectness,
		Analyzer: "bench-analyzer",
		Fixable:  fixable,
	}
}

// BenchmarkBuildSummary measures BuildSummary over 1000 findings.
func BenchmarkBuildSummary(b *testing.B) {
	severities := []domainanalysis.Severity{
		domainanalysis.SeverityCritical,
		domainanalysis.SeverityHigh,
		domainanalysis.SeverityMedium,
		domainanalysis.SeverityLow,
		domainanalysis.SeverityInfo,
	}

	findings := make([]domainanalysis.Finding, 0, 1000)
	for i := 0; i < 1000; i++ {
		sev := severities[i%len(severities)]
		findings = append(findings, makeFinding(sev, i%3 == 0))
	}

	results := []domainanalysis.Result{
		{Analyzer: "golangci-lint", Findings: findings[:500]},
		{Analyzer: "staticcheck", Findings: findings[500:]},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = domainanalysis.BuildSummary(results)
	}
}

// BenchmarkNormalizeSeverity measures NormalizeSeverity across all input forms.
func BenchmarkNormalizeSeverity(b *testing.B) {
	inputs := []string{
		"critical", "CRITICAL",
		"error", "ERROR",
		"high", "HIGH",
		"warning", "WARNING",
		"medium", "MEDIUM",
		"info", "INFO",
		"low", "LOW",
		"note", "NOTE",
		"unknown",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		_ = domainanalysis.NormalizeSeverity(input)
	}
}

// BenchmarkAllFindings measures the cost of flattening findings from many results.
func BenchmarkAllFindings(b *testing.B) {
	const resultsCount = 10
	const findingsPerResult = 100

	findings := make([]domainanalysis.Finding, findingsPerResult)
	for i := range findings {
		findings[i] = makeFinding(domainanalysis.SeverityMedium, false)
	}

	results := make([]domainanalysis.Result, resultsCount)
	for i := range results {
		results[i] = domainanalysis.Result{
			Analyzer: "bench",
			Findings: findings,
		}
	}

	agg := &domainanalysis.AggregatedResult{Results: results}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = agg.AllFindings()
	}
}
