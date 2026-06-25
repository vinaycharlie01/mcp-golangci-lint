package domain_test

import (
	"testing"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

func TestSeverityWeight(t *testing.T) {
	cases := []struct {
		sev    analysis.Severity
		weight int
	}{
		{analysis.SeverityCritical, 5},
		{analysis.SeverityHigh, 4},
		{analysis.SeverityMedium, 3},
		{analysis.SeverityLow, 2},
		{analysis.SeverityInfo, 1},
		{"unknown", 0},
	}

	for _, tc := range cases {
		if got := tc.sev.Weight(); got != tc.weight {
			t.Errorf("Severity(%q).Weight() = %d, want %d", tc.sev, got, tc.weight)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		input string
		want  analysis.Severity
	}{
		{"critical", analysis.SeverityCritical},
		{"CRITICAL", analysis.SeverityCritical},
		{"error", analysis.SeverityHigh},
		{"ERROR", analysis.SeverityHigh},
		{"high", analysis.SeverityHigh},
		{"HIGH", analysis.SeverityHigh},
		{"warning", analysis.SeverityMedium},
		{"WARNING", analysis.SeverityMedium},
		{"medium", analysis.SeverityMedium},
		{"info", analysis.SeverityLow},
		{"note", analysis.SeverityLow},
		{"low", analysis.SeverityLow},
		{"anything-else", analysis.SeverityLow},
	}

	for _, tc := range cases {
		got := analysis.NormalizeSeverity(tc.input)
		if got != tc.want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestBuildSummary(t *testing.T) {
	results := []analysis.Result{
		{
			Analyzer: "golangci-lint",
			Findings: []analysis.Finding{
				{Severity: analysis.SeverityHigh, Category: analysis.CategoryCorrectness, Analyzer: "golangci-lint", Fixable: true},
				{Severity: analysis.SeverityMedium, Category: analysis.CategorySecurity, Analyzer: "golangci-lint"},
			},
		},
		{
			Analyzer: "staticcheck",
			Findings: []analysis.Finding{
				{Severity: analysis.SeverityLow, Category: analysis.CategoryStyle, Analyzer: "staticcheck"},
			},
		},
	}

	s := analysis.BuildSummary(results)

	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.Fixable != 1 {
		t.Errorf("Fixable = %d, want 1", s.Fixable)
	}
	if s.BySeverity["high"] != 1 {
		t.Errorf("BySeverity[high] = %d, want 1", s.BySeverity["high"])
	}
	if s.BySeverity["medium"] != 1 {
		t.Errorf("BySeverity[medium] = %d, want 1", s.BySeverity["medium"])
	}
	if s.ByAnalyzer["golangci-lint"] != 2 {
		t.Errorf("ByAnalyzer[golangci-lint] = %d, want 2", s.ByAnalyzer["golangci-lint"])
	}
	if s.ByAnalyzer["staticcheck"] != 1 {
		t.Errorf("ByAnalyzer[staticcheck] = %d, want 1", s.ByAnalyzer["staticcheck"])
	}
	if s.ByCategory["security"] != 1 {
		t.Errorf("ByCategory[security] = %d, want 1", s.ByCategory["security"])
	}
}

func TestAggregatedResult_AllFindings(t *testing.T) {
	agg := &analysis.AggregatedResult{
		Results: []analysis.Result{
			{Findings: []analysis.Finding{{RuleID: "SA1006"}, {RuleID: "errcheck"}}},
			{Findings: []analysis.Finding{{RuleID: "G104"}}},
		},
	}

	findings := agg.AllFindings()
	if len(findings) != 3 {
		t.Errorf("AllFindings() count = %d, want 3", len(findings))
	}
}

func TestBuildSummary_Empty(t *testing.T) {
	s := analysis.BuildSummary(nil)
	if s.Total != 0 {
		t.Errorf("empty summary Total = %d, want 0", s.Total)
	}
	if s.BySeverity == nil {
		t.Error("BySeverity map should be non-nil")
	}
}
