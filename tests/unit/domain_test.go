// Package unit_test contains unit tests for the domain/analysis package.
package unit_test

import (
	"testing"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

func TestSeverityWeight_AllLevels(t *testing.T) {
	cases := []struct {
		sev    domainanalysis.Severity
		weight int
	}{
		{domainanalysis.SeverityCritical, 5},
		{domainanalysis.SeverityHigh, 4},
		{domainanalysis.SeverityMedium, 3},
		{domainanalysis.SeverityLow, 2},
		{domainanalysis.SeverityInfo, 1},
		{"unknown-level", 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.sev), func(t *testing.T) {
			if got := tc.sev.Weight(); got != tc.weight {
				t.Errorf("Severity(%q).Weight() = %d, want %d", tc.sev, got, tc.weight)
			}
		})
	}
}

func TestNormalizeSeverity_AllKnownStrings(t *testing.T) {
	cases := []struct {
		input string
		want  domainanalysis.Severity
	}{
		{"critical", domainanalysis.SeverityCritical},
		{"CRITICAL", domainanalysis.SeverityCritical},
		{"error", domainanalysis.SeverityHigh},
		{"ERROR", domainanalysis.SeverityHigh},
		{"high", domainanalysis.SeverityHigh},
		{"HIGH", domainanalysis.SeverityHigh},
		{"warning", domainanalysis.SeverityMedium},
		{"WARNING", domainanalysis.SeverityMedium},
		{"medium", domainanalysis.SeverityMedium},
		{"MEDIUM", domainanalysis.SeverityMedium},
		{"info", domainanalysis.SeverityLow},
		{"INFO", domainanalysis.SeverityLow},
		{"low", domainanalysis.SeverityLow},
		{"LOW", domainanalysis.SeverityLow},
		{"note", domainanalysis.SeverityLow},
		{"NOTE", domainanalysis.SeverityLow},
		{"totally-unknown", domainanalysis.SeverityLow},
		{"", domainanalysis.SeverityLow},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got := domainanalysis.NormalizeSeverity(tc.input)
			if got != tc.want {
				t.Errorf("NormalizeSeverity(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestBuildSummary_MixedResults(t *testing.T) {
	results := []domainanalysis.Result{
		{
			Analyzer: "golangci-lint",
			Findings: []domainanalysis.Finding{
				{Severity: domainanalysis.SeverityCritical, Category: domainanalysis.CategorySecurity, Analyzer: "golangci-lint", Fixable: true},
				{Severity: domainanalysis.SeverityHigh, Category: domainanalysis.CategoryCorrectness, Analyzer: "golangci-lint"},
				{Severity: domainanalysis.SeverityMedium, Category: domainanalysis.CategoryPerformance, Analyzer: "golangci-lint", Fixable: true},
			},
		},
		{
			Analyzer: "staticcheck",
			Findings: []domainanalysis.Finding{
				{Severity: domainanalysis.SeverityLow, Category: domainanalysis.CategoryStyle, Analyzer: "staticcheck"},
				{Severity: domainanalysis.SeverityInfo, Category: domainanalysis.CategoryMaintainability, Analyzer: "staticcheck"},
			},
		},
	}

	s := domainanalysis.BuildSummary(results)

	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	if s.Fixable != 2 {
		t.Errorf("Fixable = %d, want 2", s.Fixable)
	}
	if s.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", s.BySeverity["critical"])
	}
	if s.ByAnalyzer["golangci-lint"] != 3 {
		t.Errorf("ByAnalyzer[golangci-lint] = %d, want 3", s.ByAnalyzer["golangci-lint"])
	}
	if s.ByAnalyzer["staticcheck"] != 2 {
		t.Errorf("ByAnalyzer[staticcheck] = %d, want 2", s.ByAnalyzer["staticcheck"])
	}
	if s.ByCategory["security"] != 1 {
		t.Errorf("ByCategory[security] = %d, want 1", s.ByCategory["security"])
	}
	if s.ByCategory["style"] != 1 {
		t.Errorf("ByCategory[style] = %d, want 1", s.ByCategory["style"])
	}
}

func TestBuildSummary_EmptyResults(t *testing.T) {
	s := domainanalysis.BuildSummary(nil)
	if s.Total != 0 {
		t.Errorf("Total = %d, want 0", s.Total)
	}
	if s.BySeverity == nil {
		t.Error("BySeverity map must not be nil")
	}
	if s.ByCategory == nil {
		t.Error("ByCategory map must not be nil")
	}
	if s.ByAnalyzer == nil {
		t.Error("ByAnalyzer map must not be nil")
	}
}

func TestAggregatedResult_AllFindings_Flattens(t *testing.T) {
	agg := &domainanalysis.AggregatedResult{
		Results: []domainanalysis.Result{
			{Findings: []domainanalysis.Finding{
				{RuleID: "SA1006"},
				{RuleID: "errcheck"},
			}},
			{Findings: []domainanalysis.Finding{
				{RuleID: "G104"},
			}},
			{Findings: nil}, // empty result should contribute nothing
		},
	}

	all := agg.AllFindings()
	if len(all) != 3 {
		t.Errorf("AllFindings() len = %d, want 3", len(all))
	}
	ids := map[string]bool{}
	for _, f := range all {
		ids[f.RuleID] = true
	}
	for _, want := range []string{"SA1006", "errcheck", "G104"} {
		if !ids[want] {
			t.Errorf("AllFindings() missing rule %q", want)
		}
	}
}

func TestCategoryConstants_Exist(t *testing.T) {
	expected := []domainanalysis.Category{
		domainanalysis.CategorySecurity,
		domainanalysis.CategoryCorrectness,
		domainanalysis.CategoryPerformance,
		domainanalysis.CategoryMaintainability,
		domainanalysis.CategoryStyle,
	}
	for _, c := range expected {
		if c == "" {
			t.Errorf("category constant is empty string")
		}
	}
}

func TestTargetTypeConstants_Exist(t *testing.T) {
	if domainanalysis.TargetTypeRepository == "" {
		t.Error("TargetTypeRepository must not be empty")
	}
	if domainanalysis.TargetTypeFile == "" {
		t.Error("TargetTypeFile must not be empty")
	}
	if domainanalysis.TargetTypeRepository == domainanalysis.TargetTypeFile {
		t.Error("TargetTypeRepository and TargetTypeFile must be distinct")
	}
}
