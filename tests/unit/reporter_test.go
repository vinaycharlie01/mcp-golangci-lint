package unit_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/reporters"
	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

func buildSampleResult() *domainanalysis.AggregatedResult {
	return &domainanalysis.AggregatedResult{
		ID: "test-agg-1",
		Target: domainanalysis.Target{
			Type: domainanalysis.TargetTypeRepository,
			Path: "/fake/repo",
		},
		Results: []domainanalysis.Result{
			{
				Analyzer: "golangci-lint",
				Status:   domainanalysis.StatusCompleted,
				Findings: []domainanalysis.Finding{
					{
						ID:       "f1",
						RuleID:   "errcheck",
						Message:  "error return value not checked",
						Severity: domainanalysis.SeverityCritical,
						Category: domainanalysis.CategoryCorrectness,
						Analyzer: "golangci-lint",
						Fixable:  true,
						Location: domainanalysis.Location{File: "main.go", Line: 10, Column: 5},
					},
					{
						ID:       "f2",
						RuleID:   "G104",
						Message:  "errors unhandled",
						Severity: domainanalysis.SeverityMedium,
						Category: domainanalysis.CategorySecurity,
						Analyzer: "golangci-lint",
						Location: domainanalysis.Location{File: "main.go", Line: 20},
					},
				},
				StartedAt: time.Now(),
				EndedAt:   time.Now(),
			},
		},
		Summary: domainanalysis.Summary{
			Total:      2,
			BySeverity: map[string]int{"critical": 1, "medium": 1},
			ByCategory: map[string]int{"correctness": 1, "security": 1},
			ByAnalyzer: map[string]int{"golangci-lint": 2},
			Fixable:    1,
		},
		StartedAt: time.Now(),
		EndedAt:   time.Now(),
	}
}

func TestJSONReporter_RendersValidJSON(t *testing.T) {
	r := reporters.NewJSON()
	if r.Format() != "json" {
		t.Errorf("Format() = %q, want %q", r.Format(), "json")
	}

	data, err := r.Render(context.Background(), buildSampleResult())
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Render() returned empty bytes")
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Errorf("Render() produced invalid JSON: %v", err)
	}

	if _, ok := out["id"]; !ok {
		t.Error("JSON output missing 'id' field")
	}
	if _, ok := out["summary"]; !ok {
		t.Error("JSON output missing 'summary' field")
	}
}

func TestMarkdownReporter_ReturnsNonEmptyMarkdown(t *testing.T) {
	r := reporters.NewMarkdown()
	if r.Format() != "markdown" {
		t.Errorf("Format() = %q, want %q", r.Format(), "markdown")
	}

	data, err := r.Render(context.Background(), buildSampleResult())
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Render() returned empty bytes")
	}

	md := string(data)
	if !strings.Contains(md, "#") {
		t.Error("markdown output should contain headers")
	}
	if !strings.Contains(md, "Summary") {
		t.Error("markdown output should contain Summary section")
	}
}

func TestSARIFReporter_ValidSARIF(t *testing.T) {
	r := reporters.NewSARIF()
	if r.Format() != "sarif" {
		t.Errorf("Format() = %q, want %q", r.Format(), "sarif")
	}

	data, err := r.Render(context.Background(), buildSampleResult())
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Render() returned empty bytes")
	}

	var sarif struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []any  `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", sarif.Version)
	}
	if !strings.Contains(sarif.Schema, "sarif") {
		t.Errorf("SARIF $schema = %q, want a sarif schema URL", sarif.Schema)
	}
	if len(sarif.Runs) == 0 {
		t.Error("SARIF runs should not be empty")
	}
}

func TestSeverityToLevel_Mapping(t *testing.T) {
	// We test the level mapping via SARIF rendering. Build a result with
	// one finding at each severity and verify the rendered level field.
	makeResult := func(sev domainanalysis.Severity) *domainanalysis.AggregatedResult {
		return &domainanalysis.AggregatedResult{
			Target: domainanalysis.Target{Type: domainanalysis.TargetTypeRepository, Path: "/r"},
			Results: []domainanalysis.Result{{
				Analyzer: "test",
				Findings: []domainanalysis.Finding{{
					RuleID:   "RULE1",
					Severity: sev,
					Message:  "test",
					Location: domainanalysis.Location{File: "a.go", Line: 1},
				}},
			}},
		}
	}

	cases := []struct {
		sev       domainanalysis.Severity
		wantLevel string
	}{
		{domainanalysis.SeverityCritical, "error"},
		{domainanalysis.SeverityHigh, "error"},
		{domainanalysis.SeverityMedium, "warning"},
		{domainanalysis.SeverityLow, "note"},
		{domainanalysis.SeverityInfo, "note"},
	}

	r := reporters.NewSARIF()
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.sev), func(t *testing.T) {
			data, err := r.Render(context.Background(), makeResult(tc.sev))
			if err != nil {
				t.Fatalf("Render() error: %v", err)
			}
			// Parse to extract the level of the first result in the first run
			var doc struct {
				Runs []struct {
					Results []struct {
						Level string `json:"level"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("invalid SARIF JSON: %v", err)
			}
			if len(doc.Runs) == 0 || len(doc.Runs[0].Results) == 0 {
				t.Fatal("no results in SARIF output")
			}
			got := doc.Runs[0].Results[0].Level
			if got != tc.wantLevel {
				t.Errorf("severity %q → SARIF level = %q, want %q", tc.sev, got, tc.wantLevel)
			}
		})
	}
}
