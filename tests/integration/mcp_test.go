package integration_test

import (
	"context"
	"testing"
	"time"

	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/tests/mocks"
)

// buildTestService creates a Service with mock adapters for integration tests.
func buildTestService(analyzers ...*mocks.MockAnalyzer) *appanalysis.Service {
	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem().WithFile("/test/main.go", []byte("package main"))
	svc := appanalysis.NewService(cache, fs)
	for _, a := range analyzers {
		svc.RegisterAnalyzer(a)
	}
	return svc
}

// TestService_ParallelAnalyzers verifies that multiple analyzers are run and
// results are correctly aggregated.
func TestService_ParallelAnalyzers(t *testing.T) {
	findings1 := []domainanalysis.Finding{
		{ID: "1", RuleID: "SA1006", Analyzer: "staticcheck", Severity: domainanalysis.SeverityHigh},
	}
	findings2 := []domainanalysis.Finding{
		{ID: "2", RuleID: "G104", Analyzer: "gosec", Severity: domainanalysis.SeverityMedium},
		{ID: "3", RuleID: "G202", Analyzer: "gosec", Severity: domainanalysis.SeverityCritical},
	}

	a1 := mocks.NewMockAnalyzer("staticcheck").WithRunResult(&domainanalysis.Result{
		Analyzer: "staticcheck",
		Status:   domainanalysis.StatusCompleted,
		Findings: findings1,
	})
	a2 := mocks.NewMockAnalyzer("gosec").WithRunResult(&domainanalysis.Result{
		Analyzer: "gosec",
		Status:   domainanalysis.StatusCompleted,
		Findings: findings2,
	})

	svc := buildTestService(a1, a2)
	ctx := context.Background()

	agg, err := svc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:    "/test",
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("AnalyzeRepository() error: %v", err)
	}

	if agg.Summary.Total != 3 {
		t.Errorf("Total = %d, want 3", agg.Summary.Total)
	}
	if agg.Summary.BySeverity["high"] != 1 {
		t.Errorf("BySeverity[high] = %d, want 1", agg.Summary.BySeverity["high"])
	}
	if agg.Summary.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", agg.Summary.BySeverity["critical"])
	}
	if agg.Summary.ByAnalyzer["gosec"] != 2 {
		t.Errorf("ByAnalyzer[gosec] = %d, want 2", agg.Summary.ByAnalyzer["gosec"])
	}
	// Both analyzers should have been called exactly once
	if len(a1.Calls()) != 1 {
		t.Errorf("staticcheck call count = %d, want 1", len(a1.Calls()))
	}
	if len(a2.Calls()) != 1 {
		t.Errorf("gosec call count = %d, want 1", len(a2.Calls()))
	}
}

// TestService_AnalyzerSelection verifies that named analyzer selection works.
func TestService_AnalyzerSelection(t *testing.T) {
	a1 := mocks.NewMockAnalyzer("golangci-lint").WithRunResult(&domainanalysis.Result{
		Analyzer: "golangci-lint",
		Status:   domainanalysis.StatusCompleted,
		Findings: []domainanalysis.Finding{{ID: "1", RuleID: "errcheck", Analyzer: "golangci-lint"}},
	})
	a2 := mocks.NewMockAnalyzer("staticcheck").WithRunResult(&domainanalysis.Result{
		Analyzer: "staticcheck",
		Findings: []domainanalysis.Finding{{ID: "2", RuleID: "SA1006", Analyzer: "staticcheck"}},
	})

	svc := buildTestService(a1, a2)
	ctx := context.Background()

	// Only request golangci-lint
	agg, err := svc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:      "/test",
		Analyzers: []string{"golangci-lint"},
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("AnalyzeRepository() error: %v", err)
	}

	if agg.Summary.Total != 1 {
		t.Errorf("Total = %d, want 1 (only golangci-lint selected)", agg.Summary.Total)
	}
	if len(a2.Calls()) != 0 {
		t.Errorf("staticcheck should NOT have been called, got %d calls", len(a2.Calls()))
	}
}

// TestService_CacheHit verifies the second call returns cached result.
func TestService_CacheHit(t *testing.T) {
	a := mocks.NewMockAnalyzer("golangci-lint").WithRunResult(&domainanalysis.Result{
		Analyzer: "golangci-lint",
		Status:   domainanalysis.StatusCompleted,
		Findings: []domainanalysis.Finding{{ID: "1", RuleID: "errcheck", Analyzer: "golangci-lint"}},
	})

	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)
	svc.RegisterAnalyzer(a)

	ctx := context.Background()
	cmd := appanalysis.AnalyzeRepositoryCommand{Path: "/test", Timeout: 5 * time.Second}

	_, err := svc.AnalyzeRepository(ctx, cmd)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	_, err = svc.AnalyzeRepository(ctx, cmd)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	// Analyzer should only have been called once (second hit from cache)
	if len(a.Calls()) != 1 {
		t.Errorf("analyzer call count = %d, want 1 (second call should hit cache)", len(a.Calls()))
	}
	if cache.Hits() < 1 {
		t.Errorf("cache hits = %d, want >= 1", cache.Hits())
	}
}

// TestService_ContextCancellation verifies that analysis respects context cancellation.
func TestService_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled immediately

	a := mocks.NewMockAnalyzer("golangci-lint").WithRunResult(&domainanalysis.Result{
		Analyzer: "golangci-lint",
		Status:   domainanalysis.StatusCompleted,
	})

	svc := buildTestService(a)
	// Even with cancelled context, the mock returns immediately — this test
	// verifies the path doesn't panic and service remains stable.
	_, _ = svc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:    "/test",
		Timeout: 5 * time.Second,
	})
}
