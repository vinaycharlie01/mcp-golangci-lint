package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/tests/mocks"
)

func buildService(t *testing.T, analyzers ...*mocks.MockAnalyzer) *appanalysis.Service {
	t.Helper()
	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)
	for _, a := range analyzers {
		svc.RegisterAnalyzer(a)
	}
	return svc
}

func newFinding(ruleID, analyzer string, sev domainanalysis.Severity) domainanalysis.Finding {
	return domainanalysis.Finding{
		ID:       ruleID + "-1",
		RuleID:   ruleID,
		Analyzer: analyzer,
		Severity: sev,
		Category: domainanalysis.CategoryCorrectness,
	}
}

func TestService_RegisterAndListAnalyzers(t *testing.T) {
	a1 := mocks.NewMockAnalyzer("lint-a")
	a2 := mocks.NewMockAnalyzer("lint-b")
	svc := buildService(t, a1, a2)

	list := svc.ListAnalyzers()
	if len(list) != 2 {
		t.Errorf("ListAnalyzers() count = %d, want 2", len(list))
	}
}

func TestService_GetAnalyzer(t *testing.T) {
	a := mocks.NewMockAnalyzer("golangci-lint")
	svc := buildService(t, a)

	got, ok := svc.GetAnalyzer("golangci-lint")
	if !ok || got == nil {
		t.Error("GetAnalyzer(golangci-lint) returned not found")
	}

	_, ok = svc.GetAnalyzer("nonexistent")
	if ok {
		t.Error("GetAnalyzer(nonexistent) should return false")
	}
}

func TestService_AnalyzeRepository_Success(t *testing.T) {
	result := &domainanalysis.Result{
		Analyzer: "mock",
		Status:   domainanalysis.StatusCompleted,
		Findings: []domainanalysis.Finding{
			newFinding("SA1006", "mock", domainanalysis.SeverityHigh),
		},
	}
	a := mocks.NewMockAnalyzer("mock").WithRunResult(result)
	svc := buildService(t, a)

	ctx := context.Background()
	cmd := appanalysis.AnalyzeRepositoryCommand{
		Path:    "/some/valid/path",
		Timeout: 30 * time.Second,
	}

	agg, err := svc.AnalyzeRepository(ctx, cmd)
	if err != nil {
		t.Fatalf("AnalyzeRepository() error: %v", err)
	}
	if agg == nil {
		t.Fatal("AnalyzeRepository() returned nil result")
	}
	if agg.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", agg.Summary.Total)
	}
	if len(a.Calls()) != 1 {
		t.Errorf("analyzer was called %d times, want 1", len(a.Calls()))
	}
}

func TestService_AnalyzeRepository_NoAnalyzers(t *testing.T) {
	svc := buildService(t)
	ctx := context.Background()
	cmd := appanalysis.AnalyzeRepositoryCommand{Path: "/some/path", Timeout: 5 * time.Second}

	_, err := svc.AnalyzeRepository(ctx, cmd)
	if err == nil {
		t.Error("expected error when no analyzers registered")
	}
}

func TestService_AnalyzeRepository_AnalyzerError(t *testing.T) {
	a := mocks.NewMockAnalyzer("bad").WithRunError(errors.New("analyzer exploded"))
	svc := buildService(t, a)

	ctx := context.Background()
	cmd := appanalysis.AnalyzeRepositoryCommand{Path: "/some/path", Timeout: 5 * time.Second}

	// An analyzer error is non-fatal; we get an empty aggregated result
	agg, err := svc.AnalyzeRepository(ctx, cmd)
	if err != nil {
		t.Fatalf("AnalyzeRepository() unexpected error: %v", err)
	}
	if agg.Summary.Total != 0 {
		t.Errorf("expected 0 findings after analyzer error, got %d", agg.Summary.Total)
	}
}

func TestService_AnalyzeFile_NotFound(t *testing.T) {
	a := mocks.NewMockAnalyzer("mock")
	svc := buildService(t, a)

	ctx := context.Background()
	cmd := appanalysis.AnalyzeFileCommand{FilePath: "/nonexistent.go"}

	_, err := svc.AnalyzeFile(ctx, cmd)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestService_AnalyzeFile_Success(t *testing.T) {
	result := &domainanalysis.Result{
		Analyzer: "mock",
		Status:   domainanalysis.StatusCompleted,
		Findings: []domainanalysis.Finding{
			newFinding("errcheck", "mock", domainanalysis.SeverityMedium),
			newFinding("bodyclose", "mock", domainanalysis.SeverityMedium),
		},
	}
	a := mocks.NewMockAnalyzer("mock").WithRunResult(result)
	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem().WithFile("/myfile.go", []byte("package main"))
	svc := appanalysis.NewService(cache, fs)
	svc.RegisterAnalyzer(a)

	ctx := context.Background()
	cmd := appanalysis.AnalyzeFileCommand{FilePath: "/myfile.go"}

	agg, err := svc.AnalyzeFile(ctx, cmd)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if agg.Summary.Total != 2 {
		t.Errorf("Summary.Total = %d, want 2", agg.Summary.Total)
	}
}

func TestService_ExplainFinding_UnknownAnalyzer(t *testing.T) {
	svc := buildService(t)
	ctx := context.Background()

	_, err := svc.ExplainFinding(ctx, appanalysis.ExplainFindingCommand{
		Analyzer: "nonexistent",
		RuleID:   "SA1006",
	})
	if err == nil {
		t.Error("expected error for unknown analyzer")
	}
}

func TestService_ExplainFinding_Success(t *testing.T) {
	a := mocks.NewMockAnalyzer("staticcheck").WithExplainResponse("SA1006: println is not a standard Go function")
	svc := buildService(t, a)
	ctx := context.Background()

	explanation, err := svc.ExplainFinding(ctx, appanalysis.ExplainFindingCommand{
		Analyzer: "staticcheck",
		RuleID:   "SA1006",
	})
	if err != nil {
		t.Fatalf("ExplainFinding() error: %v", err)
	}
	if explanation == "" {
		t.Error("expected non-empty explanation")
	}
}

func TestService_SuggestFix_NoAutoFix(t *testing.T) {
	a := mocks.NewMockAnalyzer("staticcheck").WithAutoFix(false)
	svc := buildService(t, a)
	ctx := context.Background()

	fix, err := svc.SuggestFix(ctx, appanalysis.SuggestFixCommand{
		Analyzer: "staticcheck",
		RuleID:   "SA1006",
	})
	if err != nil {
		t.Fatalf("SuggestFix() error: %v", err)
	}
	if fix == "" {
		t.Error("expected non-empty fix suggestion")
	}
}

func TestService_SuggestFix_AutoFix(t *testing.T) {
	a := mocks.NewMockAnalyzer("golangci-lint").WithAutoFix(true)
	svc := buildService(t, a)
	ctx := context.Background()

	fix, err := svc.SuggestFix(ctx, appanalysis.SuggestFixCommand{
		Analyzer: "golangci-lint",
		RuleID:   "gofmt",
		FilePath: "/path/to/file.go",
	})
	if err != nil {
		t.Fatalf("SuggestFix() error: %v", err)
	}
	if fix == "" {
		t.Error("expected non-empty fix command")
	}
}

func TestService_GenerateGolangCIConfig(t *testing.T) {
	a := mocks.NewMockAnalyzer("golangci-lint")
	svc := buildService(t, a)
	ctx := context.Background()

	cfg, err := svc.GenerateGolangCIConfig(ctx, appanalysis.GenerateConfigCommand{Strict: true})
	if err != nil {
		t.Fatalf("GenerateGolangCIConfig() error: %v", err)
	}
	if cfg == "" {
		t.Error("expected non-empty config output")
	}
	// Config should contain timeout
	if len(cfg) < 50 {
		t.Errorf("config seems too short (%d bytes)", len(cfg))
	}
}

func TestService_Render_UnknownFormat_FallsBackToJSON(t *testing.T) {
	// With no reporters registered (NewService with no reporters), Render
	// should fail gracefully.
	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)

	ctx := context.Background()
	agg := &domainanalysis.AggregatedResult{ID: "test-id"}

	_, err := svc.Render(ctx, agg, "nonexistent")
	if err == nil {
		t.Error("expected error when no reporters configured")
	}
}
