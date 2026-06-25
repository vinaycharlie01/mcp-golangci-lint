package integration_test

import (
	"context"
	"strings"
	"testing"

	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/tests/mocks"
)

// buildEmptyService creates a Service with no analyzers registered.
func buildEmptyService() *appanalysis.Service {
	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	return appanalysis.NewService(cache, fs)
}

func TestAnalysisService_NoAnalyzers_ReturnsError(t *testing.T) {
	svc := buildEmptyService()
	ctx := context.Background()

	_, err := svc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path: "/any/path",
	})
	if err == nil {
		t.Error("AnalyzeRepository() with no analyzers: expected error, got nil")
	}
}

func TestAnalysisService_ExplainFinding_UnknownAnalyzer(t *testing.T) {
	svc := buildEmptyService()
	ctx := context.Background()

	_, err := svc.ExplainFinding(ctx, appanalysis.ExplainFindingCommand{
		Analyzer: "nonexistent",
		RuleID:   "SA1006",
		Message:  "some message",
	})
	if err == nil {
		t.Error("ExplainFinding() with unknown analyzer: expected error, got nil")
	}
}

func TestAnalysisService_ExplainFinding_KnownAnalyzer(t *testing.T) {
	a := mocks.NewMockAnalyzer("golangci-lint").
		WithExplainResponse("errcheck: error return value not checked — always handle returned errors")

	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)
	svc.RegisterAnalyzer(a)

	ctx := context.Background()
	explanation, err := svc.ExplainFinding(ctx, appanalysis.ExplainFindingCommand{
		Analyzer: "golangci-lint",
		RuleID:   "errcheck",
		Message:  "error return value not checked",
	})
	if err != nil {
		t.Fatalf("ExplainFinding() error: %v", err)
	}
	if explanation == "" {
		t.Error("ExplainFinding() returned empty explanation")
	}
}

func TestAnalysisService_GenerateGolangCIConfig_ContainsLinters(t *testing.T) {
	a := mocks.NewMockAnalyzer("golangci-lint")

	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)
	svc.RegisterAnalyzer(a)

	ctx := context.Background()
	cfg, err := svc.GenerateGolangCIConfig(ctx, appanalysis.GenerateConfigCommand{
		Strict: false,
	})
	if err != nil {
		t.Fatalf("GenerateGolangCIConfig() error: %v", err)
	}
	if cfg == "" {
		t.Fatal("GenerateGolangCIConfig() returned empty string")
	}
	if !strings.Contains(cfg, "linters:") {
		t.Errorf("config YAML missing 'linters:' section; got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "golangci-lint") {
		t.Errorf("config YAML does not mention registered analyzer 'golangci-lint'; got:\n%s", cfg)
	}
}

func TestAnalysisService_SuggestFix_NoAutoFix(t *testing.T) {
	// An analyzer that does not support auto-fix should still return a manual suggestion.
	a := mocks.NewMockAnalyzer("staticcheck").WithAutoFix(false)

	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)
	svc.RegisterAnalyzer(a)

	ctx := context.Background()
	fix, err := svc.SuggestFix(ctx, appanalysis.SuggestFixCommand{
		Analyzer: "staticcheck",
		RuleID:   "SA1006",
		FilePath: "/some/file.go",
	})
	if err != nil {
		t.Fatalf("SuggestFix() error: %v", err)
	}
	if fix == "" {
		t.Error("SuggestFix() returned empty suggestion")
	}
}

func TestAnalysisService_SuggestFix_WithAutoFix(t *testing.T) {
	a := mocks.NewMockAnalyzer("golangci-lint").WithAutoFix(true)

	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)
	svc.RegisterAnalyzer(a)

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
		t.Error("SuggestFix() returned empty suggestion even with auto-fix enabled")
	}
	if !strings.Contains(fix, "golangci-lint") {
		t.Errorf("SuggestFix() with auto-fix should mention golangci-lint; got: %s", fix)
	}
}
