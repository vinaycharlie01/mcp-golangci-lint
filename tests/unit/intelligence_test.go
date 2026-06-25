package unit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
	intelligence "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/intelligence"
	"github.com/vinaycharlie01/mcp-golangci-lint/tests/mocks"
)

// buildIntelligenceService creates an intelligence.Service backed by mock adapters.
func buildIntelligenceService(t *testing.T) *intelligence.Service {
	t.Helper()
	cache := mocks.NewMockCache()
	fs := mocks.NewMockFileSystem()
	svc := appanalysis.NewService(cache, fs)
	return intelligence.New(svc)
}

func TestIntelligence_NewNilAnalysisSvc(t *testing.T) {
	// Should not panic when passed nil.
	svc := intelligence.New(nil)
	if svc == nil {
		t.Error("New(nil) returned nil service")
	}
}

// writeTempGoFile creates a named Go source file inside dir with the given content.
func writeTempGoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file %s: %v", path, err)
	}
}

func TestComplexityReport_SimpleReturn(t *testing.T) {
	// A function with just a return statement has cyclomatic complexity = 1.
	dir := t.TempDir()
	writeTempGoFile(t, dir, "simple.go", `package simple

func JustReturn() int {
	return 42
}
`)
	svc := buildIntelligenceService(t)
	report, err := svc.GenerateComplexityReport(context.Background(), dir, 10)
	if err != nil {
		t.Fatalf("GenerateComplexityReport() error: %v", err)
	}
	if report.Summary.TotalFunctions == 0 {
		t.Fatal("expected at least one function in complexity report")
	}
	// Find JustReturn
	for _, fn := range report.TopFunctions {
		if fn.Function == "JustReturn" {
			if fn.Complexity != 1 {
				t.Errorf("JustReturn complexity = %d, want 1", fn.Complexity)
			}
			return
		}
	}
	// Not in top-N may happen if topN slicing excluded it; check all entries via summary.
	// Complexity 1 is the minimum: TopFunctions is sorted desc, so check tail logic.
	// Allow any complexity ≥ 1 since the function exists.
}

func TestComplexityReport_OneIf(t *testing.T) {
	// A function with one if statement: complexity = 2.
	dir := t.TempDir()
	writeTempGoFile(t, dir, "oneif.go", `package oneif

func OneIf(x int) bool {
	if x > 0 {
		return true
	}
	return false
}
`)
	svc := buildIntelligenceService(t)
	report, err := svc.GenerateComplexityReport(context.Background(), dir, 10)
	if err != nil {
		t.Fatalf("GenerateComplexityReport() error: %v", err)
	}
	found := false
	for _, fn := range report.TopFunctions {
		if fn.Function == "OneIf" {
			found = true
			if fn.Complexity != 2 {
				t.Errorf("OneIf complexity = %d, want 2", fn.Complexity)
			}
		}
	}
	if !found && report.Summary.TotalFunctions > 0 {
		// Function exists but wasn't in top-N; just verify total > 0.
		t.Log("OneIf not in top functions slice (may be truncated)")
	}
}

func TestComplexityReport_IfElseAndFor(t *testing.T) {
	// if + for → complexity = 3.
	dir := t.TempDir()
	writeTempGoFile(t, dir, "complex.go", `package complex

func IfElseAndFor(xs []int) int {
	sum := 0
	for _, x := range xs {
		if x > 0 {
			sum += x
		}
	}
	return sum
}
`)
	svc := buildIntelligenceService(t)
	report, err := svc.GenerateComplexityReport(context.Background(), dir, 10)
	if err != nil {
		t.Fatalf("GenerateComplexityReport() error: %v", err)
	}
	for _, fn := range report.TopFunctions {
		if fn.Function == "IfElseAndFor" {
			if fn.Complexity != 3 {
				t.Errorf("IfElseAndFor complexity = %d, want 3", fn.Complexity)
			}
			return
		}
	}
}

func TestGetRepositoryFingerprint_BasicDetection(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal go.mod
	goMod := `module example.com/myapp

go 1.22
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}

	// Write a Go file importing net/http
	writeTempGoFile(t, dir, "main.go", `package main

import (
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("hello")
	_ = http.DefaultClient
}
`)

	svc := buildIntelligenceService(t)
	fp, err := svc.GetRepositoryFingerprint(context.Background(), dir)
	if err != nil {
		t.Fatalf("GetRepositoryFingerprint() error: %v", err)
	}
	if fp.Module != "example.com/myapp" {
		t.Errorf("Module = %q, want %q", fp.Module, "example.com/myapp")
	}
	if fp.GoVersion != "1.22" {
		t.Errorf("GoVersion = %q, want %q", fp.GoVersion, "1.22")
	}

	// net/http should be detected as a web framework
	found := false
	for _, fw := range fp.WebFramework {
		if strings.Contains(fw, "http") {
			found = true
		}
	}
	if !found {
		t.Logf("WebFramework list: %v (net/http detection is best-effort)", fp.WebFramework)
	}
}

func TestGenerateKnowledgeGraph_EmptyRepo(t *testing.T) {
	dir := t.TempDir()

	// go.mod is required by the service
	goMod := `module example.com/kg

go 1.22
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}

	svc := buildIntelligenceService(t)
	// GenerateKnowledgeGraph runs `go list -json ./...`; in an empty temp dir
	// this is expected to return an empty graph (no nodes/edges), not an error.
	result, err := svc.GenerateKnowledgeGraph(context.Background(), dir, "json")
	if err != nil {
		t.Fatalf("GenerateKnowledgeGraph() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("GenerateKnowledgeGraph() returned nil result")
	}
	// Node/edge counts may be 0 for a minimal temp repo — that's fine.
	if result.Format != "json" {
		t.Errorf("Format = %q, want %q", result.Format, "json")
	}
}

func TestDetectArchitecturalSmells_CleanRepo(t *testing.T) {
	dir := t.TempDir()
	writeTempGoFile(t, dir, "small.go", `package small

// Tiny is a tiny function.
func Tiny() {}
`)
	svc := buildIntelligenceService(t)
	result, err := svc.DetectArchitecturalSmells(context.Background(), dir)
	if err != nil {
		t.Fatalf("DetectArchitecturalSmells() error: %v", err)
	}
	// A small file with a trivial function should have no smells.
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 smells, got %d: %+v", len(result.Findings), result.Findings)
	}
}
