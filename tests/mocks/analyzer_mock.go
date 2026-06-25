// Package mocks provides test doubles for outbound ports.
package mocks

import (
	"context"
	"sync"
	"time"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/ports/outbound"
)

// MockAnalyzer is a controllable test double for outbound.Analyzer.
type MockAnalyzer struct {
	mu          sync.Mutex
	name        string
	description string
	autoFix     bool
	rules       []outbound.Rule
	runResult   *domainanalysis.Result
	runErr      error
	explainResp string
	explainErr  error
	calls       []outbound.AnalysisRequest
}

// NewMockAnalyzer creates a MockAnalyzer with the given name.
func NewMockAnalyzer(name string) *MockAnalyzer {
	return &MockAnalyzer{
		name:        name,
		description: "mock analyzer: " + name,
	}
}

func (m *MockAnalyzer) WithRunResult(r *domainanalysis.Result) *MockAnalyzer {
	m.mu.Lock()
	m.runResult = r
	m.mu.Unlock()
	return m
}

func (m *MockAnalyzer) WithRunError(err error) *MockAnalyzer {
	m.mu.Lock()
	m.runErr = err
	m.mu.Unlock()
	return m
}

func (m *MockAnalyzer) WithRules(rules []outbound.Rule) *MockAnalyzer {
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
	return m
}

func (m *MockAnalyzer) WithAutoFix(v bool) *MockAnalyzer {
	m.mu.Lock()
	m.autoFix = v
	m.mu.Unlock()
	return m
}

func (m *MockAnalyzer) WithExplainResponse(resp string) *MockAnalyzer {
	m.mu.Lock()
	m.explainResp = resp
	m.mu.Unlock()
	return m
}

// Name implements outbound.Analyzer.
func (m *MockAnalyzer) Name() string { return m.name }

// Description implements outbound.Analyzer.
func (m *MockAnalyzer) Description() string { return m.description }

// Run implements outbound.Analyzer.
func (m *MockAnalyzer) Run(_ context.Context, req outbound.AnalysisRequest) (*domainanalysis.Result, error) {
	m.mu.Lock()
	m.calls = append(m.calls, req)
	r, err := m.runResult, m.runErr
	m.mu.Unlock()
	return r, err
}

// SupportsAutoFix implements outbound.Analyzer.
func (m *MockAnalyzer) SupportsAutoFix() bool { return m.autoFix }

// ExplainFinding implements outbound.Analyzer.
func (m *MockAnalyzer) ExplainFinding(_ context.Context, _ domainanalysis.Finding) (string, error) {
	m.mu.Lock()
	r, err := m.explainResp, m.explainErr
	m.mu.Unlock()
	return r, err
}

// SupportedRules implements outbound.Analyzer.
func (m *MockAnalyzer) SupportedRules() []outbound.Rule {
	m.mu.Lock()
	r := m.rules
	m.mu.Unlock()
	return r
}

// Calls returns recorded Run invocations (thread-safe).
func (m *MockAnalyzer) Calls() []outbound.AnalysisRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]outbound.AnalysisRequest, len(m.calls))
	copy(out, m.calls)
	return out
}

// MockCache is a test double for outbound.Cache.
type MockCache struct {
	mu      sync.RWMutex
	entries map[string]*domainanalysis.AggregatedResult
	hits    int
	misses  int
}

func NewMockCache() *MockCache {
	return &MockCache{entries: make(map[string]*domainanalysis.AggregatedResult)}
}

func (c *MockCache) Get(_ context.Context, key string) (*domainanalysis.AggregatedResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.entries[key]
	if ok {
		c.hits++
	} else {
		c.misses++
	}
	return v, ok
}

func (c *MockCache) Set(_ context.Context, key string, val *domainanalysis.AggregatedResult, _ time.Duration) error {
	c.mu.Lock()
	c.entries[key] = val
	c.mu.Unlock()
	return nil
}

func (c *MockCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
	return nil
}

func (c *MockCache) Clear(_ context.Context) error {
	c.mu.Lock()
	c.entries = make(map[string]*domainanalysis.AggregatedResult)
	c.mu.Unlock()
	return nil
}

func (c *MockCache) Hits() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits
}

// MockFileSystem is a test double for outbound.FileSystem.
type MockFileSystem struct {
	validateErr   error
	isGoRepo      bool
	existingFiles map[string]bool
	fileContents  map[string][]byte
}

func NewMockFileSystem() *MockFileSystem {
	return &MockFileSystem{
		isGoRepo:      true,
		existingFiles: make(map[string]bool),
		fileContents:  make(map[string][]byte),
	}
}

func (f *MockFileSystem) WithValidateError(err error) *MockFileSystem {
	f.validateErr = err
	return f
}

func (f *MockFileSystem) WithFile(path string, content []byte) *MockFileSystem {
	f.existingFiles[path] = true
	f.fileContents[path] = content
	return f
}

func (f *MockFileSystem) ValidatePath(_ context.Context, _ string) error { return f.validateErr }

func (f *MockFileSystem) IsGoRepository(_ context.Context, _ string) (bool, error) {
	return f.isGoRepo, nil
}

func (f *MockFileSystem) CreateTempWorkspace(_ context.Context) (string, func(), error) {
	return "/tmp/mock-workspace", func() {}, nil
}

func (f *MockFileSystem) ReadFile(_ context.Context, path string) ([]byte, error) {
	if c, ok := f.fileContents[path]; ok {
		return c, nil
	}
	return nil, nil
}

func (f *MockFileSystem) FileExists(_ context.Context, path string) (bool, error) {
	return f.existingFiles[path], nil
}

func (f *MockFileSystem) FindGoFiles(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
