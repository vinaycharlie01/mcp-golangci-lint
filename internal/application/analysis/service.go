package analysis

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/ports/outbound"
	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
)

const defaultTimeout = 5 * time.Minute

// Service orchestrates all static analysis operations.
// No logger is stored in the struct – all logging uses logger.FromContext(ctx, slog.Default()).
type Service struct {
	analyzers map[string]outbound.Analyzer
	cache     outbound.Cache
	fs        outbound.FileSystem
	reporters map[string]outbound.Reporter
}

// NewService creates a Service wired with the given dependencies.
func NewService(cache outbound.Cache, fs outbound.FileSystem, reporters ...outbound.Reporter) *Service {
	rm := make(map[string]outbound.Reporter, len(reporters))
	for _, r := range reporters {
		rm[r.Format()] = r
	}
	return &Service{
		analyzers: make(map[string]outbound.Analyzer),
		cache:     cache,
		fs:        fs,
		reporters: rm,
	}
}

// RegisterAnalyzer adds an analyzer to the service registry.
func (s *Service) RegisterAnalyzer(a outbound.Analyzer) {
	s.analyzers[a.Name()] = a
}

// ListAnalyzers returns all registered analyzers.
func (s *Service) ListAnalyzers() []outbound.Analyzer {
	out := make([]outbound.Analyzer, 0, len(s.analyzers))
	for _, a := range s.analyzers {
		out = append(out, a)
	}
	return out
}

// GetAnalyzer retrieves a named analyzer.
func (s *Service) GetAnalyzer(name string) (outbound.Analyzer, bool) {
	a, ok := s.analyzers[name]
	return a, ok
}

// AnalyzeRepository runs all selected analyzers against a Go repository.
func (s *Service) AnalyzeRepository(ctx context.Context, cmd AnalyzeRepositoryCommand) (*domainanalysis.AggregatedResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())

	if cmd.Timeout == 0 {
		cmd.Timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, cmd.Timeout)
	defer cancel()

	if err := s.fs.ValidatePath(ctx, cmd.Path); err != nil {
		return nil, fmt.Errorf("invalid path %q: %w", cmd.Path, err)
	}

	target := domainanalysis.Target{Type: domainanalysis.TargetTypeRepository, Path: cmd.Path}
	opts := domainanalysis.Options{
		Analyzers: cmd.Analyzers,
		Timeout:   cmd.Timeout,
		Format:    cmd.Format,
		Config:    cmd.Config,
	}

	cacheKey := buildCacheKey(target, opts)
	if cached, ok := s.cache.Get(ctx, cacheKey); ok {
		log.InfoContext(ctx, "returning cached result", slog.String("key", cacheKey))
		return cached, nil
	}

	start := time.Now()
	id := uuid.New().String()
	log.InfoContext(ctx, "starting repository analysis",
		slog.String("id", id),
		slog.String("path", cmd.Path),
		slog.Any("analyzers", cmd.Analyzers),
	)

	analyzers := s.selectAnalyzers(cmd.Analyzers)
	if len(analyzers) == 0 {
		return nil, fmt.Errorf("no analyzers available")
	}

	results := s.runParallel(ctx, analyzers, outbound.AnalysisRequest{Target: target, Options: opts})

	agg := &domainanalysis.AggregatedResult{
		ID:        id,
		Target:    target,
		Results:   results,
		Summary:   domainanalysis.BuildSummary(results),
		StartedAt: start,
		EndedAt:   time.Now(),
		Duration:  time.Since(start),
	}

	_ = s.cache.Set(ctx, cacheKey, agg, 10*time.Minute)

	log.InfoContext(ctx, "repository analysis complete",
		slog.String("id", id),
		slog.Duration("duration", agg.Duration),
		slog.Int("findings", agg.Summary.Total),
	)
	return agg, nil
}

// AnalyzeFile runs analyzers against a single Go source file.
func (s *Service) AnalyzeFile(ctx context.Context, cmd AnalyzeFileCommand) (*domainanalysis.AggregatedResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())

	if err := s.fs.ValidatePath(ctx, cmd.FilePath); err != nil {
		return nil, fmt.Errorf("invalid file path %q: %w", cmd.FilePath, err)
	}
	exists, err := s.fs.FileExists(ctx, cmd.FilePath)
	if err != nil {
		return nil, fmt.Errorf("checking file %q: %w", cmd.FilePath, err)
	}
	if !exists {
		return nil, fmt.Errorf("file not found: %s", cmd.FilePath)
	}

	target := domainanalysis.Target{Type: domainanalysis.TargetTypeFile, Path: cmd.FilePath}
	opts := domainanalysis.Options{Analyzers: cmd.Analyzers, Format: cmd.Format}

	start := time.Now()
	id := uuid.New().String()
	log.InfoContext(ctx, "starting file analysis",
		slog.String("id", id),
		slog.String("file", cmd.FilePath),
	)

	analyzers := s.selectAnalyzers(cmd.Analyzers)
	if len(analyzers) == 0 {
		return nil, fmt.Errorf("no analyzers available")
	}

	results := s.runParallel(ctx, analyzers, outbound.AnalysisRequest{Target: target, Options: opts})

	agg := &domainanalysis.AggregatedResult{
		ID:        id,
		Target:    target,
		Results:   results,
		Summary:   domainanalysis.BuildSummary(results),
		StartedAt: start,
		EndedAt:   time.Now(),
		Duration:  time.Since(start),
	}

	log.InfoContext(ctx, "file analysis complete",
		slog.String("id", id),
		slog.Int("findings", agg.Summary.Total),
	)
	return agg, nil
}

// ExplainFinding provides a detailed explanation for a rule finding.
func (s *Service) ExplainFinding(ctx context.Context, cmd ExplainFindingCommand) (string, error) {
	a, ok := s.analyzers[cmd.Analyzer]
	if !ok {
		return "", fmt.Errorf("unknown analyzer %q", cmd.Analyzer)
	}
	return a.ExplainFinding(ctx, domainanalysis.Finding{
		RuleID:  cmd.RuleID,
		Message: cmd.Message,
	})
}

// SuggestFix returns a fix suggestion for a finding.
func (s *Service) SuggestFix(_ context.Context, cmd SuggestFixCommand) (string, error) {
	a, ok := s.analyzers[cmd.Analyzer]
	if !ok {
		return "", fmt.Errorf("unknown analyzer %q", cmd.Analyzer)
	}
	if !a.SupportsAutoFix() {
		return fmt.Sprintf(
			"Analyzer %q does not support auto-fix for rule %q.\n\nManual fix guidance:\n%s",
			cmd.Analyzer, cmd.RuleID, fixGuidance(cmd.RuleID),
		), nil
	}
	return fmt.Sprintf(
		"Auto-fix available for %s/%s. Run:\n  golangci-lint run --fix --enable=%s %s",
		cmd.Analyzer, cmd.RuleID, cmd.Analyzer, cmd.FilePath,
	), nil
}

// GenerateGolangCIConfig generates a ready-to-use golangci-lint configuration.
func (s *Service) GenerateGolangCIConfig(_ context.Context, cmd GenerateConfigCommand) (string, error) {
	linters := cmd.Analyzers
	if len(linters) == 0 {
		for name := range s.analyzers {
			linters = append(linters, name)
		}
	}

	timeout := "5m"
	if cmd.Strict {
		timeout = "10m"
	}

	return fmt.Sprintf(`# Generated golangci-lint configuration
# https://golangci-lint.run/usage/configuration/
run:
  timeout: %s
  issues-exit-code: 1
  tests: true
  go: "1.24"

linters:
  disable-all: true
  enable:
    - %s

linters-settings:
  govet:
    enable-all: true
  errcheck:
    check-type-assertions: true
    check-blank: true
  gosec:
    severity: medium
    confidence: medium
  revive:
    severity: warning
  exhaustive:
    default-signifies-exhaustive: false

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
`, timeout, strings.Join(linters, "\n    - ")), nil
}

// Render formats an AggregatedResult using the named reporter.
func (s *Service) Render(ctx context.Context, result *domainanalysis.AggregatedResult, format string) (string, error) {
	r, ok := s.reporters[format]
	if !ok {
		r, ok = s.reporters["json"]
		if !ok {
			return "", fmt.Errorf("no reporter available for format %q", format)
		}
	}
	data, err := r.Render(ctx, result)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *Service) selectAnalyzers(names []string) []outbound.Analyzer {
	if len(names) == 0 {
		out := make([]outbound.Analyzer, 0, len(s.analyzers))
		for _, a := range s.analyzers {
			out = append(out, a)
		}
		return out
	}
	out := make([]outbound.Analyzer, 0, len(names))
	for _, name := range names {
		if a, ok := s.analyzers[name]; ok {
			out = append(out, a)
		}
	}
	return out
}

func (s *Service) runParallel(ctx context.Context, analyzers []outbound.Analyzer, req outbound.AnalysisRequest) []domainanalysis.Result {
	log := pkglogger.FromContext(ctx, slog.Default())

	type item struct{ result *domainanalysis.Result }
	ch := make(chan item, len(analyzers))

	var wg sync.WaitGroup
	for _, a := range analyzers {
		wg.Add(1)
		go func(az outbound.Analyzer) {
			defer wg.Done()
			r, err := az.Run(ctx, req)
			if err != nil {
				log.WarnContext(ctx, "analyzer failed",
					slog.String("analyzer", az.Name()),
					slog.String("error", err.Error()),
				)
				ch <- item{}
				return
			}
			ch <- item{result: r}
		}(a)
	}

	wg.Wait()
	close(ch)

	var results []domainanalysis.Result
	for it := range ch {
		if it.result != nil {
			results = append(results, *it.result)
		}
	}
	return results
}

func buildCacheKey(target domainanalysis.Target, opts domainanalysis.Options) string {
	return fmt.Sprintf("%s:%s:%s", target.Type, target.Path, strings.Join(opts.Analyzers, ","))
}

func fixGuidance(ruleID string) string {
	guidance := map[string]string{
		"errcheck":      "Always check returned errors. Use `if err != nil { return err }` pattern.",
		"gosec/G104":    "Handle errors explicitly instead of using blank identifier `_`.",
		"govet":         "Fix the type mismatch or formatting verb issue flagged by go vet.",
		"ineffassign":   "Remove the assignment that is immediately overwritten or never used.",
		"unused":        "Remove the exported identifier or add `//nolint:unused` with justification.",
		"bodyclose":     "Always close HTTP response bodies with `defer resp.Body.Close()`.",
		"noctx":         "Use `http.NewRequestWithContext` instead of `http.NewRequest`.",
		"contextcheck":  "Pass the context through to all functions that accept one.",
		"rowserrcheck":  "Always check `rows.Err()` after iterating over database rows.",
		"sqlclosecheck": "Always close `sql.Rows` and `sql.Stmt` with defer.",
	}
	if g, ok := guidance[ruleID]; ok {
		return g
	}
	return "Refer to the analyzer documentation for fix guidance."
}
