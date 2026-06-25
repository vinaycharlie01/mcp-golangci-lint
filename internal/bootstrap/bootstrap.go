// Package bootstrap wires together all application components using dependency injection.
package bootstrap

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/analyzers/golangci"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/analyzers/gosec"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/analyzers/staticcheck"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/cache"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/filesystem"
	mcpadapter "github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/mcp"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/observability"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/adapters/reporters"
	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/infrastructure/config"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/infrastructure/server"
)

// App holds all initialised application components.
type App struct {
	Config     *config.Config
	MCPServer  *mcpadapter.Server
	HTTPServer *server.HTTPServer
	Metrics    *observability.Metrics
	Tracing    *observability.TracerProvider
}

// Build assembles all application components from configuration.
func Build(ctx context.Context, cfg *config.Config) (*App, error) {
	// Observability
	metrics, err := observability.NewMetrics(&cfg.Observability)
	if err != nil {
		return nil, fmt.Errorf("initialising metrics: %w", err)
	}

	tracer, err := observability.NewTracerProvider(ctx, &cfg.Observability)
	if err != nil {
		return nil, fmt.Errorf("initialising tracing: %w", err)
	}

	// Infrastructure adapters
	memCache := cache.NewMemoryCache(ctx)
	fs := filesystem.New()

	// Reporters
	jsonReporter := reporters.NewJSON()
	mdReporter := reporters.NewMarkdown()
	sarifReporter := reporters.NewSARIF()

	// Application service
	svc := appanalysis.NewService(memCache, fs, jsonReporter, mdReporter, sarifReporter)

	// Analyzer adapters
	svc.RegisterAnalyzer(golangci.New())
	svc.RegisterAnalyzer(staticcheck.New())
	svc.RegisterAnalyzer(gosec.New())

	slog.InfoContext(ctx, "registered analyzers",
		slog.Int("count", len(svc.ListAnalyzers())),
	)

	// MCP server
	mcpSrv := mcpadapter.NewServer(&cfg.MCP, svc)

	// HTTP server for health/metrics
	httpSrv := server.NewHTTPServer(&cfg.Server, metrics.Handler())

	return &App{
		Config:     cfg,
		MCPServer:  mcpSrv,
		HTTPServer: httpSrv,
		Metrics:    metrics,
		Tracing:    tracer,
	}, nil
}

// Shutdown gracefully stops all components.
func (a *App) Shutdown(ctx context.Context) {
	if err := a.Metrics.Shutdown(ctx); err != nil {
		slog.WarnContext(ctx, "metrics shutdown error", slog.String("error", err.Error()))
	}
	if err := a.Tracing.Shutdown(ctx); err != nil {
		slog.WarnContext(ctx, "tracing shutdown error", slog.String("error", err.Error()))
	}
}
