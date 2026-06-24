// Package observability provides Prometheus metrics and OpenTelemetry tracing adapters.
package observability

import (
	"context"
	"net/http"
	"net/http/pprof"

	"github.com/go-chi/chi/v5"
	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/infrastructure/config"
)

// Metrics holds all instrumentation for the MCP server.
type Metrics struct {
	provider *sdkmetric.MeterProvider
	registry *promclient.Registry

	AnalysisTotal       metric.Int64Counter
	AnalysisFailures    metric.Int64Counter
	AnalysisDuration    metric.Float64Histogram
	FindingsTotal       metric.Int64Counter
	ActiveAnalyses      metric.Int64UpDownCounter
	CacheHits           metric.Int64Counter
	CacheMisses         metric.Int64Counter
}

// NewMetrics initialises the OTel metric provider with a Prometheus exporter.
func NewMetrics(cfg *config.ObservabilityConfig) (*Metrics, error) {
	registry := promclient.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, err
	}

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(provider)

	meter := provider.Meter(cfg.ServiceName)

	analysisTotal, _ := meter.Int64Counter("mcp_analysis_total",
		metric.WithDescription("Total analysis operations"))
	analysisFailures, _ := meter.Int64Counter("mcp_analysis_failures_total",
		metric.WithDescription("Total failed analysis operations"))
	analysisDuration, _ := meter.Float64Histogram("mcp_analysis_duration_seconds",
		metric.WithDescription("Analysis duration in seconds"))
	findingsTotal, _ := meter.Int64Counter("mcp_findings_total",
		metric.WithDescription("Total findings produced"))
	activeAnalyses, _ := meter.Int64UpDownCounter("mcp_active_analyses",
		metric.WithDescription("In-progress analysis operations"))
	cacheHits, _ := meter.Int64Counter("mcp_cache_hits_total",
		metric.WithDescription("Cache hit count"))
	cacheMisses, _ := meter.Int64Counter("mcp_cache_misses_total",
		metric.WithDescription("Cache miss count"))

	return &Metrics{
		provider:         provider,
		registry:         registry,
		AnalysisTotal:    analysisTotal,
		AnalysisFailures: analysisFailures,
		AnalysisDuration: analysisDuration,
		FindingsTotal:    findingsTotal,
		ActiveAnalyses:   activeAnalyses,
		CacheHits:        cacheHits,
		CacheMisses:      cacheMisses,
	}, nil
}

// Shutdown flushes and shuts down the metrics provider.
func (m *Metrics) Shutdown(ctx context.Context) error {
	return m.provider.Shutdown(ctx)
}

// Handler returns an http.Handler that serves Prometheus metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{EnableOpenMetrics: true})
}

// RegisterProfilingRoutes adds pprof endpoints to a chi router.
func RegisterProfilingRoutes(r chi.Router) {
	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
