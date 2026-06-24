// Package server provides the HTTP server for health and metrics endpoints.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/infrastructure/config"
	pkgversion "github.com/vinaycharlie01/mcp-golangci-lint/pkg/version"
)

// HTTPServer serves health, readiness, and metrics endpoints.
type HTTPServer struct {
	srv     *http.Server
	cfg     *config.ServerConfig
}

// NewHTTPServer creates an HTTPServer with health and metrics routes.
func NewHTTPServer(cfg *config.ServerConfig, metricsHandler http.Handler) *HTTPServer {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	r.Get("/healthz", handleHealth)
	r.Get("/readyz", handleReady)
	r.Get("/version", handleVersion)
	r.Handle("/metrics", metricsHandler)

	return &HTTPServer{
		cfg: cfg,
		srv: &http.Server{
			Addr:         cfg.Addr,
			Handler:      r,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
}

// Start listens and serves until ctx is cancelled.
func (s *HTTPServer) Start(ctx context.Context) error {
	slog.Info("starting HTTP server", slog.String("addr", s.cfg.Addr))
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		// ctx is already cancelled; must use a fresh context for graceful drain.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutdownCtx) //nolint:contextcheck // intentional: ctx is already done
	case err := <-errCh:
		return err
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

func handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"}) //nolint:errcheck
}

func handleVersion(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"version":    pkgversion.Version,
		"commit":     pkgversion.Commit,
		"build_date": pkgversion.BuildDate,
	})
}
