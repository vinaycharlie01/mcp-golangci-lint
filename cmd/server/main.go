// Command server is the entry point for the Go Static Analysis MCP Server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/vinaycharlie01/mcp-golangci-lint/internal/bootstrap"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/infrastructure/config"
	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
	pkgversion "github.com/vinaycharlie01/mcp-golangci-lint/pkg/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		cfgFile   string
		transport string
		version   bool
	)

	flag.StringVar(&cfgFile, "config", "", "Path to config file (default: config.yaml)")
	flag.StringVar(&transport, "transport", "", "MCP transport: stdio or sse (overrides config)")
	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.Parse()

	if version {
		fmt.Println(pkgversion.String())
		return nil
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// CLI flag overrides config file
	if transport != "" {
		cfg.MCP.Transport = transport
	}

	// Initialise structured logger and set as default
	var logger *slog.Logger
	if cfg.Log.Format == "text" {
		logger = pkglogger.NewText(cfg.Log.SlogLevel())
	} else {
		logger = pkglogger.New(cfg.Log.SlogLevel())
	}
	slog.SetDefault(logger)

	slog.Info("starting go-static-analysis MCP server",
		slog.String("version", pkgversion.Version),
		slog.String("commit", pkgversion.Commit),
		slog.String("transport", cfg.MCP.Transport),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		return fmt.Errorf("building application: %w", err)
	}
	defer app.Shutdown(context.Background())

	// Always start the HTTP metrics/health server in the background
	go func() {
		if err := app.HTTPServer.Start(ctx); err != nil {
			slog.Warn("HTTP server stopped", slog.String("error", err.Error()))
		}
	}()

	// Start MCP transport (blocking)
	switch cfg.MCP.Transport {
	case "sse":
		return app.MCPServer.ServeSSE(ctx)
	default:
		return app.MCPServer.ServeStdio(ctx)
	}
}
