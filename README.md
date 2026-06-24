# mcp-golangci-lint

A production-grade **Go Static Analysis MCP Server** that exposes `golangci-lint`, `staticcheck`, and `gosec` to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io).

## Features

- **7 MCP Tools**: analyze repository, analyze file, run golangci-lint, list analyzers, explain finding, suggest fix, generate config
- **3 Analyzers**: golangci-lint (100+ linters), staticcheck (SA/S/QF rules), gosec (security rules)
- **3 Output Formats**: JSON, Markdown, SARIF 2.1.0 (GitHub Code Scanning compatible)
- **Hexagonal Architecture**: clean separation of domain, application, and infrastructure layers
- **Pluggable Analyzers**: add new analyzers by implementing one interface — no existing code changes
- **Observability**: Prometheus metrics, OpenTelemetry tracing, structured slog logging
- **Secure by Design**: path validation (no traversal), args always passed as separate parameters (no shell injection)
- **Two Transports**: stdio (Claude Desktop, Cursor) and SSE (remote/browser clients)

## Quick Start

### Using Docker (recommended)

```bash
# Claude Desktop / Cursor — stdio transport
docker run --rm -i \
  -v /path/to/your/go/project:/workspace:ro \
  ghcr.io/vinaycharlie01/mcp-golangci-lint:latest \
  --transport stdio

# SSE transport (remote access)
docker compose up
# Server at http://localhost:8081/sse
```

### From Source

```bash
git clone https://github.com/vinaycharlie01/mcp-golangci-lint
cd mcp-golangci-lint
make build
./bin/mcp-golangci-lint --transport stdio
```

**Prerequisites**: Go 1.25+, `golangci-lint`, `staticcheck`, `gosec` in `$PATH`.

## MCP Tools

| Tool | Description |
|------|-------------|
| `analyze_repository` | Run all/selected analyzers against a Go module |
| `analyze_file` | Analyze a single `.go` file |
| `run_golangci_lint` | Direct golangci-lint with linter selection |
| `list_analyzers` | List analyzers and their rules |
| `explain_finding` | Detailed explanation of any rule/finding |
| `suggest_fix` | Auto-fix command or manual remediation steps |
| `generate_golangci_config` | Generate a ready-to-use `.golangci.yml` |

## Client Configuration

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "go-static-analysis": {
      "command": "mcp-golangci-lint",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### Cursor / VS Code

`.cursor/mcp.json` or `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "go-static-analysis": {
      "command": "mcp-golangci-lint",
      "args": ["--transport", "stdio"]
    }
  }
}
```

See [docs/mcp-clients.md](docs/mcp-clients.md) for full configuration options.

## Development

```bash
make test          # run tests with race detector
make lint          # run golangci-lint
make build         # build binary with version injection
make run-stdio     # run in stdio mode
make run-sse       # run SSE server on :8081
make docker-build  # build Docker image
```

## Architecture

Built with **Hexagonal Architecture** (Ports and Adapters):

```
Domain (zero deps) → Ports (interfaces) → Application (use cases) → Adapters (implementations)
```

- `internal/domain/analysis/` — pure Go domain types
- `internal/ports/outbound/` — Analyzer, Cache, FileSystem, Reporter interfaces
- `internal/application/analysis/` — use case orchestration (Service)
- `internal/adapters/` — golangci-lint, staticcheck, gosec, memory cache, local fs, JSON/MD/SARIF reporters
- `internal/adapters/mcp/` — MCP server and tool handlers
- `internal/infrastructure/` — config (viper), HTTP health/metrics server
- `internal/bootstrap/` — dependency injection wiring
- `pkg/` — logger (slog), executor (safe command runner), version

See [docs/architecture.md](docs/architecture.md) for the full diagram.

## Adding a New Analyzer

```go
// 1. Implement the Analyzer interface (internal/ports/outbound/analyzer.go)
type MyAnalyzer struct{}

func (a *MyAnalyzer) Name() string        { return "myanalyzer" }
func (a *MyAnalyzer) Description() string { return "My custom analyzer" }
func (a *MyAnalyzer) Run(ctx context.Context, req outbound.AnalysisRequest) (*analysis.Result, error) { ... }
func (a *MyAnalyzer) SupportsAutoFix() bool { return false }
func (a *MyAnalyzer) ExplainFinding(ctx context.Context, f analysis.Finding) (string, error) { ... }
func (a *MyAnalyzer) SupportedRules() []outbound.Rule { ... }

// 2. Register in internal/bootstrap/bootstrap.go
svc.RegisterAnalyzer(myanalyzer.New())
```

No other files need to change.

## Observability

- **Metrics**: Prometheus at `http://localhost:8080/metrics`
- **Health**: `GET /healthz`, `GET /readyz`, `GET /version`
- **Tracing**: OpenTelemetry OTLP/HTTP (disabled by default, set `MCP_OBSERVABILITY_TRACING_ENABLED=true`)

Run the full observability stack:

```bash
docker compose --profile observability up
# Prometheus: http://localhost:9090
# Grafana:    http://localhost:3000 (admin/admin)
# Jaeger:     http://localhost:16686
```

## License

MIT