# mcp-golangci-lint

A production-grade **Go Static Analysis MCP Server** that exposes `golangci-lint`, `staticcheck`, and `gosec`
— plus an AI-native intelligence layer — to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io).

## Features

- **25 MCP Tools**: 7 core static-analysis tools + 18 AI-native intelligence tools
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

### Core Static Analysis (7 tools)

| Tool | Description |
|------|-------------|
| `analyze_repository` | Run all/selected analyzers against a Go module |
| `analyze_file` | Analyze a single `.go` file |
| `run_golangci_lint` | Direct golangci-lint with linter selection |
| `list_analyzers` | List analyzers and their rules |
| `explain_finding` | Detailed explanation of any rule/finding |
| `suggest_fix` | Auto-fix command or manual remediation steps |
| `generate_golangci_config` | Generate a ready-to-use `.golangci.yml` |

### AI-Native Intelligence (18 tools)

| Tool | Description |
|------|-------------|
| `review_repository` | Full repo review: ranked issues, priority fixes, health score |
| `analyze_git_diff` | Lint-aware diff analysis — only findings in changed lines |
| `review_pull_request` | PR-scoped review with risk assessment |
| `generate_fix_patches` | Generate unified diff patches for auto-fixable findings |
| `scan_dependency_health` | Outdated, deprecated, and CVE-risk dependencies |
| `detect_architectural_smells` | Circular imports, god files, god packages, coupling violations |
| `generate_complexity_report` | Cyclomatic complexity per function/file, threshold violations |
| `find_dead_code` | Unused exports, unreachable functions, stale test helpers |
| `detect_performance_issues` | Alloc hot spots, inefficient loops, string builder opportunities |
| `detect_concurrency_issues` | Race-prone patterns: shared state, unprotected map writes, WaitGroup misuse |
| `detect_api_breaking_changes` | Removed/changed exported signatures vs a base ref |
| `generate_security_audit` | Cross-cutting security analysis beyond gosec rule flags |
| `get_repository_health_score` | 0–100 composite score across lint, complexity, coverage, deps |
| `get_repository_fingerprint` | Tech-stack fingerprint: language mix, frameworks, build tooling |
| `generate_knowledge_graph` | Package dependency graph as nodes/edges JSON |
| `generate_call_graph` | Function-level call graph for a target package |
| `analyze_impact` | What would break if this file/function changes? |
| `ask_repository` | Natural-language Q&A about codebase structure and quality |

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
mage test          # run tests with race detector
mage lint          # run golangci-lint
mage build         # build binary with version injection
mage race          # run tests with race detector
mage coverage      # generate coverage report
mage bench         # run benchmarks
```

## Architecture

Built with **Hexagonal Architecture** (Ports and Adapters):

```
Domain (zero deps) → Ports (interfaces) → Application (use cases) → Adapters (implementations)
```

- `internal/domain/analysis/` — pure Go domain types (findings, severity, results, extended types)
- `internal/ports/outbound/` — Analyzer, Cache, FileSystem, Reporter interfaces
- `internal/application/analysis/` — core use case orchestration (Service)
- `internal/application/intelligence/` — AI-native intelligence service (18 advanced tools)
- `internal/adapters/` — golangci-lint, staticcheck, gosec, memory cache, local fs, JSON/MD/SARIF reporters
- `internal/adapters/mcp/` — MCP server, core tool handlers, intelligence tool handlers
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
