# Architecture

## Overview

`mcp-golangci-lint` is a **Go Static Analysis MCP Server** built with **Hexagonal Architecture** (Ports and Adapters). AI agents connect via the [Model Context Protocol](https://modelcontextprotocol.io) and invoke static analysis tools on Go codebases.

```
┌─────────────────────────────────────────────────────────────────┐
│                      MCP Clients (AI Agents)                    │
│              Claude Desktop │ Cursor │ VS Code │ Custom         │
└───────────────────────────────┬─────────────────────────────────┘
                                │ MCP (stdio / SSE)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Adapters Layer (Driving)                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  internal/adapters/mcp/                                  │   │
│  │    server.go  — MCP server, transport selection          │   │
│  │    handler.go — Tool handlers (7 MCP tools)              │   │
│  └─────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │ calls
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  internal/application/analysis/                          │   │
│  │    service.go   — Use-case orchestration                 │   │
│  │    commands.go  — Command structs (one per use case)     │   │
│  └─────────────────────────────────────────────────────────┘   │
└──────┬────────────────────────────────────────────┬────────────┘
       │ uses Domain types                          │ calls via Ports
       ▼                                            ▼
┌──────────────────────┐         ┌─────────────────────────────────┐
│   Domain Layer       │         │   Ports (interfaces)             │
│  internal/domain/    │         │  internal/ports/outbound/        │
│    finding.go        │         │    analyzer.go  — Analyzer port  │
│    result.go         │         │    cache.go     — Cache port     │
│    target.go         │         │    filesystem.go — FS port       │
└──────────────────────┘         │    reporter.go  — Reporter port  │
                                 └───────────────┬─────────────────┘
                                                 │ implemented by
                                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Adapters Layer (Driven)                        │
│  ┌────────────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ analyzers/     │ │ cache/   │ │filesystem│ │ reporters/  │ │
│  │  golangci/     │ │ memory.go│ │ local.go │ │  json.go    │ │
│  │  staticcheck/  │ └──────────┘ └──────────┘ │  markdown.go│ │
│  │  gosec/        │                            │  sarif.go   │ │
│  └────────────────┘                            └─────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Logging Convention

**No logger is ever stored in a struct.** Every method retrieves a contextual logger at call time:

```go
func (s *Service) AnalyzeRepository(ctx context.Context, cmd AnalyzeRepositoryCommand) (*AggregatedResult, error) {
    log := pkglogger.FromContext(ctx, slog.Default())
    log.InfoContext(ctx, "starting repository analysis", ...)
}
```

This enables:
- Zero-dependency struct initialization
- Automatic enrichment with correlation IDs, request IDs, trace IDs from context
- `slog.SetDefault()` called once at bootstrap; all code benefits automatically

## Analyzer Plugin Pattern

Add a new analyzer without modifying any existing code:

```go
// 1. Implement the interface
type MyAnalyzer struct{}
func (a *MyAnalyzer) Name() string { return "myanalyzer" }
// ... implement all 6 interface methods

// 2. Register in bootstrap
svc.RegisterAnalyzer(myanalyzer.New())
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `analyze_repository` | Run all/selected analyzers against a Go module |
| `analyze_file` | Analyze a single `.go` file |
| `run_golangci_lint` | Direct golangci-lint invocation with linter selection |
| `list_analyzers` | List registered analyzers and their rules |
| `explain_finding` | Detailed explanation of a rule/finding |
| `suggest_fix` | Auto-fix command or manual remediation steps |
| `generate_golangci_config` | Generate a `.golangci.yml` configuration |

## Output Formats

- **JSON** — Structured findings, default format
- **Markdown** — Summary table + code-block findings, ideal for AI consumption  
- **SARIF 2.1.0** — GitHub Code Scanning compatible, industry standard
