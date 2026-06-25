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
│  │    server.go              — MCP server, transport        │   │
│  │    handler.go             — Core tool handlers (7 tools) │   │
│  │    handler_intelligence.go — Intelligence handlers       │   │
│  │    tools.go               — Core tool schemas           │   │
│  │    tools_intelligence.go  — Intelligence tool schemas   │   │
│  └─────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │ calls
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  internal/application/analysis/                           │  │
│  │    service.go   — Use-case orchestration                  │  │
│  │    commands.go  — Command structs (one per use case)      │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  internal/application/intelligence/                       │  │
│  │    service.go   — 18 AI-native intelligence tools         │  │
│  │                   (AST, git, complexity, security, ...)   │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────┬────────────────────────────────────────────┬────────────┘
       │ uses Domain types                          │ calls via Ports
       ▼                                            ▼
┌──────────────────────┐         ┌─────────────────────────────────┐
│   Domain Layer       │         │   Ports (interfaces)             │
│  internal/domain/    │         │  internal/ports/outbound/        │
│    finding.go        │         │    analyzer.go  — Analyzer port  │
│    result.go         │         │    cache.go     — Cache port     │
│    target.go         │         │    filesystem.go — FS port       │
│    extended.go       │         │    reporter.go  — Reporter port  │
└──────────────────────┘         └───────────────┬─────────────────┘
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

### Core Static Analysis (7 tools)

| Tool | Description |
|------|-------------|
| `analyze_repository` | Run all/selected analyzers against a Go module |
| `analyze_file` | Analyze a single `.go` file |
| `run_golangci_lint` | Direct golangci-lint invocation with linter selection |
| `list_analyzers` | List registered analyzers and their rules |
| `explain_finding` | Detailed explanation of a rule/finding |
| `suggest_fix` | Auto-fix command or manual remediation steps |
| `generate_golangci_config` | Generate a `.golangci.yml` configuration |

### AI-Native Intelligence (18 tools)

| Tool | Description |
|------|-------------|
| `review_repository` | Full repo review: ranked issues, priority fixes, health score |
| `analyze_git_diff` | Lint-aware diff analysis for changed lines only |
| `review_pull_request` | PR-scoped review with risk assessment |
| `generate_fix_patches` | Unified diff patches for auto-fixable findings |
| `scan_dependency_health` | Outdated, deprecated, and CVE-risk dependencies |
| `detect_architectural_smells` | Circular imports, god files, coupling violations |
| `generate_complexity_report` | Cyclomatic complexity per function/file |
| `find_dead_code` | Unused exports, unreachable functions |
| `detect_performance_issues` | Alloc hot spots, inefficient loops |
| `detect_concurrency_issues` | Race-prone patterns, unprotected shared state |
| `detect_api_breaking_changes` | Removed/changed exported signatures vs base ref |
| `generate_security_audit` | Cross-cutting security analysis |
| `get_repository_health_score` | 0–100 composite health score |
| `get_repository_fingerprint` | Tech-stack fingerprint: frameworks, build tooling |
| `generate_knowledge_graph` | Package dependency graph as nodes/edges |
| `generate_call_graph` | Function-level call graph for a target package |
| `analyze_impact` | What breaks if this file/function changes? |
| `ask_repository` | Natural-language Q&A about codebase structure |

## Output Formats

- **JSON** — Structured findings, default format
- **Markdown** — Summary table + code-block findings, ideal for AI consumption  
- **SARIF 2.1.0** — GitHub Code Scanning compatible, industry standard
