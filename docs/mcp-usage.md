# MCP Tool Usage Guide

## analyze_repository

Analyze an entire Go module for code quality, security, and correctness issues.

**Parameters:**
- `path` (required): Absolute path to the Go module root (must contain `go.mod`)
- `analyzers`: List of analyzers to run (default: all). Options: `golangci-lint`, `staticcheck`, `gosec`
- `format`: Output format — `json` (default), `markdown`, `sarif`
- `timeout_seconds`: Analysis timeout (default: 300)
- `config`: Path to `.golangci.yml` config file

**Example prompt:**
```
Analyze the Go repository at /home/user/myproject for all issues. 
Use the analyze_repository tool with format=markdown.
```

## analyze_file

Analyze a single Go source file. Faster and more targeted than full repository analysis.

**Parameters:**
- `file_path` (required): Absolute path to the `.go` file
- `analyzers`: Analyzers to run
- `format`: Output format

**Example prompt:**
```
Check /home/user/myproject/internal/service.go for security issues.
Use gosec analyzer only.
```

## run_golangci_lint

Run golangci-lint directly with full control over which linters to enable.

**Parameters:**
- `path` (required): Absolute path to the Go module root
- `linters`: Specific linters to enable (e.g. `govet`, `errcheck`, `gosec`)
- `config`: Path to `.golangci.yml`
- `timeout_seconds`: Timeout

**Example prompt:**
```
Run golangci-lint on /home/user/myproject with only errcheck and bodyclose linters enabled.
```

## list_analyzers

List all available analyzers with their descriptions and supported rules.

**No parameters required.**

## explain_finding

Get a detailed explanation of a static analysis finding.

**Parameters:**
- `rule_id` (required): The rule ID (e.g. `SA1006`, `G104`, `errcheck`)
- `analyzer`: The analyzer that produced the finding
- `message`: The finding message (for context)
- `code`: The offending code snippet

**Example prompt:**
```
Explain what staticcheck rule SA1006 means and why it matters.
```

## suggest_fix

Get a fix suggestion for a finding — either an auto-fix command or manual steps.

**Parameters:**
- `rule_id` (required): The rule ID to fix
- `analyzer` (required): The analyzer that produced the finding
- `code`: The offending code snippet
- `file_path`: File containing the finding
- `line`: Line number

**Example prompt:**
```
How do I fix the errcheck finding in /home/user/myproject/main.go at line 42?
```

## generate_golangci_config

Generate a ready-to-use `.golangci.yml` configuration file.

**Parameters:**
- `analyzers`: Analyzers/linters to include (default: all)
- `strict`: Enable stricter settings with longer timeout

**Example prompt:**
```
Generate a strict golangci-lint configuration for a production Go service 
using all available analyzers.
```
