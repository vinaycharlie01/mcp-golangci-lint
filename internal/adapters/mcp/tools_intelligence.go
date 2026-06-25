package mcp

import "github.com/mark3labs/mcp-go/mcp"

func toolReviewRepository() mcp.Tool {
	return mcp.NewTool("review_repository",
		mcp.WithDescription(
			"Run all analyzers on a repository and produce an AI-oriented code review: "+
				"findings grouped by severity, recurring patterns (rules appearing 3+ times), "+
				"technical debt estimate, and prioritized fix list.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolAnalyzeGitDiff() mcp.Tool {
	return mcp.NewTool("analyze_git_diff",
		mcp.WithDescription(
			"Run analysis on changed Go files between two git refs. "+
				"Returns new issues introduced in the diff and total changed files.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Git repository root"),
		),
		mcp.WithString("base",
			mcp.Description("Base git ref to diff from (default: main)"),
		),
		mcp.WithString("head",
			mcp.Description("Head git ref to diff to (default: HEAD)"),
		),
	)
}

func toolReviewPullRequest() mcp.Tool {
	return mcp.NewTool("review_pull_request",
		mcp.WithDescription(
			"Perform a PR-focused code review: identifies blocking (critical/high) issues, "+
				"security issues, and warnings introduced by the PR. Returns a recommendation.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Git repository root"),
		),
		mcp.WithString("base_branch",
			mcp.Description("Base branch to compare against (default: main)"),
		),
		mcp.WithString("head_branch",
			mcp.Description("Head branch / ref to review (default: HEAD)"),
		),
	)
}

func toolGenerateFixPatches() mcp.Tool {
	return mcp.NewTool("generate_fix_patches",
		mcp.WithDescription(
			"Run golangci-lint --fix and capture the resulting unified diff patches. "+
				"Returns per-file patches with the rules that were auto-fixed.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
		mcp.WithString("config",
			mcp.Description("Path to golangci-lint config file (optional)"),
		),
	)
}

func toolScanDependencyHealth() mcp.Tool {
	return mcp.NewTool("scan_dependency_health",
		mcp.WithDescription(
			"Parse go.mod and run `go list -m -u -json all` to check for available updates "+
				"and dependency hygiene. Returns direct/indirect deps and available updates.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolDetectArchitecturalSmells() mcp.Tool {
	return mcp.NewTool("detect_architectural_smells",
		mcp.WithDescription(
			"Detect structural problems via AST analysis: god files (>500 lines), "+
				"large interfaces (>10 methods), large structs (>20 fields), "+
				"long functions (>100 lines), and deep nesting (>4 levels).",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolGenerateComplexityReport() mcp.Tool {
	return mcp.NewTool("generate_complexity_report",
		mcp.WithDescription(
			"Compute cyclomatic complexity for every function in the repository. "+
				"Returns top-N most complex functions and files, plus aggregate statistics.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
		mcp.WithNumber("top_n",
			mcp.Description("Number of top functions/files to return (default: 20)"),
		),
	)
}

func toolFindDeadCode() mcp.Tool {
	return mcp.NewTool("find_dead_code",
		mcp.WithDescription(
			"Scan for potentially unused exported symbols within the module using AST analysis. "+
				"Returns a list of symbols that appear to have no usages.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolDetectPerformanceIssues() mcp.Tool {
	return mcp.NewTool("detect_performance_issues",
		mcp.WithDescription(
			"AST-based detection of common Go performance anti-patterns: "+
				"fmt.Sprintf in loops, append without pre-allocation, string([]byte) conversions, "+
				"make without capacity hints, and defer in loops.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolDetectConcurrencyIssues() mcp.Tool {
	return mcp.NewTool("detect_concurrency_issues",
		mcp.WithDescription(
			"AST-based detection of concurrency problems: goroutine leak risks, "+
				"mutex Lock without deferred Unlock, time.Sleep in goroutines, "+
				"and defer inside loops.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolDetectAPIBreakingChanges() mcp.Tool {
	return mcp.NewTool("detect_api_breaking_changes",
		mcp.WithDescription(
			"Compare exported Go API between HEAD and a base git ref. "+
				"Reports removed exports, changed function signatures, and added exports. "+
				"Sets `breaking: true` when backwards-incompatible changes are detected.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Git repository root"),
		),
		mcp.WithString("base_ref",
			mcp.Description("Base git ref to compare against (default: main)"),
		),
	)
}

func toolGenerateSecurityAudit() mcp.Tool {
	return mcp.NewTool("generate_security_audit",
		mcp.WithDescription(
			"Run gosec and map findings to OWASP Top 10 (2021) categories with CWE IDs and "+
				"estimated CVSS scores. Returns a structured security audit with remediation guidance.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolGetRepositoryHealthScore() mcp.Tool {
	return mcp.NewTool("get_repository_health_score",
		mcp.WithDescription(
			"Compute a 0-100 repository health score across 6 dimensions: "+
				"security, maintainability, architecture, testing, performance, and complexity. "+
				"Returns weighted overall score with recommendations.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolGetRepositoryFingerprint() mcp.Tool {
	return mcp.NewTool("get_repository_fingerprint",
		mcp.WithDescription(
			"Detect the technology stack used by the project: web frameworks, ORMs, caches, "+
				"message queues, logging, observability, CI systems, containerization, and architecture pattern.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
	)
}

func toolGenerateKnowledgeGraph() mcp.Tool {
	return mcp.NewTool("generate_knowledge_graph",
		mcp.WithDescription(
			"Build a package dependency graph for the module using `go list -json ./...`. "+
				"Output can be a Mermaid diagram or a JSON adjacency list.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: mermaid (default) or json"),
		),
	)
}

func toolGenerateCallGraph() mcp.Tool {
	return mcp.NewTool("generate_call_graph",
		mcp.WithDescription(
			"Build a function call graph for the module using AST analysis. "+
				"Limited to the top 50 most-connected functions for readability. "+
				"Output can be a Mermaid diagram or JSON.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
		mcp.WithString("package_pattern",
			mcp.Description("Package pattern to analyse (default: ./...)"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: mermaid (default) or json"),
		),
	)
}

func toolAnalyzeImpact() mcp.Tool {
	return mcp.NewTool("analyze_impact",
		mcp.WithDescription(
			"Find all usages of a function or type symbol across the codebase. "+
				"Returns direct callers, affected packages, affected test files, and an impact score.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
		mcp.WithString("symbol",
			mcp.Required(),
			mcp.Description("Function or type name to analyse (e.g. NewService, Handler)"),
		),
		mcp.WithString("package_path",
			mcp.Description("Optional package import path to scope the search"),
		),
	)
}

func toolAskRepository() mcp.Tool {
	return mcp.NewTool("ask_repository",
		mcp.WithDescription(
			"Answer natural language questions about the codebase using AST analysis and pattern matching. "+
				"Supports questions like: 'Show all HTTP routes', 'Where is X initialized?', "+
				"'What are all database calls?', 'Show all interfaces', 'How does auth work?'",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
		mcp.WithString("question",
			mcp.Required(),
			mcp.Description("Natural language question about the codebase"),
		),
	)
}
