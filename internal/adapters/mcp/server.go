// Package mcp provides the MCP server adapter that exposes Go static analysis
// capabilities to AI agents via the Model Context Protocol.
package mcp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
	intelligence "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/intelligence"
	"github.com/vinaycharlie01/mcp-golangci-lint/internal/infrastructure/config"
)

// Server wraps the MCP server and registers all static analysis tools.
// No logger is stored in the struct.
type Server struct {
	mcp     *server.MCPServer
	handler *Handler
	cfg     *config.MCPConfig
}

// NewServer creates and configures the MCP server with all 25 tools registered.
func NewServer(cfg *config.MCPConfig, analysisSvc *appanalysis.Service, intelligenceSvc *intelligence.Service) *Server {
	s := server.NewMCPServer(
		cfg.Name,
		cfg.Version,
		server.WithToolCapabilities(true),
		server.WithRecovery(),
	)

	h := &Handler{analysisSvc: analysisSvc, intelligenceSvc: intelligenceSvc}
	registerTools(s, h)

	return &Server{mcp: s, handler: h, cfg: cfg}
}

// ServeStdio runs the MCP server over stdin/stdout (standard MCP transport).
// This is the transport used by Claude Desktop, Cursor, and VS Code.
func (s *Server) ServeStdio(_ context.Context) error {
	slog.Info("starting MCP server", slog.String("transport", "stdio"))
	return server.ServeStdio(s.mcp)
}

// ServeSSE runs the MCP server as an SSE HTTP endpoint.
func (s *Server) ServeSSE(_ context.Context) error {
	addr := s.cfg.SSEAddr
	if addr == "" {
		addr = "0.0.0.0:8081"
	}
	slog.Info("starting MCP server",
		slog.String("transport", "sse"),
		slog.String("addr", addr),
	)
	sseServer := server.NewSSEServer(s.mcp, server.WithBaseURL(fmt.Sprintf("http://%s", addr)))
	return sseServer.Start(addr)
}

// registerTools registers all 25 MCP tools onto the server.
func registerTools(s *server.MCPServer, h *Handler) {
	// Original 7 tools
	s.AddTool(toolAnalyzeRepository(), h.AnalyzeRepository)
	s.AddTool(toolAnalyzeFile(), h.AnalyzeFile)
	s.AddTool(toolRunGolangCILint(), h.RunGolangCILint)
	s.AddTool(toolListAnalyzers(), h.ListAnalyzers)
	s.AddTool(toolExplainFinding(), h.ExplainFinding)
	s.AddTool(toolSuggestFix(), h.SuggestFix)
	s.AddTool(toolGenerateGolangCIConfig(), h.GenerateGolangCIConfig)

	// 18 new intelligence tools
	s.AddTool(toolReviewRepository(), h.ReviewRepository)
	s.AddTool(toolAnalyzeGitDiff(), h.AnalyzeGitDiff)
	s.AddTool(toolReviewPullRequest(), h.ReviewPullRequest)
	s.AddTool(toolGenerateFixPatches(), h.GenerateFixPatches)
	s.AddTool(toolScanDependencyHealth(), h.ScanDependencyHealth)
	s.AddTool(toolDetectArchitecturalSmells(), h.DetectArchitecturalSmells)
	s.AddTool(toolGenerateComplexityReport(), h.GenerateComplexityReport)
	s.AddTool(toolFindDeadCode(), h.FindDeadCode)
	s.AddTool(toolDetectPerformanceIssues(), h.DetectPerformanceIssues)
	s.AddTool(toolDetectConcurrencyIssues(), h.DetectConcurrencyIssues)
	s.AddTool(toolDetectAPIBreakingChanges(), h.DetectAPIBreakingChanges)
	s.AddTool(toolGenerateSecurityAudit(), h.GenerateSecurityAudit)
	s.AddTool(toolGetRepositoryHealthScore(), h.GetRepositoryHealthScore)
	s.AddTool(toolGetRepositoryFingerprint(), h.GetRepositoryFingerprint)
	s.AddTool(toolGenerateKnowledgeGraph(), h.GenerateKnowledgeGraph)
	s.AddTool(toolGenerateCallGraph(), h.GenerateCallGraph)
	s.AddTool(toolAnalyzeImpact(), h.AnalyzeImpact)
	s.AddTool(toolAskRepository(), h.AskRepository)
}

// --- Tool definitions ---

func toolAnalyzeRepository() mcp.Tool {
	return mcp.NewTool("analyze_repository",
		mcp.WithDescription(
			"Analyze a Go repository for code quality, security, correctness, performance, and "+
				"maintainability issues. Runs multiple analyzers in parallel and returns aggregated findings.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root (must contain go.mod)"),
		),
		mcp.WithArray("analyzers",
			mcp.Description("Analyzer names to run (empty = all). Options: golangci-lint, staticcheck, gosec"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: json (default), markdown, sarif"),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Analysis timeout in seconds (default: 300)"),
		),
		mcp.WithString("config",
			mcp.Description("Path to golangci-lint config file (optional)"),
		),
	)
}

func toolAnalyzeFile() mcp.Tool {
	return mcp.NewTool("analyze_file",
		mcp.WithDescription(
			"Analyze a single Go source file for code quality issues. "+
				"Ideal for targeted analysis during code review.",
		),
		mcp.WithString("file_path",
			mcp.Required(),
			mcp.Description("Absolute path to the .go file to analyze"),
		),
		mcp.WithArray("analyzers",
			mcp.Description("Analyzer names to run (empty = all)"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: json (default), markdown, sarif"),
		),
	)
}

func toolRunGolangCILint() mcp.Tool {
	return mcp.NewTool("run_golangci_lint",
		mcp.WithDescription(
			"Execute golangci-lint directly against a Go module with full control over "+
				"which linters to enable. Returns raw linter output mapped to structured findings.",
		),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go module root"),
		),
		mcp.WithArray("linters",
			mcp.Description("Specific linters to enable (e.g. govet, errcheck, gosec). Empty = golangci-lint defaults"),
		),
		mcp.WithString("config",
			mcp.Description("Path to .golangci.yml config file"),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Timeout in seconds (default: 300)"),
		),
	)
}

func toolListAnalyzers() mcp.Tool {
	return mcp.NewTool("list_analyzers",
		mcp.WithDescription(
			"List all available static analysis adapters with their descriptions, "+
				"supported rules, and auto-fix capabilities.",
		),
	)
}

func toolExplainFinding() mcp.Tool {
	return mcp.NewTool("explain_finding",
		mcp.WithDescription(
			"Get a detailed explanation of a static analysis finding including what the rule "+
				"checks, why it matters, and references to documentation.",
		),
		mcp.WithString("rule_id",
			mcp.Required(),
			mcp.Description("The rule/linter ID (e.g. SA1006, G104, errcheck)"),
		),
		mcp.WithString("analyzer",
			mcp.Description("The analyzer that produced the finding (e.g. golangci-lint, staticcheck, gosec)"),
		),
		mcp.WithString("message",
			mcp.Description("The finding message for context-aware explanation"),
		),
		mcp.WithString("code",
			mcp.Description("The offending source code snippet"),
		),
	)
}

func toolSuggestFix() mcp.Tool {
	return mcp.NewTool("suggest_fix",
		mcp.WithDescription(
			"Suggest a code fix for a static analysis finding. "+
				"For auto-fixable rules, provides the golangci-lint --fix command. "+
				"For manual fixes, provides step-by-step remediation guidance.",
		),
		mcp.WithString("rule_id",
			mcp.Required(),
			mcp.Description("The rule ID to fix (e.g. errcheck, bodyclose)"),
		),
		mcp.WithString("analyzer",
			mcp.Required(),
			mcp.Description("The analyzer that produced the finding"),
		),
		mcp.WithString("code",
			mcp.Description("The offending source code snippet"),
		),
		mcp.WithString("file_path",
			mcp.Description("Path to the file containing the finding"),
		),
		mcp.WithNumber("line",
			mcp.Description("Line number of the finding"),
		),
	)
}

func toolGenerateGolangCIConfig() mcp.Tool {
	return mcp.NewTool("generate_golangci_config",
		mcp.WithDescription(
			"Generate a ready-to-use .golangci.yml configuration file tailored to the "+
				"selected analyzers. The generated config follows golangci-lint best practices.",
		),
		mcp.WithArray("analyzers",
			mcp.Description("Analyzers/linters to include (empty = all registered analyzers)"),
		),
		mcp.WithBoolean("strict",
			mcp.Description("Enable stricter settings with longer timeout and more rules"),
		),
	)
}
