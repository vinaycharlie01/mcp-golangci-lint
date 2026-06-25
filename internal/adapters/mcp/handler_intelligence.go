package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"

	intelligence "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/intelligence"
)

// intelligenceHandler is embedded in Handler to provide the 18 intelligence tool methods.
// It delegates to intelligenceSvc (may be nil – guarded in each method).

func (h *Handler) intelligenceSvcOrError() (*intelligence.Service, *mcp.CallToolResult) {
	if h.intelligenceSvc == nil {
		return nil, toolError("intelligence service is not available")
	}
	return h.intelligenceSvc, nil
}

// --- review_repository ---

func (h *Handler) ReviewRepository(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.ReviewRepository(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("review_repository failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- analyze_git_diff ---

func (h *Handler) AnalyzeGitDiff(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	base := mcp.ParseString(req, "base", "main")
	head := mcp.ParseString(req, "head", "HEAD")
	result, err := svc.AnalyzeGitDiff(ctx, path, base, head)
	if err != nil {
		return toolError(fmt.Sprintf("analyze_git_diff failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- review_pull_request ---

func (h *Handler) ReviewPullRequest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	baseBranch := mcp.ParseString(req, "base_branch", "main")
	headBranch := mcp.ParseString(req, "head_branch", "HEAD")
	result, err := svc.ReviewPullRequest(ctx, path, baseBranch, headBranch)
	if err != nil {
		return toolError(fmt.Sprintf("review_pull_request failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- generate_fix_patches ---

func (h *Handler) GenerateFixPatches(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	config := mcp.ParseString(req, "config", "")
	result, err := svc.GenerateFixPatches(ctx, path, config)
	if err != nil {
		return toolError(fmt.Sprintf("generate_fix_patches failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- scan_dependency_health ---

func (h *Handler) ScanDependencyHealth(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.ScanDependencyHealth(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("scan_dependency_health failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- detect_architectural_smells ---

func (h *Handler) DetectArchitecturalSmells(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.DetectArchitecturalSmells(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("detect_architectural_smells failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- generate_complexity_report ---

func (h *Handler) GenerateComplexityReport(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	topN := int(mcp.ParseFloat64(req, "top_n", 20))
	if topN <= 0 {
		topN = 20
	}
	result, err := svc.GenerateComplexityReport(ctx, path, topN)
	if err != nil {
		return toolError(fmt.Sprintf("generate_complexity_report failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- find_dead_code ---

func (h *Handler) FindDeadCode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.FindDeadCode(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("find_dead_code failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- detect_performance_issues ---

func (h *Handler) DetectPerformanceIssues(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.DetectPerformanceIssues(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("detect_performance_issues failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- detect_concurrency_issues ---

func (h *Handler) DetectConcurrencyIssues(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.DetectConcurrencyIssues(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("detect_concurrency_issues failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- detect_api_breaking_changes ---

func (h *Handler) DetectAPIBreakingChanges(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	baseRef := mcp.ParseString(req, "base_ref", "main")
	result, err := svc.DetectAPIBreakingChanges(ctx, path, baseRef)
	if err != nil {
		return toolError(fmt.Sprintf("detect_api_breaking_changes failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- generate_security_audit ---

func (h *Handler) GenerateSecurityAudit(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.GenerateSecurityAudit(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("generate_security_audit failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- get_repository_health_score ---

func (h *Handler) GetRepositoryHealthScore(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.GetRepositoryHealthScore(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("get_repository_health_score failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- get_repository_fingerprint ---

func (h *Handler) GetRepositoryFingerprint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	result, err := svc.GetRepositoryFingerprint(ctx, path)
	if err != nil {
		return toolError(fmt.Sprintf("get_repository_fingerprint failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- generate_knowledge_graph ---

func (h *Handler) GenerateKnowledgeGraph(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	format := mcp.ParseString(req, "format", "mermaid")
	result, err := svc.GenerateKnowledgeGraph(ctx, path, format)
	if err != nil {
		return toolError(fmt.Sprintf("generate_knowledge_graph failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- generate_call_graph ---

func (h *Handler) GenerateCallGraph(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	packagePattern := mcp.ParseString(req, "package_pattern", "./...")
	format := mcp.ParseString(req, "format", "mermaid")
	result, err := svc.GenerateCallGraph(ctx, path, packagePattern, format)
	if err != nil {
		return toolError(fmt.Sprintf("generate_call_graph failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- analyze_impact ---

func (h *Handler) AnalyzeImpact(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	symbol := mcp.ParseString(req, "symbol", "")
	if symbol == "" {
		return toolError("symbol parameter is required"), nil
	}
	packagePath := mcp.ParseString(req, "package_path", "")
	result, err := svc.AnalyzeImpact(ctx, path, symbol, packagePath)
	if err != nil {
		return toolError(fmt.Sprintf("analyze_impact failed: %v", err)), nil
	}
	return toolJSON(result)
}

// --- ask_repository ---

func (h *Handler) AskRepository(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	svc, errResult := h.intelligenceSvcOrError()
	if errResult != nil {
		return errResult, nil
	}
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}
	question := mcp.ParseString(req, "question", "")
	if question == "" {
		return toolError("question parameter is required"), nil
	}
	result, err := svc.AskRepository(ctx, path, question)
	if err != nil {
		return toolError(fmt.Sprintf("ask_repository failed: %v", err)), nil
	}
	return toolJSON(result)
}
