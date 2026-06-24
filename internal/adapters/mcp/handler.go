package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
)

// Handler implements all MCP tool handler functions.
// No logger is stored – package-level slog is used after bootstrap sets the default.
type Handler struct {
	analysisSvc *appanalysis.Service
}

const defaultTimeoutSecs = 300

// --- analyze_repository ---

func (h *Handler) AnalyzeRepository(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}

	analyzers := parseStringSlice(req, "analyzers")
	format := mcp.ParseString(req, "format", "json")
	timeoutSecs := int(mcp.ParseFloat64(req, "timeout_seconds", defaultTimeoutSecs))
	config := mcp.ParseString(req, "config", "")

	result, err := h.analysisSvc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:      path,
		Analyzers: analyzers,
		Format:    format,
		Timeout:   time.Duration(timeoutSecs) * time.Second,
		Config:    config,
	})
	if err != nil {
		return toolError(fmt.Sprintf("analyze_repository failed: %v", err)), nil
	}

	if format == "json" {
		return toolJSON(result)
	}

	rendered, err := h.analysisSvc.Render(ctx, result, format)
	if err != nil {
		return toolError(fmt.Sprintf("rendering result: %v", err)), nil
	}
	return toolText(rendered), nil
}

// --- analyze_file ---

func (h *Handler) AnalyzeFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filePath := mcp.ParseString(req, "file_path", "")
	if filePath == "" {
		return toolError("file_path parameter is required"), nil
	}

	analyzers := parseStringSlice(req, "analyzers")
	format := mcp.ParseString(req, "format", "json")

	result, err := h.analysisSvc.AnalyzeFile(ctx, appanalysis.AnalyzeFileCommand{
		FilePath:  filePath,
		Analyzers: analyzers,
		Format:    format,
	})
	if err != nil {
		return toolError(fmt.Sprintf("analyze_file failed: %v", err)), nil
	}

	if format == "json" {
		return toolJSON(result)
	}

	rendered, err := h.analysisSvc.Render(ctx, result, format)
	if err != nil {
		return toolError(fmt.Sprintf("rendering result: %v", err)), nil
	}
	return toolText(rendered), nil
}

// --- run_golangci_lint ---

func (h *Handler) RunGolangCILint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := mcp.ParseString(req, "path", "")
	if path == "" {
		return toolError("path parameter is required"), nil
	}

	linters := parseStringSlice(req, "linters")
	config := mcp.ParseString(req, "config", "")
	timeoutSecs := int(mcp.ParseFloat64(req, "timeout_seconds", defaultTimeoutSecs))

	result, err := h.analysisSvc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:      path,
		Analyzers: linters,
		Timeout:   time.Duration(timeoutSecs) * time.Second,
		Config:    config,
		Format:    "json",
	})
	if err != nil {
		return toolError(fmt.Sprintf("run_golangci_lint failed: %v", err)), nil
	}

	// Filter to golangci-lint results only
	for i := range result.Results {
		if result.Results[i].Analyzer == "golangci-lint" {
			return toolJSON(result.Results[i])
		}
	}
	return toolJSON(result)
}

// --- list_analyzers ---

func (h *Handler) ListAnalyzers(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	analyzers := h.analysisSvc.ListAnalyzers()

	type analyzerInfo struct {
		Name            string `json:"name"`
		Description     string `json:"description"`
		SupportsAutoFix bool   `json:"supports_auto_fix"`
		RuleCount       int    `json:"rule_count"`
	}

	items := make([]analyzerInfo, 0, len(analyzers))
	for _, a := range analyzers {
		items = append(items, analyzerInfo{
			Name:            a.Name(),
			Description:     a.Description(),
			SupportsAutoFix: a.SupportsAutoFix(),
			RuleCount:       len(a.SupportedRules()),
		})
	}

	return toolJSON(map[string]any{
		"analyzers": items,
		"count":     len(items),
	})
}

// --- explain_finding ---

func (h *Handler) ExplainFinding(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ruleID := mcp.ParseString(req, "rule_id", "")
	analyzer := mcp.ParseString(req, "analyzer", "")
	message := mcp.ParseString(req, "message", "")
	code := mcp.ParseString(req, "code", "")

	if ruleID == "" {
		return toolError("rule_id parameter is required"), nil
	}

	explanation, err := h.analysisSvc.ExplainFinding(ctx, appanalysis.ExplainFindingCommand{
		RuleID:   ruleID,
		Analyzer: analyzer,
		Message:  message,
		Code:     code,
	})
	if err != nil {
		return toolError(fmt.Sprintf("explain_finding failed: %v", err)), nil
	}

	return toolJSON(map[string]any{
		"rule_id":     ruleID,
		"analyzer":    analyzer,
		"explanation": explanation,
	})
}

// --- suggest_fix ---

func (h *Handler) SuggestFix(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ruleID := mcp.ParseString(req, "rule_id", "")
	analyzer := mcp.ParseString(req, "analyzer", "")
	code := mcp.ParseString(req, "code", "")
	filePath := mcp.ParseString(req, "file_path", "")
	line := int(mcp.ParseFloat64(req, "line", 0))

	if ruleID == "" {
		return toolError("rule_id parameter is required"), nil
	}

	suggestion, err := h.analysisSvc.SuggestFix(ctx, appanalysis.SuggestFixCommand{
		RuleID:   ruleID,
		Analyzer: analyzer,
		Code:     code,
		FilePath: filePath,
		Line:     line,
	})
	if err != nil {
		return toolError(fmt.Sprintf("suggest_fix failed: %v", err)), nil
	}

	return toolJSON(map[string]any{
		"rule_id":    ruleID,
		"analyzer":   analyzer,
		"suggestion": suggestion,
	})
}

// --- generate_golangci_config ---

func (h *Handler) GenerateGolangCIConfig(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	analyzers := parseStringSlice(req, "analyzers")
	strict := mcp.ParseBoolean(req, "strict", false)

	cfg, err := h.analysisSvc.GenerateGolangCIConfig(ctx, appanalysis.GenerateConfigCommand{
		Analyzers: analyzers,
		Strict:    strict,
	})
	if err != nil {
		return toolError(fmt.Sprintf("generate_golangci_config failed: %v", err)), nil
	}

	return toolText(cfg), nil
}

// --- Helpers ---

func toolJSON(v any) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(fmt.Sprintf("serializing result: %v", err)), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

func toolText(text string) *mcp.CallToolResult {
	return mcp.NewToolResultText(text)
}

func toolError(msg string) *mcp.CallToolResult {
	return mcp.NewToolResultError(msg)
}

func parseStringSlice(req mcp.CallToolRequest, key string) []string {
	args := req.GetArguments()
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if val == "" {
			return nil
		}
		return strings.Split(val, ",")
	}
	return nil
}
