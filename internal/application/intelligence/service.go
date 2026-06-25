// Package intelligence provides repository intelligence operations that go beyond
// basic static analysis: architectural reviews, complexity reports, security audits,
// dependency health checks, call/knowledge graphs, and natural-language Q&A.
package intelligence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	appanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/application/analysis"
	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
)

// Service provides all repository intelligence capabilities.
// No logger is stored in the struct – use pkglogger.FromContext(ctx, slog.Default()).
type Service struct {
	analysisSvc *appanalysis.Service
}

// New creates a new intelligence Service.
func New(analysisSvc *appanalysis.Service) *Service {
	return &Service{analysisSvc: analysisSvc}
}

// ---------------------------------------------------------------------------
// 1. ReviewRepository
// ---------------------------------------------------------------------------

// ReviewRepositoryResult is returned by ReviewRepository.
type ReviewRepositoryResult struct {
	Summary             string                              `json:"summary"`
	FindingsBySeverity  map[string][]domainanalysis.Finding `json:"findings_by_severity"`
	Patterns            []RecurringPattern                  `json:"patterns"`
	DebtEstimateMinutes int                                 `json:"debt_estimate_minutes"`
	PriorityFixes       []PriorityFix                       `json:"priority_fixes"`
}

// RecurringPattern is a rule that appears 3+ times.
type RecurringPattern struct {
	RuleID     string `json:"rule_id"`
	Count      int    `json:"count"`
	Analyzer   string `json:"analyzer"`
	Suggestion string `json:"suggestion"`
}

// PriorityFix is a recommended action.
type PriorityFix struct {
	Rank        int    `json:"rank"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// ReviewRepository runs all analyzers and produces an AI-oriented review.
func (s *Service) ReviewRepository(ctx context.Context, path string) (*ReviewRepositoryResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "review_repository started", slog.String("path", path))

	agg, err := s.analysisSvc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:   path,
		Format: "json",
	})
	if err != nil {
		return nil, fmt.Errorf("analyzing repository: %w", err)
	}

	bySeverity := map[string][]domainanalysis.Finding{
		"critical": {},
		"high":     {},
		"medium":   {},
		"low":      {},
		"info":     {},
	}
	ruleCounts := map[string]struct {
		count    int
		analyzer string
		severity string
		message  string
	}{}

	for _, f := range agg.AllFindings() {
		sev := string(f.Severity)
		bySeverity[sev] = append(bySeverity[sev], f)
		entry := ruleCounts[f.RuleID]
		entry.count++
		entry.analyzer = f.Analyzer
		entry.severity = sev
		entry.message = f.Message
		ruleCounts[f.RuleID] = entry
	}

	// Debt estimation
	debt := len(bySeverity["critical"])*30 + len(bySeverity["high"])*15 + len(bySeverity["medium"])*5

	// Recurring patterns (3+ occurrences)
	var patterns []RecurringPattern
	for ruleID, entry := range ruleCounts {
		if entry.count >= 3 {
			patterns = append(patterns, RecurringPattern{
				RuleID:     ruleID,
				Count:      entry.count,
				Analyzer:   entry.analyzer,
				Suggestion: fmt.Sprintf("Address all %d occurrences of %s", entry.count, ruleID),
			})
		}
	}
	sort.Slice(patterns, func(i, j int) bool { return patterns[i].Count > patterns[j].Count })

	// Priority fixes – sort by severity weight then count
	type ruleKey struct {
		ruleID   string
		severity string
		count    int
		msg      string
	}
	ranked := make([]ruleKey, 0, len(ruleCounts))
	for ruleID, entry := range ruleCounts {
		ranked = append(ranked, ruleKey{ruleID, entry.severity, entry.count, entry.message})
	}
	sort.Slice(ranked, func(i, j int) bool {
		wi := domainanalysis.NormalizeSeverity(ranked[i].severity).Weight()
		wj := domainanalysis.NormalizeSeverity(ranked[j].severity).Weight()
		if wi != wj {
			return wi > wj
		}
		return ranked[i].count > ranked[j].count
	})
	maxFixes := len(ranked)
	if maxFixes > 10 {
		maxFixes = 10
	}
	priorityFixes := make([]PriorityFix, 0, maxFixes)
	for i, r := range ranked {
		if i >= 10 {
			break
		}
		priorityFixes = append(priorityFixes, PriorityFix{
			Rank:        i + 1,
			RuleID:      r.ruleID,
			Severity:    r.severity,
			Description: r.msg,
			Count:       r.count,
		})
	}

	total := agg.Summary.Total
	summary := fmt.Sprintf(
		"Repository analysis complete: %d total findings — %d critical, %d high, %d medium, %d low. Estimated technical debt: %d minutes.",
		total,
		len(bySeverity["critical"]),
		len(bySeverity["high"]),
		len(bySeverity["medium"]),
		len(bySeverity["low"]),
		debt,
	)

	return &ReviewRepositoryResult{
		Summary:             summary,
		FindingsBySeverity:  bySeverity,
		Patterns:            patterns,
		DebtEstimateMinutes: debt,
		PriorityFixes:       priorityFixes,
	}, nil
}

// ---------------------------------------------------------------------------
// 2. AnalyzeGitDiff
// ---------------------------------------------------------------------------

// GitDiffResult is returned by AnalyzeGitDiff.
type GitDiffResult struct {
	ChangedFiles       []string                 `json:"changed_files"`
	NewIssues          []domainanalysis.Finding `json:"new_issues"`
	TotalNew           int                      `json:"total_new"`
	TotalFixedEstimate int                      `json:"total_fixed_estimate"`
}

// AnalyzeGitDiff runs analysis and separates new issues from existing.
func (s *Service) AnalyzeGitDiff(ctx context.Context, path, base, head string) (*GitDiffResult, error) {
	// Get changed .go files
	out, err := runGit(ctx, path, "diff", "--name-only", "--diff-filter=ACMR", base+"..."+head)
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	var changedFiles []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasSuffix(line, ".go") {
			changedFiles = append(changedFiles, line)
		}
	}

	if len(changedFiles) == 0 {
		return &GitDiffResult{ChangedFiles: changedFiles}, nil
	}

	agg, err := s.analysisSvc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:   path,
		Format: "json",
	})
	if err != nil {
		return nil, fmt.Errorf("analyzing repository: %w", err)
	}

	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[f] = true
		changedSet[filepath.Join(path, f)] = true
	}

	var newIssues []domainanalysis.Finding
	for _, f := range agg.AllFindings() {
		file := f.Location.File
		rel, relErr := filepath.Rel(path, file)
		if relErr == nil {
			file = rel
		}
		if changedSet[file] || changedSet[f.Location.File] {
			newIssues = append(newIssues, f)
		}
	}

	return &GitDiffResult{
		ChangedFiles:       changedFiles,
		NewIssues:          newIssues,
		TotalNew:           len(newIssues),
		TotalFixedEstimate: 0,
	}, nil
}

// ---------------------------------------------------------------------------
// 3. ReviewPullRequest
// ---------------------------------------------------------------------------

// PRReviewResult is returned by ReviewPullRequest.
type PRReviewResult struct {
	Summary        string                   `json:"summary"`
	BlockingIssues []domainanalysis.Finding `json:"blocking_issues"`
	SecurityIssues []domainanalysis.Finding `json:"security_issues"`
	WarningIssues  []domainanalysis.Finding `json:"warning_issues"`
	ChangedFiles   []string                 `json:"changed_files"`
	Recommendation string                   `json:"recommendation"`
}

// ReviewPullRequest performs a PR-focused review.
func (s *Service) ReviewPullRequest(ctx context.Context, path, baseBranch, headBranch string) (*PRReviewResult, error) {
	diffResult, err := s.AnalyzeGitDiff(ctx, path, baseBranch, headBranch)
	if err != nil {
		return nil, err
	}

	var blocking, security, warnings []domainanalysis.Finding
	for _, f := range diffResult.NewIssues {
		switch f.Severity {
		case domainanalysis.SeverityCritical, domainanalysis.SeverityHigh:
			blocking = append(blocking, f)
		case domainanalysis.SeverityMedium, domainanalysis.SeverityLow, domainanalysis.SeverityInfo:
			warnings = append(warnings, f)
		}
		if f.Category == domainanalysis.CategorySecurity {
			security = append(security, f)
		}
	}

	recommendation := "APPROVE"
	if len(blocking) > 0 {
		recommendation = "REQUEST_CHANGES"
	} else if len(warnings) > 5 {
		recommendation = "COMMENT"
	}

	summary := fmt.Sprintf(
		"PR review: %d changed files, %d new issues (%d blocking, %d security, %d warnings). Recommendation: %s",
		len(diffResult.ChangedFiles), diffResult.TotalNew, len(blocking), len(security), len(warnings), recommendation,
	)

	return &PRReviewResult{
		Summary:        summary,
		BlockingIssues: blocking,
		SecurityIssues: security,
		WarningIssues:  warnings,
		ChangedFiles:   diffResult.ChangedFiles,
		Recommendation: recommendation,
	}, nil
}

// ---------------------------------------------------------------------------
// 4. GenerateFixPatches
// ---------------------------------------------------------------------------

// FixPatch represents a unified diff patch.
type FixPatch struct {
	File         string   `json:"file"`
	Diff         string   `json:"diff"`
	RuleIDsFixed []string `json:"rule_ids_fixed"`
}

// FixPatchesResult is returned by GenerateFixPatches.
type FixPatchesResult struct {
	Patches    []FixPatch `json:"patches"`
	TotalFixed int        `json:"total_fixed"`
}

// GenerateFixPatches runs golangci-lint --fix and returns the diffs.
func (s *Service) GenerateFixPatches(ctx context.Context, path, config string) (*FixPatchesResult, error) {
	args := []string{"run", "--fix", "--out-format", "json"}
	if config != "" {
		args = append(args, "--config", config)
	}
	args = append(args, "./...")

	//nolint:gosec // path is validated by caller
	cmd := exec.CommandContext(ctx, "golangci-lint", args...)
	cmd.Dir = path
	_ = cmd.Run() // non-zero exit is normal

	// Capture git diff
	diffOut, err := runGit(ctx, path, "diff")
	if err != nil || diffOut == "" {
		return &FixPatchesResult{}, nil
	}

	// Parse unified diff into per-file patches
	patches := parseDiff(diffOut)

	return &FixPatchesResult{
		Patches:    patches,
		TotalFixed: len(patches),
	}, nil
}

func parseDiff(diffText string) []FixPatch {
	var patches []FixPatch
	var currentFile string
	var currentLines []string

	flush := func() {
		if currentFile != "" {
			patches = append(patches, FixPatch{
				File: currentFile,
				Diff: strings.Join(currentLines, "\n"),
			})
		}
	}

	for _, line := range strings.Split(diffText, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				currentFile = strings.TrimPrefix(parts[3], "b/")
			}
			currentLines = []string{line}
		} else {
			currentLines = append(currentLines, line)
		}
	}
	flush()
	return patches
}

// ---------------------------------------------------------------------------
// 5. ScanDependencyHealth
// ---------------------------------------------------------------------------

// DepHealthResult is returned by ScanDependencyHealth.
type DepHealthResult struct {
	Module           string                          `json:"module"`
	GoVersion        string                          `json:"go_version"`
	DirectDeps       []domainanalysis.DependencyInfo `json:"direct_deps"`
	IndirectDeps     []domainanalysis.DependencyInfo `json:"indirect_deps"`
	UpdatesAvailable []UpdateInfo                    `json:"updates_available"`
	Recommendations  []string                        `json:"recommendations"`
}

// UpdateInfo describes an available module update.
type UpdateInfo struct {
	Module  string `json:"module"`
	Current string `json:"current"`
	Latest  string `json:"latest"`
}

// goModListEntry is the JSON shape of `go list -m -u -json all`.
type goModListEntry struct {
	Path     string          `json:"Path"`
	Version  string          `json:"Version"`
	Update   *goModListEntry `json:"Update,omitempty"`
	Indirect bool            `json:"Indirect,omitempty"`
	Main     bool            `json:"Main,omitempty"`
}

// ScanDependencyHealth scans go.mod and reports update/health info.
func (s *Service) ScanDependencyHealth(ctx context.Context, path string) (*DepHealthResult, error) {
	// Read go.mod
	goModPath := filepath.Join(path, "go.mod")
	goModData, err := os.ReadFile(goModPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	moduleName, goVersion := parseGoMod(string(goModData))

	// Run go list -m -u -json all
	//nolint:gosec
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-u", "-json", "all")
	cmd.Dir = path
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	var directDeps, indirectDeps []domainanalysis.DependencyInfo
	var updates []UpdateInfo

	// go list outputs multiple JSON objects, one per module
	decoder := json.NewDecoder(&stdout)
	for decoder.More() {
		var entry goModListEntry
		if err2 := decoder.Decode(&entry); err2 != nil {
			break
		}
		if entry.Main {
			continue
		}
		dep := domainanalysis.DependencyInfo{
			Path:     entry.Path,
			Version:  entry.Version,
			Indirect: entry.Indirect,
		}
		if entry.Update != nil {
			dep.Latest = entry.Update.Version
			updates = append(updates, UpdateInfo{
				Module:  entry.Path,
				Current: entry.Version,
				Latest:  entry.Update.Version,
			})
		}
		if entry.Indirect {
			indirectDeps = append(indirectDeps, dep)
		} else {
			directDeps = append(directDeps, dep)
		}
	}

	var recs []string
	if len(updates) > 0 {
		recs = append(recs, fmt.Sprintf("%d dependencies have updates available. Run `go get -u ./...` to upgrade.", len(updates)))
	}
	if len(directDeps) > 20 {
		recs = append(recs, "Consider reducing direct dependencies to minimize attack surface.")
	}

	return &DepHealthResult{
		Module:           moduleName,
		GoVersion:        goVersion,
		DirectDeps:       directDeps,
		IndirectDeps:     indirectDeps,
		UpdatesAvailable: updates,
		Recommendations:  recs,
	}, nil
}

// parseGoMod extracts module name and go version from go.mod content.
func parseGoMod(content string) (module, goVersion string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			module = strings.TrimPrefix(line, "module ")
			module = strings.TrimSpace(module)
		}
		if strings.HasPrefix(line, "go ") {
			goVersion = strings.TrimPrefix(line, "go ")
			goVersion = strings.TrimSpace(goVersion)
		}
	}
	return
}

// ---------------------------------------------------------------------------
// 6. DetectArchitecturalSmells
// ---------------------------------------------------------------------------

// ArchSmellsResult is returned by DetectArchitecturalSmells.
type ArchSmellsResult struct {
	Findings []domainanalysis.ArchSmellFinding `json:"findings"`
}

// DetectArchitecturalSmells finds god files, large interfaces, deep nesting, etc.
func (s *Service) DetectArchitecturalSmells(ctx context.Context, path string) (*ArchSmellsResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "detect_architectural_smells started", slog.String("path", path))

	var findings []domainanalysis.ArchSmellFinding

	goFiles, err := collectGoFiles(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	for _, filePath := range goFiles {
		// Count lines
		data, readErr := os.ReadFile(filePath) //nolint:gosec
		if readErr != nil {
			continue
		}
		lineCount := strings.Count(string(data), "\n")
		rel := relPath(path, filePath)

		if lineCount > 500 {
			findings = append(findings, domainanalysis.ArchSmellFinding{
				Type:        "god_file",
				Location:    rel,
				Description: fmt.Sprintf("File has %d lines (threshold: 500)", lineCount),
				Severity:    "medium",
				Suggestion:  "Break into smaller, focused files following single-responsibility principle.",
			})
		}

		// Parse AST
		f, parseErr := parser.ParseFile(fset, filePath, data, 0)
		if parseErr != nil {
			continue
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.InterfaceType:
				if node.Methods != nil && len(node.Methods.List) > 10 {
					pos := fset.Position(node.Pos())
					findings = append(findings, domainanalysis.ArchSmellFinding{
						Type:        "large_interface",
						Location:    fmt.Sprintf("%s:%d", rel, pos.Line),
						Description: fmt.Sprintf("Interface has %d methods (threshold: 10)", len(node.Methods.List)),
						Severity:    "medium",
						Suggestion:  "Split into smaller, more focused interfaces (Interface Segregation Principle).",
					})
				}
			case *ast.StructType:
				if node.Fields != nil && len(node.Fields.List) > 20 {
					pos := fset.Position(node.Pos())
					findings = append(findings, domainanalysis.ArchSmellFinding{
						Type:        "large_struct",
						Location:    fmt.Sprintf("%s:%d", rel, pos.Line),
						Description: fmt.Sprintf("Struct has %d fields (threshold: 20)", len(node.Fields.List)),
						Severity:    "low",
						Suggestion:  "Consider splitting into smaller structs or using composition.",
					})
				}
			case *ast.FuncDecl:
				if node.Body != nil {
					funcLines := fset.Position(node.Body.End()).Line - fset.Position(node.Body.Pos()).Line
					if funcLines > 100 {
						pos := fset.Position(node.Pos())
						name := ""
						if node.Name != nil {
							name = node.Name.Name
						}
						findings = append(findings, domainanalysis.ArchSmellFinding{
							Type:        "long_function",
							Location:    fmt.Sprintf("%s:%d", rel, pos.Line),
							Description: fmt.Sprintf("Function %q has %d lines (threshold: 100)", name, funcLines),
							Severity:    "low",
							Suggestion:  "Extract sub-functions to improve readability and testability.",
						})
					}
					// Check nesting depth
					depth := maxNestingDepth(node.Body)
					if depth > 4 {
						pos := fset.Position(node.Pos())
						name := ""
						if node.Name != nil {
							name = node.Name.Name
						}
						findings = append(findings, domainanalysis.ArchSmellFinding{
							Type:        "deep_nesting",
							Location:    fmt.Sprintf("%s:%d", rel, pos.Line),
							Description: fmt.Sprintf("Function %q has nesting depth %d (threshold: 4)", name, depth),
							Severity:    "medium",
							Suggestion:  "Use early returns and extract helper functions to reduce nesting.",
						})
					}
				}
			}
			return true
		})
	}

	return &ArchSmellsResult{Findings: findings}, nil
}

// maxNestingDepth computes the maximum block nesting depth in a function body.
func maxNestingDepth(body *ast.BlockStmt) int {
	if body == nil {
		return 0
	}
	max := 0
	var walk func(ast.Node, int)
	walk = func(n ast.Node, depth int) {
		if depth > max {
			max = depth
		}
		switch node := n.(type) {
		case *ast.IfStmt:
			walk(node.Body, depth+1)
			if node.Else != nil {
				walk(node.Else, depth+1)
			}
		case *ast.ForStmt:
			walk(node.Body, depth+1)
		case *ast.RangeStmt:
			walk(node.Body, depth+1)
		case *ast.SwitchStmt:
			walk(node.Body, depth+1)
		case *ast.TypeSwitchStmt:
			walk(node.Body, depth+1)
		case *ast.SelectStmt:
			walk(node.Body, depth+1)
		case *ast.BlockStmt:
			for _, stmt := range node.List {
				walk(stmt, depth)
			}
		case *ast.CaseClause:
			for _, stmt := range node.Body {
				walk(stmt, depth)
			}
		case *ast.CommClause:
			for _, stmt := range node.Body {
				walk(stmt, depth)
			}
		}
	}
	walk(body, 0)
	return max
}

// ---------------------------------------------------------------------------
// 7. GenerateComplexityReport
// ---------------------------------------------------------------------------

// ComplexityReport is returned by GenerateComplexityReport.
type ComplexityReport struct {
	TopFunctions []domainanalysis.ComplexityEntry `json:"top_functions"`
	TopFiles     []domainanalysis.FileComplexity  `json:"top_files"`
	Summary      ComplexitySummary                `json:"summary"`
}

// ComplexitySummary holds aggregate complexity statistics.
type ComplexitySummary struct {
	TotalFunctions int     `json:"total_functions"`
	AvgComplexity  float64 `json:"avg_complexity"`
	MaxComplexity  int     `json:"max_complexity"`
}

// GenerateComplexityReport computes cyclomatic complexity for all functions.
func (s *Service) GenerateComplexityReport(ctx context.Context, path string, topN int) (*ComplexityReport, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "generate_complexity_report started", slog.String("path", path))

	goFiles, err := collectGoFiles(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	var entries []domainanalysis.ComplexityEntry
	fileMap := map[string][]int{} // file -> list of complexities

	for _, filePath := range goFiles {
		f, parseErr := parser.ParseFile(fset, filePath, nil, 0)
		if parseErr != nil {
			continue
		}
		rel := relPath(path, filePath)

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			pos := fset.Position(fn.Pos())
			name := ""
			if fn.Name != nil {
				name = fn.Name.Name
			}
			cc := cyclomaticComplexity(fn)
			entries = append(entries, domainanalysis.ComplexityEntry{
				Function:   name,
				File:       rel,
				Line:       pos.Line,
				Complexity: cc,
			})
			fileMap[rel] = append(fileMap[rel], cc)
			return true
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Complexity > entries[j].Complexity })

	topFuncs := entries
	if len(topFuncs) > topN {
		topFuncs = topFuncs[:topN]
	}

	// Build top files
	type fileStats struct {
		name  string
		comps []int
	}
	fileList := make([]fileStats, 0, len(fileMap))
	for name, comps := range fileMap {
		fileList = append(fileList, fileStats{name, comps})
	}
	sort.Slice(fileList, func(i, j int) bool {
		return avgInt(fileList[i].comps) > avgInt(fileList[j].comps)
	})
	maxTopFiles := len(fileList)
	if maxTopFiles > topN {
		maxTopFiles = topN
	}
	topFiles := make([]domainanalysis.FileComplexity, 0, maxTopFiles)
	for i, fs := range fileList {
		if i >= topN {
			break
		}
		topFiles = append(topFiles, domainanalysis.FileComplexity{
			File:          fs.name,
			AvgComplexity: avgInt(fs.comps),
			MaxComplexity: maxInt(fs.comps),
			FunctionCount: len(fs.comps),
		})
	}

	totalCC := 0
	maxCC := 0
	for _, e := range entries {
		totalCC += e.Complexity
		if e.Complexity > maxCC {
			maxCC = e.Complexity
		}
	}
	avg := 0.0
	if len(entries) > 0 {
		avg = float64(totalCC) / float64(len(entries))
	}

	return &ComplexityReport{
		TopFunctions: topFuncs,
		TopFiles:     topFiles,
		Summary: ComplexitySummary{
			TotalFunctions: len(entries),
			AvgComplexity:  math.Round(avg*100) / 100,
			MaxComplexity:  maxCC,
		},
	}, nil
}

// cyclomaticComplexity computes cyclomatic complexity for a function declaration.
func cyclomaticComplexity(fn *ast.FuncDecl) int {
	complexity := 1
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			complexity++
		case *ast.ForStmt:
			complexity++
		case *ast.RangeStmt:
			complexity++
		case *ast.CaseClause:
			if node.List != nil {
				complexity++
			}
		case *ast.CommClause:
			complexity++
		case *ast.BinaryExpr:
			if node.Op.String() == "&&" || node.Op.String() == "||" {
				complexity++
			}
		case *ast.SwitchStmt:
			// switch itself doesn't add; cases do
		}
		return true
	})
	return complexity
}

// ---------------------------------------------------------------------------
// 8. FindDeadCode
// ---------------------------------------------------------------------------

// DeadCodeResult is returned by FindDeadCode.
type DeadCodeResult struct {
	PotentiallyUnused []domainanalysis.PotentiallyUnused `json:"potentially_unused"`
}

// FindDeadCode scans for unused exported symbols.
func (s *Service) FindDeadCode(ctx context.Context, path string) (*DeadCodeResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "find_dead_code started", slog.String("path", path))

	goFiles, err := collectGoFiles(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()

	// Collect all exported symbols and where they appear
	type symbolDef struct {
		name string
		kind string
		file string
		line int
	}
	var defs []symbolDef

	// Collect all identifiers used anywhere
	usedIdents := map[string]int{}

	for _, filePath := range goFiles {
		data, readErr := os.ReadFile(filePath) //nolint:gosec
		if readErr != nil {
			continue
		}
		f, parseErr := parser.ParseFile(fset, filePath, data, 0)
		if parseErr != nil {
			continue
		}
		rel := relPath(path, filePath)

		// Walk for definitions
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				if node.Name != nil && ast.IsExported(node.Name.Name) && node.Recv == nil {
					pos := fset.Position(node.Pos())
					defs = append(defs, symbolDef{node.Name.Name, "func", rel, pos.Line})
				}
			case *ast.TypeSpec:
				if ast.IsExported(node.Name.Name) {
					pos := fset.Position(node.Pos())
					defs = append(defs, symbolDef{node.Name.Name, "type", rel, pos.Line})
				}
			case *ast.ValueSpec:
				for _, name := range node.Names {
					if ast.IsExported(name.Name) {
						pos := fset.Position(name.Pos())
						defs = append(defs, symbolDef{name.Name, "var/const", rel, pos.Line})
					}
				}
			}
			return true
		})

		// Walk for usages (all identifiers)
		ast.Inspect(f, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok {
				usedIdents[ident.Name]++
			}
			return true
		})
	}

	var unused []domainanalysis.PotentiallyUnused
	for _, def := range defs {
		count := usedIdents[def.name]
		// Definitions themselves count as 1 usage (the declaration), so <= 1 means unused
		if count <= 1 {
			unused = append(unused, domainanalysis.PotentiallyUnused{
				Name:   def.name,
				Type:   def.kind,
				File:   def.file,
				Line:   def.line,
				Reason: "exported symbol appears to have no usages within the module",
			})
		}
	}

	return &DeadCodeResult{PotentiallyUnused: unused}, nil
}

// ---------------------------------------------------------------------------
// 9. DetectPerformanceIssues
// ---------------------------------------------------------------------------

// PerfResult is returned by DetectPerformanceIssues.
type PerfResult struct {
	Findings []domainanalysis.PerfFinding `json:"findings"`
}

// DetectPerformanceIssues performs AST-based performance analysis.
func (s *Service) DetectPerformanceIssues(ctx context.Context, path string) (*PerfResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "detect_performance_issues started", slog.String("path", path))

	goFiles, err := collectGoFiles(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	var findings []domainanalysis.PerfFinding

	for _, filePath := range goFiles {
		data, readErr := os.ReadFile(filePath) //nolint:gosec
		if readErr != nil {
			continue
		}
		f, parseErr := parser.ParseFile(fset, filePath, data, 0)
		if parseErr != nil {
			continue
		}
		rel := relPath(path, filePath)

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				// Check body for performance issues
				var body *ast.BlockStmt
				switch v := node.(type) {
				case *ast.ForStmt:
					body = v.Body
				case *ast.RangeStmt:
					body = v.Body
				}
				if body == nil {
					return true
				}
				ast.Inspect(body, func(inner ast.Node) bool {
					call, ok := inner.(*ast.CallExpr)
					if !ok {
						return true
					}
					pos := fset.Position(call.Pos())
					if isFmtSprintf(call) {
						findings = append(findings, domainanalysis.PerfFinding{
							Type:        "fmt_sprintf_in_loop",
							File:        rel,
							Line:        pos.Line,
							Description: "fmt.Sprintf called inside a loop – use strings.Builder for repeated string construction",
							Suggestion:  "Use strings.Builder or bytes.Buffer instead of fmt.Sprintf in loops",
							Severity:    "medium",
						})
					}
					if isAppendCall(call) {
						findings = append(findings, domainanalysis.PerfFinding{
							Type:        "append_in_loop_no_prealloc",
							File:        rel,
							Line:        pos.Line,
							Description: "append() called in loop without pre-allocation",
							Suggestion:  "Pre-allocate slice with make([]T, 0, n) before the loop",
							Severity:    "low",
						})
					}
					if isDeferInLoop(call) {
						findings = append(findings, domainanalysis.PerfFinding{
							Type:        "defer_in_loop",
							File:        rel,
							Line:        pos.Line,
							Description: "defer inside a loop – defers accumulate until function returns",
							Suggestion:  "Move defer outside the loop or use an immediately-invoked function",
							Severity:    "high",
						})
					}
					return true
				})
			case *ast.CallExpr:
				pos := fset.Position(node.Pos())
				if isStringByteConversion(node) {
					findings = append(findings, domainanalysis.PerfFinding{
						Type:        "string_byte_conversion",
						File:        rel,
						Line:        pos.Line,
						Description: "string([]byte) conversion causes allocation",
						Suggestion:  "Use unsafe.String or store as []byte to avoid conversion",
						Severity:    "low",
					})
				}
				if isMakeZeroNoCapacity(node) {
					findings = append(findings, domainanalysis.PerfFinding{
						Type:        "make_zero_no_capacity",
						File:        rel,
						Line:        pos.Line,
						Description: "make([]T, 0) without capacity hint",
						Suggestion:  "Provide capacity hint: make([]T, 0, expectedSize)",
						Severity:    "low",
					})
				}
			}
			return true
		})
	}

	return &PerfResult{Findings: findings}, nil
}

func isFmtSprintf(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "fmt" && sel.Sel.Name == "Sprintf"
}

func isAppendCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "append"
}

func isDeferInLoop(call *ast.CallExpr) bool {
	// defer is a statement not a call; detect via parent – handled separately
	_ = call
	return false
}

func isStringByteConversion(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "string" {
		return false
	}
	if len(call.Args) != 1 {
		return false
	}
	// Return false for string(someFunc()) — that's a function call, not a byte-slice conversion
	if _, ok := call.Args[0].(*ast.CallExpr); ok {
		return false
	}
	return true
}

func isMakeZeroNoCapacity(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "make" {
		return false
	}
	if len(call.Args) != 2 {
		return false
	}
	// Second arg is length, no capacity arg means no 3rd arg
	if lit, ok := call.Args[1].(*ast.BasicLit); ok {
		return lit.Value == "0"
	}
	return false
}

// ---------------------------------------------------------------------------
// 10. DetectConcurrencyIssues
// ---------------------------------------------------------------------------

// ConcurrencyResult is returned by DetectConcurrencyIssues.
type ConcurrencyResult struct {
	Findings []domainanalysis.ConcurrencyFinding `json:"findings"`
}

// DetectConcurrencyIssues performs AST-based concurrency analysis.
func (s *Service) DetectConcurrencyIssues(ctx context.Context, path string) (*ConcurrencyResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "detect_concurrency_issues started", slog.String("path", path))

	goFiles, err := collectGoFiles(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	var findings []domainanalysis.ConcurrencyFinding

	for _, filePath := range goFiles {
		data, readErr := os.ReadFile(filePath) //nolint:gosec
		if readErr != nil {
			continue
		}
		f, parseErr := parser.ParseFile(fset, filePath, data, 0)
		if parseErr != nil {
			continue
		}
		rel := relPath(path, filePath)

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.GoStmt:
				// go func() {} without assignment = potential goroutine leak
				pos := fset.Position(node.Pos())
				if _, ok := node.Call.Fun.(*ast.FuncLit); ok {
					findings = append(findings, domainanalysis.ConcurrencyFinding{
						Type:        "goroutine_leak_risk",
						File:        rel,
						Line:        pos.Line,
						Description: "Anonymous goroutine started without WaitGroup or channel capture",
						Severity:    "medium",
						Suggestion:  "Track goroutine completion with sync.WaitGroup or a done channel",
					})
				}
			case *ast.FuncDecl:
				if node.Body == nil {
					return true
				}
				checkMutexWithoutDefer(node.Body, fset, rel, &findings)
				checkTimeSleepInGoroutine(node.Body, fset, rel, &findings)
				checkDeferInLoop(node.Body, fset, rel, &findings)
			}
			return true
		})
	}

	return &ConcurrencyResult{Findings: findings}, nil
}

func checkMutexWithoutDefer(body *ast.BlockStmt, fset *token.FileSet, file string, findings *[]domainanalysis.ConcurrencyFinding) {
	hasLock := false
	hasDeferUnlock := false
	var lockPos token.Position

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Lock" {
			hasLock = true
			lockPos = fset.Position(call.Pos())
		}
		return true
	})

	// Check for defer Unlock
	for _, stmt := range body.List {
		deferStmt, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		call, ok := deferStmt.Call.Fun.(*ast.SelectorExpr)
		if ok && call.Sel.Name == "Unlock" {
			hasDeferUnlock = true
		}
	}

	if hasLock && !hasDeferUnlock {
		*findings = append(*findings, domainanalysis.ConcurrencyFinding{
			Type:        "mutex_lock_without_defer",
			File:        file,
			Line:        lockPos.Line,
			Description: "sync.Mutex Lock() called without deferred Unlock()",
			Severity:    "high",
			Suggestion:  "Add `defer mu.Unlock()` immediately after Lock() to prevent deadlocks",
		})
	}
}

func checkTimeSleepInGoroutine(body *ast.BlockStmt, fset *token.FileSet, file string, findings *[]domainanalysis.ConcurrencyFinding) {
	ast.Inspect(body, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		ast.Inspect(goStmt.Call, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if ok && pkg.Name == "time" && sel.Sel.Name == "Sleep" {
				pos := fset.Position(call.Pos())
				*findings = append(*findings, domainanalysis.ConcurrencyFinding{
					Type:        "time_sleep_in_goroutine",
					File:        file,
					Line:        pos.Line,
					Description: "time.Sleep inside goroutine is a busy-wait smell",
					Severity:    "low",
					Suggestion:  "Use time.Ticker, time.After, or select with a context for controlled waits",
				})
			}
			return true
		})
		return true
	})
}

func checkDeferInLoop(body *ast.BlockStmt, fset *token.FileSet, file string, findings *[]domainanalysis.ConcurrencyFinding) {
	ast.Inspect(body, func(n ast.Node) bool {
		var loopBody *ast.BlockStmt
		switch v := n.(type) {
		case *ast.ForStmt:
			loopBody = v.Body
		case *ast.RangeStmt:
			loopBody = v.Body
		default:
			return true
		}
		if loopBody == nil {
			return true
		}
		for _, stmt := range loopBody.List {
			if _, ok := stmt.(*ast.DeferStmt); ok {
				pos := fset.Position(stmt.Pos())
				*findings = append(*findings, domainanalysis.ConcurrencyFinding{
					Type:        "defer_in_loop",
					File:        file,
					Line:        pos.Line,
					Description: "defer inside loop – deferred calls accumulate until function returns",
					Severity:    "medium",
					Suggestion:  "Use an immediately-invoked function or move defer outside the loop",
				})
			}
		}
		return true
	})
}

// ---------------------------------------------------------------------------
// 11. DetectAPIBreakingChanges
// ---------------------------------------------------------------------------

// APIBreakingResult is returned by DetectAPIBreakingChanges.
type APIBreakingResult struct {
	RemovedExports    []domainanalysis.ExportedSymbol `json:"removed_exports"`
	ChangedSignatures []SignatureChange               `json:"changed_signatures"`
	AddedExports      []domainanalysis.ExportedSymbol `json:"added_exports"`
	Breaking          bool                            `json:"breaking"`
}

// SignatureChange records a changed exported function signature.
type SignatureChange struct {
	Name   string `json:"name"`
	OldSig string `json:"old_signature"`
	NewSig string `json:"new_signature"`
}

// DetectAPIBreakingChanges compares exported API between HEAD and baseRef.
func (s *Service) DetectAPIBreakingChanges(ctx context.Context, path, baseRef string) (*APIBreakingResult, error) {
	// Get list of .go files changed vs base
	changedOut, err := runGit(ctx, path, "diff", "--name-only", baseRef+"...HEAD")
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}

	var changedFiles []string
	for _, line := range strings.Split(changedOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, ".go") && !strings.HasSuffix(line, "_test.go") {
			changedFiles = append(changedFiles, line)
		}
	}

	// Extract current exported symbols
	currentSymbols := s.extractExportedSymbols(path, changedFiles)

	// Extract base exported symbols using git show
	baseSymbols := map[string]domainanalysis.ExportedSymbol{}
	for _, relFile := range changedFiles {
		content, gitErr := runGit(ctx, path, "show", baseRef+":"+relFile)
		if gitErr != nil {
			continue
		}
		syms := extractSymbolsFromContent(content, relFile)
		for _, sym := range syms {
			baseSymbols[sym.Name+":"+sym.Kind] = sym
		}
	}

	currentMap := map[string]domainanalysis.ExportedSymbol{}
	for _, sym := range currentSymbols {
		currentMap[sym.Name+":"+sym.Kind] = sym
	}

	var removed, added []domainanalysis.ExportedSymbol
	var changed []SignatureChange

	for key, baseSym := range baseSymbols {
		if curSym, ok := currentMap[key]; !ok {
			removed = append(removed, baseSym)
		} else if baseSym.Signature != curSym.Signature {
			changed = append(changed, SignatureChange{
				Name:   baseSym.Name,
				OldSig: baseSym.Signature,
				NewSig: curSym.Signature,
			})
		}
	}
	for key, curSym := range currentMap {
		if _, ok := baseSymbols[key]; !ok {
			added = append(added, curSym)
		}
	}

	breaking := len(removed) > 0 || len(changed) > 0

	return &APIBreakingResult{
		RemovedExports:    removed,
		ChangedSignatures: changed,
		AddedExports:      added,
		Breaking:          breaking,
	}, nil
}

func (s *Service) extractExportedSymbols(path string, relFiles []string) []domainanalysis.ExportedSymbol {
	fset := token.NewFileSet()
	var symbols []domainanalysis.ExportedSymbol

	for _, relFile := range relFiles {
		fullPath := filepath.Join(path, relFile)
		f, err := parser.ParseFile(fset, fullPath, nil, 0)
		if err != nil {
			continue
		}
		syms := extractSymbolsFromAST(fset, f, relFile)
		symbols = append(symbols, syms...)
	}
	return symbols
}

func extractSymbolsFromContent(content, relFile string) []domainanalysis.ExportedSymbol {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, relFile, content, 0)
	if err != nil {
		return nil
	}
	return extractSymbolsFromAST(fset, f, relFile)
}

func extractSymbolsFromAST(fset *token.FileSet, f *ast.File, relFile string) []domainanalysis.ExportedSymbol {
	var symbols []domainanalysis.ExportedSymbol
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name == nil || !ast.IsExported(node.Name.Name) {
				return true
			}
			pos := fset.Position(node.Pos())
			sig := funcSignature(node)
			symbols = append(symbols, domainanalysis.ExportedSymbol{
				Name:      node.Name.Name,
				Kind:      "func",
				File:      relFile,
				Line:      pos.Line,
				Signature: sig,
			})
		case *ast.TypeSpec:
			if !ast.IsExported(node.Name.Name) {
				return true
			}
			pos := fset.Position(node.Pos())
			symbols = append(symbols, domainanalysis.ExportedSymbol{
				Name: node.Name.Name,
				Kind: "type",
				File: relFile,
				Line: pos.Line,
			})
		}
		return true
	})
	return symbols
}

func funcSignature(fn *ast.FuncDecl) string {
	if fn.Type == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("func ")
	if fn.Name != nil {
		sb.WriteString(fn.Name.Name)
	}
	sb.WriteString("(")
	if fn.Type.Params != nil {
		writeFieldList(&sb, fn.Type.Params)
	}
	sb.WriteString(")")
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		sb.WriteString(" (")
		writeFieldList(&sb, fn.Type.Results)
		sb.WriteString(")")
	}
	return sb.String()
}

func writeFieldList(sb *strings.Builder, fl *ast.FieldList) {
	for i, field := range fl.List {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(sb, "%T", field.Type)
	}
}

// ---------------------------------------------------------------------------
// 12. GenerateSecurityAudit
// ---------------------------------------------------------------------------

// SecurityAuditResult is returned by GenerateSecurityAudit.
type SecurityAuditResult struct {
	Findings       []domainanalysis.SecurityAuditFinding `json:"findings"`
	SummaryByOWASP map[string]int                        `json:"summary_by_owasp"`
}

// owaspMap maps gosec rule IDs to OWASP 2021 categories.
var owaspMap = map[string]string{
	"G101": "A07:2021 - Identification and Authentication Failures",
	"G201": "A03:2021 - Injection",
	"G202": "A03:2021 - Injection",
	"G104": "A05:2021 - Security Misconfiguration",
	"G304": "A05:2021 - Security Misconfiguration",
	"G305": "A05:2021 - Security Misconfiguration",
	"G401": "A02:2021 - Cryptographic Failures",
	"G402": "A02:2021 - Cryptographic Failures",
	"G501": "A02:2021 - Cryptographic Failures",
	"G502": "A02:2021 - Cryptographic Failures",
	"G503": "A02:2021 - Cryptographic Failures",
	"G504": "A02:2021 - Cryptographic Failures",
	"G505": "A02:2021 - Cryptographic Failures",
}

var cweMap = map[string]string{
	"G101": "CWE-798",
	"G201": "CWE-89",
	"G202": "CWE-89",
	"G104": "CWE-391",
	"G304": "CWE-22",
	"G305": "CWE-22",
	"G401": "CWE-327",
	"G402": "CWE-295",
	"G501": "CWE-327",
}

var cvssMap = map[string]float64{
	"G101": 9.1,
	"G201": 9.8,
	"G202": 9.8,
	"G104": 5.3,
	"G304": 7.5,
	"G305": 7.5,
	"G401": 7.4,
	"G402": 7.4,
	"G501": 7.4,
}

var remediationMap = map[string]string{
	"G101": "Remove hardcoded credentials. Use environment variables or secrets managers.",
	"G201": "Use parameterized queries or prepared statements.",
	"G202": "Use parameterized queries or prepared statements.",
	"G104": "Always check and handle returned errors explicitly.",
	"G304": "Validate and sanitize file paths. Use filepath.Clean and enforce base directory.",
	"G305": "Validate and sanitize file paths. Use filepath.Clean and enforce base directory.",
	"G401": "Replace weak hash (MD5/SHA1) with SHA-256 or SHA-3.",
	"G402": "Set InsecureSkipVerify to false and provide a valid certificate.",
	"G501": "Replace crypto/md5 with crypto/sha256 or stronger.",
}

// gosecAuditOutput is the JSON from gosec -fmt json.
type gosecAuditOutput struct {
	Issues []struct {
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Details  string `json:"details"`
		File     string `json:"file"`
		Line     string `json:"line"`
	} `json:"Issues"`
}

// GenerateSecurityAudit runs gosec and maps findings to OWASP/CWE taxonomy.
func (s *Service) GenerateSecurityAudit(ctx context.Context, path string) (*SecurityAuditResult, error) {
	//nolint:gosec
	cmd := exec.CommandContext(ctx, "gosec", "-fmt", "json", "-nosec", "-quiet", "./...")
	cmd.Dir = path
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()

	var raw gosecAuditOutput
	_ = json.Unmarshal(stdout.Bytes(), &raw)

	auditFindings := make([]domainanalysis.SecurityAuditFinding, 0, len(raw.Issues))
	summaryByOWASP := map[string]int{}

	for _, issue := range raw.Issues {
		line, _ := strconv.Atoi(issue.Line)
		owasp := owaspMap[issue.RuleID]
		if owasp == "" {
			owasp = "Uncategorized"
		}
		cwe := cweMap[issue.RuleID]
		if cwe == "" {
			cwe = "CWE-0"
		}
		cvss := cvssMap[issue.RuleID]
		rem := remediationMap[issue.RuleID]
		if rem == "" {
			rem = "Review the finding and apply appropriate security controls."
		}

		auditFindings = append(auditFindings, domainanalysis.SecurityAuditFinding{
			RuleID:       issue.RuleID,
			Description:  issue.Details,
			Severity:     strings.ToLower(issue.Severity),
			File:         issue.File,
			Line:         line,
			OWASP:        owasp,
			CWE:          cwe,
			CVSSEstimate: cvss,
			Remediation:  rem,
		})
		summaryByOWASP[owasp]++
	}

	return &SecurityAuditResult{
		Findings:       auditFindings,
		SummaryByOWASP: summaryByOWASP,
	}, nil
}

// ---------------------------------------------------------------------------
// 13. GetRepositoryHealthScore
// ---------------------------------------------------------------------------

// HealthScore is returned by GetRepositoryHealthScore.
type HealthScore struct {
	Overall         int            `json:"overall"`
	Breakdown       map[string]int `json:"breakdown"`
	Recommendations []string       `json:"recommendations"`
}

// GetRepositoryHealthScore computes a 0-100 health score.
func (s *Service) GetRepositoryHealthScore(ctx context.Context, path string) (*HealthScore, error) {
	// Run analyzers
	agg, err := s.analysisSvc.AnalyzeRepository(ctx, appanalysis.AnalyzeRepositoryCommand{
		Path:   path,
		Format: "json",
	})
	if err != nil {
		return nil, fmt.Errorf("analyzing repository: %w", err)
	}

	bySeverity := map[string]int{}
	secFindings := 0
	for _, f := range agg.AllFindings() {
		bySeverity[string(f.Severity)]++
		if f.Category == domainanalysis.CategorySecurity {
			secFindings++
		}
	}

	// Security score
	secScore := 100 - (bySeverity["critical"]*20 + bySeverity["high"]*10 + bySeverity["medium"]*3)
	if secScore < 0 {
		secScore = 0
	}

	// Complexity score
	complexReport, complexErr := s.GenerateComplexityReport(ctx, path, 20)
	maintScore := 100
	if complexErr == nil && complexReport.Summary.AvgComplexity > 0 {
		// avg complexity > 10 starts reducing score
		reduction := int((complexReport.Summary.AvgComplexity - 5) * 5)
		if reduction < 0 {
			reduction = 0
		}
		maintScore = 100 - reduction
		if maintScore < 0 {
			maintScore = 0
		}
	}

	// Architecture score
	archResult, archErr := s.DetectArchitecturalSmells(ctx, path)
	archScore := 100
	if archErr == nil {
		archScore = 100 - len(archResult.Findings)*5
		if archScore < 0 {
			archScore = 0
		}
	}

	// Testing score: check for test files
	testScore := 0
	goFiles, _ := collectGoFiles(path)
	testCount := 0
	nonTestCount := 0
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") {
			testCount++
		} else {
			nonTestCount++
		}
	}
	if nonTestCount > 0 {
		ratio := float64(testCount) / float64(nonTestCount)
		testScore = int(ratio * 100)
		if testScore > 100 {
			testScore = 100
		}
	}

	// Performance score
	perfResult, perfErr := s.DetectPerformanceIssues(ctx, path)
	perfScore := 100
	if perfErr == nil {
		perfScore = 100 - len(perfResult.Findings)*5
		if perfScore < 0 {
			perfScore = 0
		}
	}

	// Overall weighted average
	overall := (secScore*30 + maintScore*20 + archScore*15 + testScore*20 + perfScore*15) / 100

	var recs []string
	if secScore < 70 {
		recs = append(recs, "Address security findings to improve security score.")
	}
	if maintScore < 70 {
		recs = append(recs, "Reduce cyclomatic complexity in complex functions.")
	}
	if testScore < 50 {
		recs = append(recs, "Add more test files to improve test coverage score.")
	}
	if archScore < 70 {
		recs = append(recs, "Refactor large files/interfaces to improve architecture score.")
	}

	return &HealthScore{
		Overall: overall,
		Breakdown: map[string]int{
			"security":        secScore,
			"maintainability": maintScore,
			"architecture":    archScore,
			"testing":         testScore,
			"performance":     perfScore,
			"complexity":      maintScore,
		},
		Recommendations: recs,
	}, nil
}

// ---------------------------------------------------------------------------
// 14. GetRepositoryFingerprint
// ---------------------------------------------------------------------------

// RepositoryFingerprint is returned by GetRepositoryFingerprint.
type RepositoryFingerprint struct {
	Module              string   `json:"module"`
	GoVersion           string   `json:"go_version"`
	ProjectType         string   `json:"project_type"`
	ArchitecturePattern string   `json:"architecture_pattern"`
	WebFramework        []string `json:"web_framework"`
	ORM                 []string `json:"orm"`
	Cache               []string `json:"cache"`
	Queue               []string `json:"queue"`
	Logging             []string `json:"logging"`
	Observability       []string `json:"observability"`
	CI                  []string `json:"ci"`
	Containerized       bool     `json:"containerized"`
	Deployment          []string `json:"deployment"`
}

// GetRepositoryFingerprint detects the technology stack used by the project.
func (s *Service) GetRepositoryFingerprint(ctx context.Context, path string) (*RepositoryFingerprint, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "get_repository_fingerprint started", slog.String("path", path))

	// Parse go.mod
	goModData, err := os.ReadFile(filepath.Join(path, "go.mod")) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	moduleName, goVersion := parseGoMod(string(goModData))

	// Collect all imports across go files
	goFiles, _ := collectGoFiles(path)
	fset := token.NewFileSet()
	allImports := map[string]bool{}
	packageDirs := map[string]bool{}

	for _, filePath := range goFiles {
		f, parseErr := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
		if parseErr != nil {
			continue
		}
		for _, imp := range f.Imports {
			path2 := strings.Trim(imp.Path.Value, `"`)
			allImports[path2] = true
		}
		packageDirs[filepath.Dir(relPath(path, filePath))] = true
	}

	// Detect frameworks
	webFrameworks := detectPatterns(allImports, map[string]string{
		"github.com/gin-gonic/gin": "gin",
		"github.com/go-chi/chi":    "chi",
		"github.com/labstack/echo": "echo",
		"github.com/gofiber/fiber": "fiber",
		"github.com/gorilla/mux":   "gorilla/mux",
		"net/http":                 "net/http",
	})
	orms := detectPatterns(allImports, map[string]string{
		"gorm.io/gorm":            "gorm",
		"github.com/uptrace/bun":  "bun",
		"entgo.io/ent":            "ent",
		"github.com/jmoiron/sqlx": "sqlx",
		"database/sql":            "database/sql",
	})
	caches := detectPatterns(allImports, map[string]string{
		"github.com/redis/go-redis":      "redis",
		"github.com/go-redis/redis":      "redis",
		"github.com/bradfitz/gomemcache": "memcache",
		"github.com/allegro/bigcache":    "bigcache",
	})
	queues := detectPatterns(allImports, map[string]string{
		"github.com/IBM/sarama":          "kafka",
		"github.com/Shopify/sarama":      "kafka",
		"github.com/nats-io/nats.go":     "nats",
		"github.com/rabbitmq/amqp091-go": "rabbitmq",
		"github.com/streadway/amqp":      "rabbitmq",
		"github.com/nsqio/go-nsq":        "nsq",
	})
	logging := detectPatterns(allImports, map[string]string{
		"log/slog":                   "slog",
		"go.uber.org/zap":            "zap",
		"github.com/sirupsen/logrus": "logrus",
		"github.com/rs/zerolog":      "zerolog",
	})
	observability := detectPatterns(allImports, map[string]string{
		"go.opentelemetry.io/otel":            "opentelemetry",
		"github.com/prometheus/client_golang": "prometheus",
		"github.com/jaegertracing/jaeger":     "jaeger",
		"github.com/DataDog/datadog-go":       "datadog",
	})

	// Detect CI
	var ci []string
	if _, err2 := os.Stat(filepath.Join(path, ".github", "workflows")); err2 == nil {
		ci = append(ci, "github-actions")
	}
	if _, err2 := os.Stat(filepath.Join(path, ".gitlab-ci.yml")); err2 == nil {
		ci = append(ci, "gitlab-ci")
	}
	if _, err2 := os.Stat(filepath.Join(path, "Jenkinsfile")); err2 == nil {
		ci = append(ci, "jenkins")
	}

	// Containerized
	_, dockerfileErr := os.Stat(filepath.Join(path, "Dockerfile"))
	_, composeErr := os.Stat(filepath.Join(path, "docker-compose.yml"))
	containerized := dockerfileErr == nil || composeErr == nil

	// Deployment
	var deployment []string
	if dockerfileErr == nil {
		deployment = append(deployment, "docker")
	}
	if _, err2 := os.Stat(filepath.Join(path, "helm")); err2 == nil {
		deployment = append(deployment, "helm")
	}
	if _, err2 := os.Stat(filepath.Join(path, "deploy")); err2 == nil {
		deployment = append(deployment, "kubernetes")
	}

	// Architecture pattern
	archPattern := detectArchPattern(packageDirs)

	// Project type
	projectType := "library"
	if _, err2 := os.Stat(filepath.Join(path, "cmd")); err2 == nil {
		projectType = "application"
	}

	return &RepositoryFingerprint{
		Module:              moduleName,
		GoVersion:           goVersion,
		ProjectType:         projectType,
		ArchitecturePattern: archPattern,
		WebFramework:        webFrameworks,
		ORM:                 orms,
		Cache:               caches,
		Queue:               queues,
		Logging:             logging,
		Observability:       observability,
		CI:                  ci,
		Containerized:       containerized,
		Deployment:          deployment,
	}, nil
}

func detectPatterns(imports map[string]bool, patterns map[string]string) []string {
	found := map[string]bool{}
	for imp := range imports {
		for prefix, label := range patterns {
			if imp == prefix || strings.HasPrefix(imp, prefix+"/") || strings.HasPrefix(imp, prefix) {
				found[label] = true
			}
		}
	}
	result := make([]string, 0, len(found))
	for label := range found {
		result = append(result, label)
	}
	sort.Strings(result)
	return result
}

func detectArchPattern(packageDirs map[string]bool) string {
	hasHexagonal := false
	hasCleanArch := false
	for dir := range packageDirs {
		parts := strings.Split(dir, string(os.PathSeparator))
		for _, part := range parts {
			switch part {
			case "domain", "adapters", "ports":
				hasHexagonal = true
			case "usecase", "repository", "handler":
				hasCleanArch = true
			}
		}
	}
	if hasHexagonal {
		return "hexagonal"
	}
	if hasCleanArch {
		return "clean"
	}
	return "standard"
}

// ---------------------------------------------------------------------------
// 15. GenerateKnowledgeGraph
// ---------------------------------------------------------------------------

// KnowledgeGraphResult is returned by GenerateKnowledgeGraph.
type KnowledgeGraphResult struct {
	Format    string                     `json:"format"`
	Graph     string                     `json:"graph"`
	Nodes     []domainanalysis.GraphNode `json:"nodes,omitempty"`
	Edges     []domainanalysis.GraphEdge `json:"edges,omitempty"`
	NodeCount int                        `json:"node_count"`
	EdgeCount int                        `json:"edge_count"`
}

// goListPackage is the JSON shape of `go list -json ./...`.
type goListPackage struct {
	ImportPath string   `json:"ImportPath"`
	Imports    []string `json:"Imports"`
}

// GenerateKnowledgeGraph builds a package dependency graph.
func (s *Service) GenerateKnowledgeGraph(ctx context.Context, path, format string) (*KnowledgeGraphResult, error) {
	moduleName, _ := parseGoMod(readFileString(filepath.Join(path, "go.mod")))

	//nolint:gosec
	cmd := exec.CommandContext(ctx, "go", "list", "-json", "./...")
	cmd.Dir = path
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()

	nodes := map[string]bool{}
	var edges []domainanalysis.GraphEdge

	decoder := json.NewDecoder(&stdout)
	for decoder.More() {
		var pkg goListPackage
		if err := decoder.Decode(&pkg); err != nil {
			break
		}
		if !strings.HasPrefix(pkg.ImportPath, moduleName) {
			continue
		}
		nodes[pkg.ImportPath] = true
		for _, imp := range pkg.Imports {
			if strings.HasPrefix(imp, moduleName) {
				nodes[imp] = true
				edges = append(edges, domainanalysis.GraphEdge{From: pkg.ImportPath, To: imp})
			}
		}
	}

	nodeList := make([]domainanalysis.GraphNode, 0, len(nodes))
	for imp := range nodes {
		label := strings.TrimPrefix(imp, moduleName+"/")
		nodeList = append(nodeList, domainanalysis.GraphNode{ID: imp, Label: label})
	}
	sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].ID < nodeList[j].ID })

	var graph string
	if format == "json" {
		data, _ := json.MarshalIndent(map[string]any{
			"nodes": nodeList,
			"edges": edges,
		}, "", "  ")
		graph = string(data)
	} else {
		graph = buildMermaidGraph(nodeList, edges, moduleName)
	}

	return &KnowledgeGraphResult{
		Format:    format,
		Graph:     graph,
		Nodes:     nodeList,
		Edges:     edges,
		NodeCount: len(nodeList),
		EdgeCount: len(edges),
	}, nil
}

func buildMermaidGraph(nodes []domainanalysis.GraphNode, edges []domainanalysis.GraphEdge, moduleName string) string {
	var sb strings.Builder
	sb.WriteString("graph TD\n")
	for _, e := range edges {
		from := mermaidID(strings.TrimPrefix(e.From, moduleName+"/"))
		to := mermaidID(strings.TrimPrefix(e.To, moduleName+"/"))
		fromLabel := strings.TrimPrefix(e.From, moduleName+"/")
		toLabel := strings.TrimPrefix(e.To, moduleName+"/")
		sb.WriteString(fmt.Sprintf("  %s[%s] --> %s[%s]\n", from, fromLabel, to, toLabel))
	}
	_ = nodes // nodes are implicit in edges
	return sb.String()
}

func mermaidID(s string) string {
	return strings.NewReplacer("/", "_", "-", "_", ".", "_").Replace(s)
}

// ---------------------------------------------------------------------------
// 16. GenerateCallGraph
// ---------------------------------------------------------------------------

// CallGraphResult is returned by GenerateCallGraph.
type CallGraphResult struct {
	Format         string                     `json:"format"`
	Graph          string                     `json:"graph"`
	EntryPoints    []string                   `json:"entry_points"`
	TotalFunctions int                        `json:"total_functions"`
	Nodes          []domainanalysis.GraphNode `json:"nodes,omitempty"`
	Edges          []domainanalysis.GraphEdge `json:"edges,omitempty"`
}

// GenerateCallGraph builds an intra-module function call graph.
func (s *Service) GenerateCallGraph(ctx context.Context, path, packagePattern, format string) (*CallGraphResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "generate_call_graph started", slog.String("path", path))

	goFiles, err := collectGoFiles(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	// Map: caller -> set of callees
	callMap := map[string]map[string]bool{}
	_ = packagePattern

	for _, filePath := range goFiles {
		f, parseErr := parser.ParseFile(fset, filePath, nil, 0)
		if parseErr != nil {
			continue
		}

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				return true
			}
			callerName := fn.Name.Name
			if _, exists := callMap[callerName]; !exists {
				callMap[callerName] = map[string]bool{}
			}

			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				}
				if callee != "" {
					callMap[callerName][callee] = true
				}
				return true
			})
			return true
		})
	}

	// Build node/edge lists; limit to top 50 by out-degree
	type nodeEdge struct {
		name   string
		degree int
	}
	nodeEdges := make([]nodeEdge, 0, len(callMap))
	for name, callees := range callMap {
		nodeEdges = append(nodeEdges, nodeEdge{name, len(callees)})
	}
	sort.Slice(nodeEdges, func(i, j int) bool { return nodeEdges[i].degree > nodeEdges[j].degree })
	if len(nodeEdges) > 50 {
		nodeEdges = nodeEdges[:50]
	}
	topSet := map[string]bool{}
	for _, ne := range nodeEdges {
		topSet[ne.name] = true
	}

	nodes := make([]domainanalysis.GraphNode, 0, len(topSet))
	edges := make([]domainanalysis.GraphEdge, 0, len(topSet))
	for name := range topSet {
		nodes = append(nodes, domainanalysis.GraphNode{ID: name, Label: name})
		for callee := range callMap[name] {
			if topSet[callee] {
				edges = append(edges, domainanalysis.GraphEdge{From: name, To: callee})
			}
		}
	}

	// Entry points = exported functions
	var entryPoints []string
	for name := range topSet {
		if len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z' {
			entryPoints = append(entryPoints, name)
		}
	}
	sort.Strings(entryPoints)

	var graph string
	if format == "json" {
		data, _ := json.MarshalIndent(map[string]any{"nodes": nodes, "edges": edges}, "", "  ")
		graph = string(data)
	} else {
		var sb strings.Builder
		sb.WriteString("graph TD\n")
		for _, e := range edges {
			sb.WriteString(fmt.Sprintf("  %s --> %s\n", e.From, e.To))
		}
		graph = sb.String()
	}

	return &CallGraphResult{
		Format:         format,
		Graph:          graph,
		EntryPoints:    entryPoints,
		TotalFunctions: len(callMap),
		Nodes:          nodes,
		Edges:          edges,
	}, nil
}

// ---------------------------------------------------------------------------
// 17. AnalyzeImpact
// ---------------------------------------------------------------------------

// ImpactResult is returned by AnalyzeImpact.
type ImpactResult struct {
	Symbol            string                        `json:"symbol"`
	Package           string                        `json:"package"`
	DirectCallers     []domainanalysis.EvidenceItem `json:"direct_callers"`
	AffectedPackages  []string                      `json:"affected_packages"`
	AffectedTestFiles []string                      `json:"affected_test_files"`
	ImpactScore       int                           `json:"impact_score"`
}

// AnalyzeImpact finds all references to a symbol across the codebase.
func (s *Service) AnalyzeImpact(ctx context.Context, path, symbol, packagePath string) (*ImpactResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "analyze_impact started", slog.String("symbol", symbol))

	goFiles, err := collectGoFiles(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	var callers []domainanalysis.EvidenceItem
	affectedPkgs := map[string]bool{}
	var testFiles []string

	for _, filePath := range goFiles {
		data, readErr := os.ReadFile(filePath) //nolint:gosec
		if readErr != nil {
			continue
		}
		f, parseErr := parser.ParseFile(fset, filePath, data, 0)
		if parseErr != nil {
			continue
		}
		rel := relPath(path, filePath)
		pkgDir := filepath.Dir(rel)

		lines := strings.Split(string(data), "\n")

		ast.Inspect(f, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok || ident.Name != symbol {
				return true
			}
			pos := fset.Position(ident.Pos())
			lineIdx := pos.Line - 1
			snippet := ""
			if lineIdx >= 0 && lineIdx < len(lines) {
				snippet = strings.TrimSpace(lines[lineIdx])
			}
			callers = append(callers, domainanalysis.EvidenceItem{
				File:    rel,
				Line:    pos.Line,
				Snippet: snippet,
			})
			affectedPkgs[pkgDir] = true
			if strings.HasSuffix(filePath, "_test.go") {
				testFiles = append(testFiles, rel)
			}
			return true
		})
	}

	// Deduplicate test files
	testFileSet := map[string]bool{}
	var uniqueTestFiles []string
	for _, tf := range testFiles {
		if !testFileSet[tf] {
			testFileSet[tf] = true
			uniqueTestFiles = append(uniqueTestFiles, tf)
		}
	}

	pkgList := make([]string, 0, len(affectedPkgs))
	for pkg := range affectedPkgs {
		pkgList = append(pkgList, pkg)
	}
	sort.Strings(pkgList)

	// Deduplicate callers by file:line
	seen := map[string]bool{}
	var uniqueCallers []domainanalysis.EvidenceItem
	for _, c := range callers {
		key := fmt.Sprintf("%s:%d", c.File, c.Line)
		if !seen[key] {
			seen[key] = true
			uniqueCallers = append(uniqueCallers, c)
		}
	}

	impactScore := len(uniqueCallers)*10 + len(pkgList)*20

	return &ImpactResult{
		Symbol:            symbol,
		Package:           packagePath,
		DirectCallers:     uniqueCallers,
		AffectedPackages:  pkgList,
		AffectedTestFiles: uniqueTestFiles,
		ImpactScore:       impactScore,
	}, nil
}

// ---------------------------------------------------------------------------
// 18. AskRepository
// ---------------------------------------------------------------------------

// AskRepositoryResult is returned by AskRepository.
type AskRepositoryResult struct {
	Question string                        `json:"question"`
	Answer   string                        `json:"answer"`
	Evidence []domainanalysis.EvidenceItem `json:"evidence"`
}

// AskRepository answers natural language questions about the codebase.
func (s *Service) AskRepository(ctx context.Context, path, question string) (*AskRepositoryResult, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	log.InfoContext(ctx, "ask_repository", slog.String("question", question))

	q := strings.ToLower(question)
	var answer string
	var evidence []domainanalysis.EvidenceItem

	switch {
	case containsAny(q, "http route", "route", "handlefunc", "get ", "post ", "put ", "delete "):
		answer, evidence = s.findHTTPRoutes(ctx, path)
	case containsAny(q, "interface"):
		answer, evidence = s.findInterfaces(ctx, path)
	case containsAny(q, "database", "sql", "query", "db.", "db call"):
		answer, evidence = s.findDatabaseCalls(ctx, path)
	case containsAny(q, "middleware"):
		answer, evidence = s.findMiddleware(ctx, path)
	case containsAny(q, "auth", "authentication", "authorization"):
		answer, evidence = s.findAuthPatterns(ctx, path)
	case containsAny(q, "initializ", "new", "create"):
		symbol := extractSymbolFromQuestion(question)
		if symbol != "" {
			answer, evidence = s.findInitializations(ctx, path, symbol)
		} else {
			answer = "Could not extract a symbol name from the question. Please specify the symbol (e.g. 'Where is MyService initialized?')"
		}
	default:
		// General grep-based search
		keyword := extractKeyword(question)
		answer, evidence = s.grepForKeyword(path, keyword)
	}

	return &AskRepositoryResult{
		Question: question,
		Answer:   answer,
		Evidence: evidence,
	}, nil
}

func (s *Service) findHTTPRoutes(ctx context.Context, path string) (string, []domainanalysis.EvidenceItem) {
	patterns := []string{"HandleFunc", ".GET(", ".POST(", ".PUT(", ".DELETE(", ".PATCH(", ".Handle("}
	return s.searchPatterns(ctx, path, patterns, "HTTP routes")
}

func (s *Service) findInterfaces(_ context.Context, path string) (string, []domainanalysis.EvidenceItem) {
	goFiles, _ := collectGoFiles(path)
	fset := token.NewFileSet()
	var evidence []domainanalysis.EvidenceItem

	for _, filePath := range goFiles {
		data, err := os.ReadFile(filePath) //nolint:gosec
		if err != nil {
			continue
		}
		f, err := parser.ParseFile(fset, filePath, data, 0)
		if err != nil {
			continue
		}
		rel := relPath(path, filePath)
		lines := strings.Split(string(data), "\n")

		ast.Inspect(f, func(n ast.Node) bool {
			typeSpec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			if _, isInterface := typeSpec.Type.(*ast.InterfaceType); isInterface {
				pos := fset.Position(typeSpec.Pos())
				lineIdx := pos.Line - 1
				snippet := ""
				if lineIdx >= 0 && lineIdx < len(lines) {
					snippet = strings.TrimSpace(lines[lineIdx])
				}
				evidence = append(evidence, domainanalysis.EvidenceItem{
					File:    rel,
					Line:    pos.Line,
					Snippet: fmt.Sprintf("interface %s", typeSpec.Name.Name) + " { " + snippet + " }",
				})
			}
			return true
		})
	}

	answer := fmt.Sprintf("Found %d interface declarations.", len(evidence))
	return answer, evidence
}

func (s *Service) findDatabaseCalls(ctx context.Context, path string) (string, []domainanalysis.EvidenceItem) {
	patterns := []string{"sql.Query", "sql.Exec", "db.Query", "db.Exec", "db.Get(", "db.Select(", ".Raw(", ".Find(", ".Create(", ".Save("}
	return s.searchPatterns(ctx, path, patterns, "database calls")
}

func (s *Service) findMiddleware(ctx context.Context, path string) (string, []domainanalysis.EvidenceItem) {
	patterns := []string{"Use(", "With(", "Middleware(", "middleware", ".Handler("}
	return s.searchPatterns(ctx, path, patterns, "middleware registrations")
}

func (s *Service) findAuthPatterns(ctx context.Context, path string) (string, []domainanalysis.EvidenceItem) {
	patterns := []string{"auth", "jwt", "token", "Authorization", "Bearer ", "authenticate", "authorize"}
	return s.searchPatterns(ctx, path, patterns, "authentication/authorization patterns")
}

func (s *Service) findInitializations(_ context.Context, path, symbol string) (string, []domainanalysis.EvidenceItem) {
	goFiles, _ := collectGoFiles(path)
	fset := token.NewFileSet()
	var evidence []domainanalysis.EvidenceItem

	for _, filePath := range goFiles {
		data, err := os.ReadFile(filePath) //nolint:gosec
		if err != nil {
			continue
		}
		f, parseErr := parser.ParseFile(fset, filePath, data, 0)
		if parseErr != nil {
			continue
		}
		rel := relPath(path, filePath)
		lines := strings.Split(string(data), "\n")

		ast.Inspect(f, func(n ast.Node) bool {
			// Look for: symbol := ..., var symbol ..., New+symbol, new(symbol)
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok && strings.EqualFold(ident.Name, symbol) {
						pos := fset.Position(node.Pos())
						lineIdx := pos.Line - 1
						snippet := ""
						if lineIdx >= 0 && lineIdx < len(lines) {
							snippet = strings.TrimSpace(lines[lineIdx])
						}
						evidence = append(evidence, domainanalysis.EvidenceItem{File: rel, Line: pos.Line, Snippet: snippet})
					}
				}
			case *ast.CallExpr:
				var callee string
				switch fun := node.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				}
				if strings.Contains(strings.ToLower(callee), strings.ToLower(symbol)) ||
					strings.HasPrefix(callee, "New") && strings.Contains(strings.ToLower(callee), strings.ToLower(symbol)) {
					pos := fset.Position(node.Pos())
					lineIdx := pos.Line - 1
					snippet := ""
					if lineIdx >= 0 && lineIdx < len(lines) {
						snippet = strings.TrimSpace(lines[lineIdx])
					}
					evidence = append(evidence, domainanalysis.EvidenceItem{File: rel, Line: pos.Line, Snippet: snippet})
				}
			}
			return true
		})
	}

	if len(evidence) == 0 {
		return fmt.Sprintf("No initializations of %q found.", symbol), evidence
	}
	return fmt.Sprintf("Found %d initialization(s) of %q.", len(evidence), symbol), evidence
}

func (s *Service) grepForKeyword(path, keyword string) (string, []domainanalysis.EvidenceItem) {
	goFiles, _ := collectGoFiles(path)
	var evidence []domainanalysis.EvidenceItem

	for _, filePath := range goFiles {
		data, err := os.ReadFile(filePath) //nolint:gosec
		if err != nil {
			continue
		}
		rel := relPath(path, filePath)
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
				evidence = append(evidence, domainanalysis.EvidenceItem{
					File:    rel,
					Line:    i + 1,
					Snippet: strings.TrimSpace(line),
				})
				if len(evidence) >= 20 {
					break
				}
			}
		}
		if len(evidence) >= 20 {
			break
		}
	}

	return fmt.Sprintf("Found %d occurrence(s) of %q.", len(evidence), keyword), evidence
}

func (s *Service) searchPatterns(_ context.Context, path string, patterns []string, description string) (string, []domainanalysis.EvidenceItem) {
	goFiles, _ := collectGoFiles(path)
	var evidence []domainanalysis.EvidenceItem

	for _, filePath := range goFiles {
		data, err := os.ReadFile(filePath) //nolint:gosec
		if err != nil {
			continue
		}
		rel := relPath(path, filePath)
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(line, pattern) {
					evidence = append(evidence, domainanalysis.EvidenceItem{
						File:    rel,
						Line:    i + 1,
						Snippet: strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}

	answer := fmt.Sprintf("Found %d %s.", len(evidence), description)
	return answer, evidence
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	//nolint:gosec
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w (stderr: %s)", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

func collectGoFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable
		}
		if info.IsDir() {
			// Skip vendor and hidden dirs
			base := filepath.Base(path)
			if base == "vendor" || (len(base) > 0 && base[0] == '.') {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(info.Name(), ".go") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func relPath(base, full string) string {
	rel, err := filepath.Rel(base, full)
	if err != nil {
		return full
	}
	return rel
}

func readFileString(path string) string {
	data, _ := os.ReadFile(path) //nolint:gosec
	return string(data)
}

func avgInt(vals []int) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0
	for _, v := range vals {
		sum += v
	}
	return float64(sum) / float64(len(vals))
}

func maxInt(vals []int) int {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func containsAny(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func extractSymbolFromQuestion(question string) string {
	words := strings.Fields(question)
	for _, word := range words {
		// Look for CamelCase words
		if len(word) > 2 && word[0] >= 'A' && word[0] <= 'Z' {
			word = strings.Trim(word, "?.,;:\"'")
			return word
		}
	}
	return ""
}

func extractKeyword(question string) string {
	// Remove common stop words and return the most meaningful word
	stopWords := map[string]bool{
		"what": true, "where": true, "how": true, "why": true,
		"is": true, "are": true, "does": true, "do": true,
		"the": true, "a": true, "an": true, "all": true,
		"show": true, "find": true, "list": true,
	}
	words := strings.Fields(strings.ToLower(question))
	for _, w := range words {
		w = strings.Trim(w, "?.,;:\"'")
		if !stopWords[w] && len(w) > 2 {
			return w
		}
	}
	return question
}
