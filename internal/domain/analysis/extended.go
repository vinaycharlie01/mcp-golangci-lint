package analysis

// ArchSmellFinding describes a structural smell found in the codebase.
type ArchSmellFinding struct {
	Type        string `json:"type"`
	Location    string `json:"location"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Suggestion  string `json:"suggestion"`
}

// ComplexityEntry holds cyclomatic complexity data for a function.
type ComplexityEntry struct {
	Function   string `json:"function"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Complexity int    `json:"complexity"`
}

// FileComplexity holds aggregated complexity metrics for a file.
type FileComplexity struct {
	File          string  `json:"file"`
	AvgComplexity float64 `json:"avg_complexity"`
	MaxComplexity int     `json:"max_complexity"`
	FunctionCount int     `json:"function_count"`
}

// PotentiallyUnused describes a symbol that may be dead code.
type PotentiallyUnused struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

// PerfFinding describes a performance issue found via AST analysis.
type PerfFinding struct {
	Type        string `json:"type"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
	Severity    string `json:"severity"`
}

// ConcurrencyFinding describes a concurrency problem found via AST analysis.
type ConcurrencyFinding struct {
	Type        string `json:"type"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Suggestion  string `json:"suggestion"`
}

// ExportedSymbol holds information about an exported Go symbol.
type ExportedSymbol struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // func, type, var, const, method, field
	File      string `json:"file"`
	Line      int    `json:"line"`
	Signature string `json:"signature,omitempty"`
}

// SecurityAuditFinding maps a gosec finding to OWASP/CWE taxonomy.
type SecurityAuditFinding struct {
	RuleID       string  `json:"rule_id"`
	Description  string  `json:"description"`
	Severity     string  `json:"severity"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	OWASP        string  `json:"owasp"`
	CWE          string  `json:"cwe"`
	CVSSEstimate float64 `json:"cvss_estimate"`
	Remediation  string  `json:"remediation"`
}

// GraphNode is a node in a dependency or call graph.
type GraphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// GraphEdge is a directed edge between two nodes.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// EvidenceItem is a location+snippet found during repository Q&A.
type EvidenceItem struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// DependencyInfo holds information about a Go module dependency.
type DependencyInfo struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
	Latest   string `json:"latest,omitempty"`
}
