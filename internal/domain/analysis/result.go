package analysis

import "time"

// Status represents the state of an analysis run.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Summary aggregates finding counts.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
	ByAnalyzer map[string]int `json:"by_analyzer"`
	Fixable    int            `json:"fixable"`
}

// Result represents the output of a single analyzer run.
type Result struct {
	ID        string        `json:"id"`
	Status    Status        `json:"status"`
	Target    Target        `json:"target"`
	Findings  []Finding     `json:"findings"`
	Analyzer  string        `json:"analyzer"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Duration  time.Duration `json:"duration_ns"`
	Error     string        `json:"error,omitempty"`
}

// AggregatedResult combines results from multiple analyzers for the same target.
type AggregatedResult struct {
	ID        string        `json:"id"`
	Target    Target        `json:"target"`
	Results   []Result      `json:"results"`
	Summary   Summary       `json:"summary"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Duration  time.Duration `json:"duration_ns"`
}

// AllFindings returns a flat slice of all findings across all results.
func (a *AggregatedResult) AllFindings() []Finding {
	var out []Finding
	for _, r := range a.Results {
		out = append(out, r.Findings...)
	}
	return out
}

// BuildSummary computes a Summary from a slice of Results.
func BuildSummary(results []Result) Summary {
	s := Summary{
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
		ByAnalyzer: make(map[string]int),
	}
	for _, r := range results {
		for _, f := range r.Findings {
			s.Total++
			s.BySeverity[string(f.Severity)]++
			s.ByCategory[string(f.Category)]++
			s.ByAnalyzer[f.Analyzer]++
			if f.Fixable {
				s.Fixable++
			}
		}
	}
	return s
}
