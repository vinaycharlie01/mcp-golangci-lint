package reporters

import (
	"context"
	"encoding/json"
	"fmt"

	domainanalysis "github.com/vinaycharlie01/mcp-golangci-lint/internal/domain/analysis"
)

// SARIFReporter renders analysis results in SARIF 2.1.0 format.
// SARIF is the industry-standard format for static analysis results,
// supported by GitHub Code Scanning and VS Code.
type SARIFReporter struct{}

// NewSARIF creates a SARIFReporter.
func NewSARIF() *SARIFReporter { return &SARIFReporter{} }

func (r *SARIFReporter) Format() string { return "sarif" }

type sarifRoot struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	Properties       map[string]string   `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// Render converts an AggregatedResult to a SARIF 2.1.0 document.
func (r *SARIFReporter) Render(_ context.Context, result *domainanalysis.AggregatedResult) ([]byte, error) {
	runs := make([]sarifRun, 0, len(result.Results))

	for _, res := range result.Results {
		ruleSet := make(map[string]sarifRule)
		sarResults := make([]sarifResult, 0, len(res.Findings))

		for _, f := range res.Findings {
			if _, exists := ruleSet[f.RuleID]; !exists {
				ruleSet[f.RuleID] = sarifRule{
					ID:               f.RuleID,
					Name:             f.RuleID,
					ShortDescription: sarifMessage{Text: fmt.Sprintf("%s rule %s", f.Analyzer, f.RuleID)},
					Properties:       map[string]string{"category": string(f.Category)},
				}
			}
			sarResults = append(sarResults, sarifResult{
				RuleID:  f.RuleID,
				Level:   severityToLevel(f.Severity),
				Message: sarifMessage{Text: f.Message},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: f.Location.File},
						Region: sarifRegion{
							StartLine:   f.Location.Line,
							StartColumn: f.Location.Column,
						},
					},
				}},
			})
		}

		rules := make([]sarifRule, 0, len(ruleSet))
		for _, rule := range ruleSet {
			rules = append(rules, rule)
		}

		runs = append(runs, sarifRun{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           res.Analyzer,
				Version:        "1.0.0",
				InformationURI: "https://github.com/vinaycharlie01/mcp-golangci-lint",
				Rules:          rules,
			}},
			Results: sarResults,
		})
	}

	doc := sarifRoot{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    runs,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func severityToLevel(s domainanalysis.Severity) string {
	switch s {
	case domainanalysis.SeverityCritical, domainanalysis.SeverityHigh:
		return "error"
	case domainanalysis.SeverityMedium:
		return "warning"
	case domainanalysis.SeverityLow, domainanalysis.SeverityInfo:
		return "note"
	}
	return "note"
}
