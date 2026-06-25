package analysis

import "time"

// TargetType identifies what is being analyzed.
type TargetType string

const (
	TargetTypeRepository TargetType = "repository"
	TargetTypeFile       TargetType = "file"
)

// Target specifies what to analyze.
type Target struct {
	Type TargetType `json:"type"`
	Path string     `json:"path"`
}

// Options controls how analysis is performed.
type Options struct {
	Analyzers  []string          `json:"analyzers,omitempty"`
	Timeout    time.Duration     `json:"timeout,omitempty"`
	Format     string            `json:"format,omitempty"`
	Config     string            `json:"config,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// Repository describes a validated Go repository.
type Repository struct {
	Path     string `json:"path"`
	Module   string `json:"module,omitempty"`
	HasGoMod bool   `json:"has_go_mod"`
}
