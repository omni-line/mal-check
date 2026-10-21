package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/omni-line/mal-check/internal/scan"
	"github.com/omni-line/mal-check/pkg/maldb"
)

// SchemaVersion is bumped only for breaking changes to the JSON document.
// Adding fields is not a breaking change.
const SchemaVersion = 1

// JSONDocument is the machine-readable report.
type JSONDocument struct {
	SchemaVersion int            `json:"schema_version"`
	Version       string         `json:"version"`
	Complete      bool           `json:"complete"`
	Findings      []scan.Finding `json:"findings"`
	Warnings      []scan.Warning `json:"warnings,omitempty"`
	Stats         scan.Stats     `json:"stats"`
	Database      maldb.Meta     `json:"database"`
	Sponsor       *Sponsor       `json:"sponsor,omitempty"`
}

func writeJSON(w io.Writer, res *scan.Result, opts Options) error {
	doc := JSONDocument{
		SchemaVersion: SchemaVersion,
		Version:       opts.Version,
		Complete:      res.Complete(),
		Findings:      res.Findings,
		Warnings:      res.Warnings,
		Stats:         res.Stats,
		Database:      res.Database,
	}
	if doc.Findings == nil {
		doc.Findings = []scan.Finding{}
	}
	if shouldShowMarketing(opts) {
		s := NewSponsor(len(res.Findings))
		doc.Sponsor = &s
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}
