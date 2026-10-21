// Package scan walks a project, parses every supported lockfile and manifest,
// and checks each package against the embedded malicious-package snapshot.
package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/omni-line/mal-check/internal/discover"
	"github.com/omni-line/mal-check/internal/manifest"
	"github.com/omni-line/mal-check/internal/match"
	"github.com/omni-line/mal-check/internal/parse"
	"github.com/omni-line/mal-check/pkg/maldb"
)

// Finding reasons.
const (
	// ReasonMalicious: the package (at this version, or at every version)
	// was published as malware.
	ReasonMalicious = "malicious"
	// ReasonCompromised: specific versions of this package were malware and
	// the installed version is not one of them.
	ReasonCompromised = "previously_compromised"
)

// Finding severities.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Warning kinds.
const (
	WarnWalk = "walk" // a path could not be walked or was skipped
	WarnFile = "file" // a lockfile or manifest could not be read or parsed
)

// Remediation is the default guidance for malicious findings.
const Remediation = "Remove the package, delete node_modules / virtualenvs / caches, and reinstall from a clean lockfile. " +
	"If it ran on a machine or in CI, treat that environment as compromised: rotate every secret and token it could read."

// RemediationCompromised is the guidance for previously compromised packages.
const RemediationCompromised = "Your version is not one of the malicious releases. Pin it in the lockfile so an update cannot pull a bad one, and check that CI never installed the listed versions."

// maxListedVersions caps the malicious versions copied into one finding.
const maxListedVersions = 10

// Finding is one package that matches the snapshot.
//
// ecosystem, package, version, manifest, reason, severity and ids are part of
// the stable JSON schema; other fields are additive.
type Finding struct {
	Ecosystem         string   `json:"ecosystem"`
	Package           string   `json:"package"`
	Version           string   `json:"version,omitempty"`
	Exact             bool     `json:"exact"`
	Manifest          string   `json:"manifest"`
	Line              int      `json:"line,omitempty"`
	Group             string   `json:"group,omitempty"`
	Reason            string   `json:"reason"`
	Severity          string   `json:"severity"`
	IDs               []string `json:"ids"`
	URL               string   `json:"url"`
	Registry          string   `json:"registry,omitempty"`
	Campaign          string   `json:"campaign,omitempty"`
	Finders           []string `json:"finders,omitempty"`
	Published         string   `json:"published,omitempty"`
	MaliciousVersions []string `json:"malicious_versions,omitempty"`
	Remediation       string   `json:"remediation,omitempty"`
}

// Warning is a non-fatal issue that may leave the scan incomplete.
type Warning struct {
	Kind     string `json:"kind"`
	Manifest string `json:"manifest"`
	Message  string `json:"message"`
}

// Stats summarizes a scan.
type Stats struct {
	// Files is the number of lockfiles and manifests parsed.
	Files int `json:"files"`
	// Lockfiles counts the files among them that record installed versions.
	Lockfiles int `json:"lockfiles"`
	// Packages counts package entries checked.
	Packages int `json:"packages"`
	// UniquePackages counts distinct ecosystem/name pairs checked.
	UniquePackages int `json:"unique_packages"`
	Findings       int `json:"findings"`
	// Skipped counts entries matched by --ignore, plus declarations already
	// covered by a lockfile entry for the same package.
	Skipped    int   `json:"skipped"`
	Errors     int   `json:"errors"`
	DurationMS int64 `json:"duration_ms"`
}

// Result is the full scan outcome.
type Result struct {
	Findings []Finding  `json:"findings"`
	Warnings []Warning  `json:"warnings,omitempty"`
	Stats    Stats      `json:"stats"`
	Database maldb.Meta `json:"database"`
}

// Complete reports whether every discovered file was parsed.
func (r *Result) Complete() bool {
	return len(r.Warnings) == 0
}

// Options configures Run.
type Options struct {
	// DB is the snapshot to check against; nil means maldb.Default().
	DB *maldb.DB
	// Kinds overrides the supported formats; nil means parse.Default().
	Kinds   []parse.Kind
	Ignore  *match.Matcher
	Exclude *match.Matcher
}

type parsedFile struct {
	rel  string
	kind *parse.Kind
	pkgs []parse.Package
}

// Run scans root, which may be a directory or a single supported file.
func Run(ctx context.Context, root string, opts Options) (*Result, error) {
	start := time.Now()
	db := opts.DB
	if db == nil {
		var err error
		if db, err = maldb.Default(); err != nil {
			return nil, err
		}
	}
	kinds := opts.Kinds
	if kinds == nil {
		kinds = parse.Default()
	}
	res := &Result{Database: db.Meta()}

	files, err := collect(root, kinds, opts.Exclude, res)
	if err != nil {
		return nil, err
	}

	var parsed []parsedFile
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := manifest.ReadFile(f.path)
		if err == nil {
			var pkgs []parse.Package
			if pkgs, err = parse.File(f.kind, f.rel, data); err == nil {
				parsed = append(parsed, parsedFile{rel: f.rel, kind: f.kind, pkgs: pkgs})
				res.Stats.Files++
				if f.kind.Lockfile {
					res.Stats.Lockfiles++
				}
				continue
			}
		}
		res.Warnings = append(res.Warnings, Warning{Kind: WarnFile, Manifest: f.rel, Message: err.Error()})
	}

	// Lockfile entries are what is installed; a declaration of a package the
	// lockfiles already pin adds nothing but a vaguer verdict.
	locked := map[string]bool{}
	for _, f := range parsed {
		if f.kind.Lockfile {
			for _, p := range f.pkgs {
				locked[key(p.Ecosystem, p.Name)] = true
			}
		}
	}
	sort.SliceStable(parsed, func(i, j int) bool {
		if parsed[i].kind.Lockfile != parsed[j].kind.Lockfile {
			return parsed[i].kind.Lockfile
		}
		return parsed[i].rel < parsed[j].rel
	})

	unique := map[string]bool{}
	for _, f := range parsed {
		for _, p := range f.pkgs {
			k := key(p.Ecosystem, p.Name)
			if opts.Ignore.Match(p.Name) || (!f.kind.Lockfile && locked[k]) {
				res.Stats.Skipped++
				continue
			}
			res.Stats.Packages++
			unique[k] = true
			if fd, ok := check(db, f.rel, p); ok {
				res.Findings = append(res.Findings, fd)
			}
		}
	}

	sortFindings(res.Findings)
	res.Stats.UniquePackages = len(unique)
	res.Stats.Findings = len(res.Findings)
	res.Stats.Errors = len(res.Warnings)
	res.Stats.DurationMS = time.Since(start).Milliseconds()
	return res, nil
}

type candidate struct {
	path, rel string
	kind      *parse.Kind
}

func collect(root string, kinds []parse.Kind, exclude *match.Matcher, res *Result) ([]candidate, error) {
	fi, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		rel := filepath.ToSlash(root)
		kind := parse.Classify(kinds, rel)
		if kind == nil {
			return nil, fmt.Errorf("%s: not a supported lockfile or manifest", root)
		}
		return []candidate{{path: root, rel: rel, kind: kind}}, nil
	}
	walk, err := discover.Walk(root, discover.Options{
		Exclude: exclude,
		Classify: func(rel string) string {
			if k := parse.Classify(kinds, rel); k != nil {
				return k.Ecosystem
			}
			return ""
		},
	})
	if err != nil {
		return nil, err
	}
	for _, p := range walk.Problems {
		msg := p.Err.Error()
		if errors.Is(p.Err, discover.ErrOutsideRoot) {
			msg = discover.ErrOutsideRoot.Error()
		}
		res.Warnings = append(res.Warnings, Warning{Kind: WarnWalk, Manifest: filepath.ToSlash(p.Path), Message: msg})
	}
	out := make([]candidate, 0, len(walk.Manifests))
	for _, m := range walk.Manifests {
		out = append(out, candidate{path: m.Path, rel: m.Rel, kind: parse.Classify(kinds, m.Rel)})
	}
	return out, nil
}

// check folds every record for p into one finding, at the most severe
// verdict any record gives.
func check(db *maldb.DB, rel string, p parse.Package) (Finding, bool) {
	recs := db.Lookup(p.Ecosystem, p.Name)
	if len(recs) == 0 {
		return Finding{}, false
	}
	version := ""
	if p.Exact {
		version = p.Version
	}
	best := maldb.Clean
	var ids, bad []string
	var lead *maldb.Record
	for i := range recs {
		r := &recs[i]
		v := maldb.Check(*r, version)
		ids = append(ids, r.ID)
		bad = append(bad, r.Versions...)
		for _, rg := range r.Ranges {
			bad = append(bad, rangeString(rg))
		}
		if lead == nil || v < best || (v == best && r.Published > lead.Published) {
			best, lead = v, r
		}
	}
	f := Finding{
		Ecosystem: p.Ecosystem,
		Package:   p.Name,
		Version:   p.Version,
		Exact:     p.Exact,
		Manifest:  rel,
		Line:      p.Line,
		Group:     p.Group,
		IDs:       dedupe(ids),
		URL:       maldb.URL(lead.ID),
		Registry:  lead.Registry,
		Campaign:  lead.Campaign,
		Finders:   lead.Finders,
		Published: lead.Published,
	}
	switch best {
	case maldb.Affected:
		f.Reason, f.Severity, f.Remediation = ReasonMalicious, SeverityCritical, Remediation
	case maldb.Unknown:
		f.Reason, f.Severity, f.Remediation = ReasonMalicious, SeverityHigh,
			"Some versions of this package were malware and the version you install is not pinned. "+Remediation
	default:
		f.Reason, f.Severity, f.Remediation = ReasonCompromised, SeverityLow, RemediationCompromised
	}
	if best != maldb.Affected || !lead.All {
		if bad = dedupe(bad); len(bad) > maxListedVersions {
			bad = bad[:maxListedVersions]
		}
		f.MaliciousVersions = bad
	}
	return f, true
}

// rangeString renders an affected interval: ">=1.0.0 <1.2.11", "<=2.0.0".
func rangeString(r maldb.Range) string {
	var parts []string
	if r.Introduced != "" {
		parts = append(parts, ">="+r.Introduced)
	}
	if r.Fixed != "" {
		parts = append(parts, "<"+r.Fixed)
	}
	if r.LastAffected != "" {
		parts = append(parts, "<="+r.LastAffected)
	}
	if len(parts) == 0 {
		return "*"
	}
	return strings.Join(parts, " ")
}

func key(ecosystem, name string) string {
	return ecosystem + "\x00" + maldb.Normalize(ecosystem, name)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := SeverityRank(a.Severity), SeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Manifest < b.Manifest
	})
}

// SeverityRank orders severities; unknown values rank lowest.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity validates a --min-severity value.
func ParseSeverity(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if SeverityRank(s) == 0 {
		return "", fmt.Errorf("unknown severity %q", s)
	}
	return s, nil
}
