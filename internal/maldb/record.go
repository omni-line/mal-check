// Package maldb holds the embedded snapshot of packages published to public
// registries as malware (OpenSSF malicious-packages, MAL- ids) and answers
// "is this name, at this version, a known malicious package?".
package maldb

// Ecosystem ids used in findings and in the snapshot. They match the ids
// omni-audit uses for the same registries; do not rename them.
const (
	NPM      = "npm"
	PyPI     = "pypi"
	RubyGems = "rubygems"
	NuGet    = "nuget"
	Cargo    = "cargo"
	Go       = "go"
	Composer = "composer"
	Maven    = "maven"
	VSCode   = "vscode"
)

// Record is one MAL- advisory for one package. Field names are short because
// the snapshot carries ~240k of them.
type Record struct {
	// ID is the OpenSSF id, e.g. MAL-2026-14338.
	ID string `json:"i"`
	// Ecosystem is one of the ids above.
	Ecosystem string `json:"e"`
	// Registry is set when one ecosystem id spans several registries
	// (vscode: marketplace vs open-vsx.org).
	Registry string `json:"g,omitempty"`
	// Name is the package name exactly as the advisory spells it.
	Name string `json:"n"`
	// All marks every version of the package as malicious (introduced: 0
	// with no end), which is the common case for throwaway malware names.
	All bool `json:"a,omitempty"`
	// Versions lists explicitly affected versions when All is false.
	Versions []string `json:"v,omitempty"`
	// Ranges lists affected intervals when All is false.
	Ranges []Range `json:"r,omitempty"`
	// Published is the advisory date, YYYY-MM-DD.
	Published string `json:"p,omitempty"`
	// Campaign is a coarse label for mass campaigns (e.g. tea-xyz-token-farming).
	Campaign string `json:"c,omitempty"`
	// Finders are the credited reporters (OSV credits[].name).
	Finders []string `json:"f,omitempty"`
}

// Range is one affected interval. Introduced is inclusive; Fixed is
// exclusive; LastAffected is inclusive. An empty bound is open.
type Range struct {
	// Type is the OSV range type: SEMVER or ECOSYSTEM.
	Type         string `json:"t"`
	Introduced   string `json:"in,omitempty"`
	Fixed        string `json:"fx,omitempty"`
	LastAffected string `json:"la,omitempty"`
}

// URL is the public advisory page for a MAL id.
func URL(id string) string {
	return "https://osv.dev/vulnerability/" + id
}
