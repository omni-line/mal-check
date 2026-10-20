// Package parse extracts package names and versions from lockfiles and
// manifests. Each supported file format is one Kind; nothing outside this
// package knows file names.
package parse

import (
	"fmt"
	"path"
	"strings"
)

// Package is one dependency found in a file.
type Package struct {
	// Ecosystem is a maldb ecosystem id (npm, pypi, …).
	Ecosystem string
	// Name is the package name as the registry knows it.
	Name string
	// Version is the installed version when Exact, else the declared
	// constraint verbatim (may be empty).
	Version string
	// Exact reports whether Version is one concrete version (a lockfile entry
	// or an == pin) rather than a range.
	Exact bool
	// Group is the file section, e.g. "devDependencies" or "packages-dev".
	Group string
	// Line is the 1-based line of the entry, or 0 when unknown.
	Line int
}

// Kind is one supported file format.
type Kind struct {
	// Ecosystem is the maldb ecosystem id the format belongs to.
	Ecosystem string
	// Lockfile reports whether the format records installed versions.
	Lockfile bool
	// Match reports whether a slash-separated path relative to the scan root
	// is this format.
	Match func(rel string) bool
	// Parse extracts packages from file contents.
	Parse func(data []byte) ([]Package, error)
}

// Default returns every supported format.
func Default() []Kind {
	return []Kind{
		{Ecosystem: "npm", Lockfile: true, Match: base("package-lock.json", "npm-shrinkwrap.json"), Parse: NPMLock},
		{Ecosystem: "npm", Lockfile: true, Match: base("yarn.lock"), Parse: YarnLock},
		{Ecosystem: "npm", Lockfile: true, Match: base("pnpm-lock.yaml"), Parse: PNPMLock},
		{Ecosystem: "npm", Match: base("package.json"), Parse: PackageJSON},
		{Ecosystem: "pypi", Lockfile: true, Match: base("poetry.lock", "uv.lock"), Parse: TOMLPackages("pypi", false)},
		{Ecosystem: "pypi", Lockfile: true, Match: base("Pipfile.lock"), Parse: PipfileLock},
		{Ecosystem: "pypi", Match: requirementsFile, Parse: Requirements},
		{Ecosystem: "rubygems", Lockfile: true, Match: base("Gemfile.lock", "gems.locked"), Parse: GemfileLock},
		{Ecosystem: "nuget", Lockfile: true, Match: base("packages.lock.json"), Parse: NuGetLock},
		{Ecosystem: "nuget", Match: nugetProject, Parse: NuGetProject},
		{Ecosystem: "cargo", Lockfile: true, Match: base("Cargo.lock"), Parse: TOMLPackages("cargo", true)},
		{Ecosystem: "go", Match: base("go.mod"), Parse: GoMod},
		{Ecosystem: "composer", Lockfile: true, Match: base("composer.lock"), Parse: ComposerLock},
		{Ecosystem: "composer", Match: base("composer.json"), Parse: ComposerJSON},
		{Ecosystem: "vscode", Match: vscodeExtensions, Parse: VSCodeExtensions},
	}
}

// Classify returns the first Kind matching rel, or nil.
func Classify(kinds []Kind, rel string) *Kind {
	for i := range kinds {
		if kinds[i].Match(rel) {
			return &kinds[i]
		}
	}
	return nil
}

// File parses data as kind, wrapping errors with the file's base name.
func File(kind *Kind, rel string, data []byte) ([]Package, error) {
	pkgs, err := kind.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path.Base(rel), err)
	}
	return pkgs, nil
}

func base(names ...string) func(string) bool {
	return func(rel string) bool {
		b := path.Base(rel)
		for _, n := range names {
			if strings.EqualFold(b, n) {
				return true
			}
		}
		return false
	}
}

func requirementsFile(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	if !strings.HasSuffix(b, ".txt") {
		return false
	}
	if strings.HasPrefix(b, "requirements") || strings.HasPrefix(b, "constraints") {
		return true
	}
	// requirements/base.txt, requirements/dev.txt
	return strings.EqualFold(path.Base(path.Dir(rel)), "requirements")
}

func nugetProject(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	switch {
	case strings.HasSuffix(b, ".csproj"), strings.HasSuffix(b, ".fsproj"), strings.HasSuffix(b, ".vbproj"):
		return true
	case b == "directory.packages.props", b == "packages.config":
		return true
	}
	return false
}

func vscodeExtensions(rel string) bool {
	return strings.EqualFold(path.Base(rel), "extensions.json") &&
		strings.EqualFold(path.Base(path.Dir(rel)), ".vscode")
}

// exactVersion reports whether a declared version is one concrete version
// (1.2.3, v1.2.3, 1.2.3-beta.1) rather than a range or tag.
func exactVersion(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || (v[0] < '0' || v[0] > '9') {
		return false
	}
	return !strings.ContainsAny(v, " <>=^~*|,xX")
}
