package parse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/omni-line/mal-check/internal/manifest"
)

// maxNPMV1Depth bounds nested dependencies trees in lockfileVersion 1.
const maxNPMV1Depth = 64

// NPMLock parses package-lock.json / npm-shrinkwrap.json (lockfileVersion 1,
// 2, and 3). Linked workspace packages and the root project are skipped.
func NPMLock(data []byte) ([]Package, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]bool{}
	add := func(p Package) {
		key := p.Name + "@" + p.Version
		if p.Name == "" || p.Version == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}

	if packages, ok := raw["packages"]; ok && string(packages) != "null" {
		var pkgs map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
			Dev     bool   `json:"dev"`
		}
		if err := json.Unmarshal(packages, &pkgs); err != nil {
			return nil, fmt.Errorf("packages: %w", err)
		}
		keys := make([]string, 0, len(pkgs))
		for k := range pkgs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			p := pkgs[key]
			if key == "" || p.Link || !strings.Contains(key, "node_modules/") {
				continue // root project, workspace links, workspace sources
			}
			group := "dependencies"
			if p.Dev {
				group = "devDependencies"
			}
			add(Package{
				Ecosystem: "npm",
				Name:      npmLockName(key, p.Name),
				Version:   p.Version,
				Exact:     true,
				Group:     group,
				Line:      manifest.JSONKeyLine(data, key, "version"),
			})
		}
		return out, nil
	}

	if deps, ok := raw["dependencies"]; ok && string(deps) != "null" {
		var tree map[string]npmV1Dep
		if err := json.Unmarshal(deps, &tree); err != nil {
			return nil, fmt.Errorf("dependencies: %w", err)
		}
		walkNPMV1(data, tree, add, 0)
	}
	return out, nil
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dev          bool                `json:"dev"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func walkNPMV1(data []byte, tree map[string]npmV1Dep, add func(Package), depth int) {
	if depth > maxNPMV1Depth {
		return
	}
	names := make([]string, 0, len(tree))
	for n := range tree {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		d := tree[name]
		group := "dependencies"
		if d.Dev {
			group = "devDependencies"
		}
		// v1 records aliases and file/git deps in "version"; only registry
		// versions are comparable.
		if exactVersion(d.Version) {
			add(Package{Ecosystem: "npm", Name: name, Version: d.Version, Exact: true, Group: group,
				Line: manifest.JSONKeyLine(data, name, "version")})
		}
		walkNPMV1(data, d.Dependencies, add, depth+1)
	}
}

// npmLockName returns the package name for a lockfile v2/v3 path key
// ("node_modules/a/node_modules/@s/b" -> "@s/b"), preferring an explicit
// "name" field, which npm writes for aliased installs.
func npmLockName(pathKey, explicit string) string {
	if explicit != "" {
		return explicit
	}
	const prefix = "node_modules/"
	if i := strings.LastIndex(pathKey, prefix); i >= 0 {
		return pathKey[i+len(prefix):]
	}
	return pathKey
}

var packageJSONGroups = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// PackageJSON parses declared dependencies from package.json. Aliases
// ("npm:real@^1") are checked under the real name; local, git and URL specs
// are skipped because they never resolve through the registry.
func PackageJSON(data []byte) ([]Package, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var out []Package
	for _, group := range packageJSONGroups {
		sec, ok := raw[group]
		if !ok {
			continue
		}
		var deps map[string]string
		if err := json.Unmarshal(sec, &deps); err != nil {
			// A malformed section should not hide the others.
			continue
		}
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			spec := strings.TrimSpace(deps[name])
			real := name
			if strings.HasPrefix(spec, "npm:") {
				real, spec = splitNameVersion(strings.TrimPrefix(spec, "npm:"))
			}
			if npmNonRegistrySpec(spec) || real == "" {
				continue
			}
			out = append(out, Package{
				Ecosystem: "npm",
				Name:      real,
				Version:   spec,
				Exact:     exactVersion(spec),
				Group:     group,
				Line:      manifest.JSONKeyLine(data, group, name),
			})
		}
	}
	return out, nil
}

func npmNonRegistrySpec(spec string) bool {
	for _, p := range []string{"file:", "link:", "workspace:", "portal:", "git", "http:", "https:", "github:", "patch:"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	// "user/repo" GitHub shorthand.
	return strings.Contains(spec, "/") && !strings.HasPrefix(spec, "@")
}

// splitNameVersion splits "name@ver" / "@scope/name@ver" on the version '@'.
func splitNameVersion(spec string) (name, version string) {
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	if i := strings.IndexByte(spec[start:], '@'); i >= 0 {
		return spec[:start+i], spec[start+i+1:]
	}
	return spec, ""
}

// YarnLock parses yarn.lock: classic (v1) and Berry (v2+, YAML-shaped).
func YarnLock(data []byte) ([]Package, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var (
		out    []Package
		names  []string
		header int
		lineNo int
	)
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(trimmed, ":") {
			names = yarnEntryNames(strings.TrimSuffix(trimmed, ":"))
			header = lineNo
			continue
		}
		key, val, ok := yarnField(trimmed)
		if !ok || key != "version" || len(names) == 0 {
			continue
		}
		version := unquote(val)
		for _, name := range names {
			out = append(out, Package{Ecosystem: "npm", Name: name, Version: version, Exact: true, Line: header})
		}
		names = nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// yarnEntryNames returns the package names in an entry header such as
// `"lodash@^4.17.0", lodash@^4.17.21` or `"@s/x@npm:^1.0.0"`. Workspace,
// link, file and patch protocol entries are skipped.
func yarnEntryNames(header string) []string {
	var names []string
	seen := map[string]bool{}
	// Classic quotes each spec ("a@^1", "a@^1.1"); Berry quotes the whole
	// header ("a@npm:^1, a@npm:^1.1"). Trimming quotes per part covers both.
	for _, part := range strings.Split(header, ",") {
		spec := strings.Trim(strings.TrimSpace(part), `"'`)
		if spec == "__metadata" || spec == "" {
			continue
		}
		name, rng := splitNameVersion(spec)
		if strings.HasPrefix(rng, "npm:") {
			// "alias@npm:real@^1" installs real; "x@npm:^1" installs x.
			if real, v := splitNameVersion(strings.TrimPrefix(rng, "npm:")); v != "" {
				name = real
			}
		} else if strings.Contains(rng, ":") {
			continue // workspace:, link:, file:, patch:, portal:, git
		}
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func yarnField(line string) (key, val string, ok bool) {
	i := strings.IndexAny(line, " \t")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSuffix(line[:i], ":"), strings.TrimSpace(line[i+1:]), true
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// PNPMLock parses the top-level `packages:` map of pnpm-lock.yaml, whose keys
// spell name and version: "/lodash/4.17.21" (v5), "/lodash@4.17.21" (v6),
// "lodash@4.17.21" (v9), with an optional "(peer@x)" suffix.
func PNPMLock(data []byte) ([]Package, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var (
		out    []Package
		inPkgs bool
		lineNo int
	)
	seen := map[string]bool{}
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' {
			inPkgs = strings.TrimSpace(line) == "packages:"
			continue
		}
		if !inPkgs || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		key := strings.TrimSuffix(strings.TrimSpace(line), ":")
		name, version := pnpmKey(unquote(key))
		if name == "" || !exactVersion(version) || seen[name+"@"+version] {
			continue
		}
		seen[name+"@"+version] = true
		out = append(out, Package{Ecosystem: "npm", Name: name, Version: version, Exact: true, Line: lineNo})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func pnpmKey(key string) (name, version string) {
	if i := strings.IndexByte(key, '('); i > 0 {
		key = key[:i]
	}
	key = strings.TrimPrefix(key, "/")
	if name, version = splitNameVersion(key); version != "" {
		return name, version
	}
	// v5: name/version, scoped @s/name/version.
	if i := strings.LastIndexByte(key, '/'); i > 0 {
		return key[:i], key[i+1:]
	}
	return "", ""
}
