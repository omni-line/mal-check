package parse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/omni-line/mal-check/internal/manifest"
)

// GemfileLock parses the GEM section of Gemfile.lock. PATH and GIT sections
// are skipped: those gems never came from rubygems.org.
func GemfileLock(data []byte) ([]Package, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var (
		out     []Package
		inGem   bool
		inSpecs bool
		lineNo  int
	)
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' {
			inGem, inSpecs = strings.TrimSpace(line) == "GEM", false
			continue
		}
		if !inGem {
			continue
		}
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		// Gems sit at exactly four spaces; their dependencies at six.
		if !inSpecs || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		t := strings.TrimSpace(line)
		lp, rp := strings.IndexByte(t, '('), strings.IndexByte(t, ')')
		if lp <= 0 || rp < lp {
			continue
		}
		version := t[lp+1 : rp]
		if i := strings.IndexByte(version, '-'); i > 0 {
			version = version[:i] // platform suffix: 1.16.0-x86_64-linux
		}
		out = append(out, Package{Ecosystem: "rubygems", Name: strings.TrimSpace(t[:lp]), Version: version, Exact: true, Line: lineNo})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// NuGetLock parses packages.lock.json (every target framework).
func NuGetLock(data []byte) ([]Package, error) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Package
	seen := map[string]bool{}
	tfms := make([]string, 0, len(lock.Dependencies))
	for t := range lock.Dependencies {
		tfms = append(tfms, t)
	}
	sort.Strings(tfms)
	for _, tfm := range tfms {
		deps := lock.Dependencies[tfm]
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			d := deps[name]
			if d.Resolved == "" || strings.EqualFold(d.Type, "Project") || seen[name+"@"+d.Resolved] {
				continue
			}
			seen[name+"@"+d.Resolved] = true
			out = append(out, Package{Ecosystem: "nuget", Name: name, Version: d.Resolved, Exact: true, Group: tfm,
				Line: manifest.JSONKeyLine(data, name, "resolved")})
		}
	}
	return out, nil
}

// NuGetProject parses <PackageReference>/<PackageVersion> items in MSBuild
// project files and <package> entries in packages.config.
func NuGetProject(data []byte) ([]Package, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var out []Package
	for {
		off := int(dec.InputOffset())
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var name, version string
		switch el.Name.Local {
		case "PackageReference", "PackageVersion":
			name = attr(el, "Include")
			if name == "" {
				name = attr(el, "Update")
			}
			version = attr(el, "Version")
		case "package":
			name, version = attr(el, "id"), attr(el, "version")
		default:
			continue
		}
		if name == "" {
			continue
		}
		v := strings.Trim(version, "[] ")
		out = append(out, Package{Ecosystem: "nuget", Name: name, Version: version, Exact: exactVersion(v) && !strings.Contains(version, ","),
			Group: el.Name.Local, Line: manifest.LineAt(data, off)})
		if out[len(out)-1].Exact {
			out[len(out)-1].Version = v
		}
	}
	return out, nil
}

func attr(el xml.StartElement, name string) string {
	for _, a := range el.Attr {
		if strings.EqualFold(a.Name.Local, name) {
			return strings.TrimSpace(a.Value)
		}
	}
	return ""
}

// GoMod parses require directives in go.mod (single-line and blocks).
func GoMod(data []byte) ([]Package, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var (
		out     []Package
		inBlock bool
		lineNo  int
	)
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
			continue
		case inBlock && f[0] == ")":
			inBlock = false
			continue
		case f[0] == "require" && len(f) == 2 && f[1] == "(":
			inBlock = true
			continue
		case f[0] == "require" && len(f) >= 3:
			f = f[1:]
		case !inBlock:
			continue
		}
		if len(f) >= 2 {
			out = append(out, Package{Ecosystem: "go", Name: f[0], Version: f[1], Exact: true, Group: "require", Line: lineNo})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ComposerLock parses composer.lock packages and packages-dev.
func ComposerLock(data []byte) ([]Package, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for _, group := range []string{"packages", "packages-dev"} {
		var pkgs []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if raw, ok := lock[group]; !ok || json.Unmarshal(raw, &pkgs) != nil {
			continue
		}
		for _, p := range pkgs {
			if p.Name == "" || p.Version == "" {
				continue
			}
			out = append(out, Package{Ecosystem: "composer", Name: p.Name, Version: p.Version, Exact: true, Group: group,
				Line: jsonValueLine(data, "name", p.Name)})
		}
	}
	return out, nil
}

// jsonValueLine returns the line of the first `"key": "value"` pair, or 0.
func jsonValueLine(data []byte, key, value string) int {
	re, err := regexp.Compile(`"` + regexp.QuoteMeta(key) + `"\s*:\s*"` + regexp.QuoteMeta(value) + `"`)
	if err != nil {
		return 0
	}
	loc := re.FindIndex(data)
	if loc == nil {
		return 0
	}
	return manifest.LineAt(data, loc[0])
}

// ComposerJSON parses composer.json require / require-dev, skipping platform
// packages (php, ext-*, lib-*, composer-*), which never come from Packagist.
func ComposerJSON(data []byte) ([]Package, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var out []Package
	for _, group := range []string{"require", "require-dev"} {
		var deps map[string]string
		if sec, ok := raw[group]; !ok || json.Unmarshal(sec, &deps) != nil {
			continue
		}
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			if !strings.Contains(name, "/") {
				continue // php, ext-json, lib-icu, composer-plugin-api
			}
			spec := deps[name]
			out = append(out, Package{Ecosystem: "composer", Name: name, Version: spec, Exact: exactVersion(spec), Group: group,
				Line: manifest.JSONKeyLine(data, group, name)})
		}
	}
	return out, nil
}

// VSCodeExtensions parses the "recommendations" of .vscode/extensions.json,
// which VS Code reads as JSON with comments and trailing commas.
func VSCodeExtensions(data []byte) ([]Package, error) {
	var doc struct {
		Recommendations []string `json:"recommendations"`
	}
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		return nil, err
	}
	var out []Package
	for _, id := range doc.Recommendations {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		out = append(out, Package{Ecosystem: "vscode", Name: id, Group: "recommendations",
			Line: manifest.LineAt(data, bytes.Index(data, []byte(`"`+id+`"`)))})
	}
	return out, nil
}

// stripJSONC removes // and /* */ comments outside strings and commas that
// precede a closing bracket, turning JSONC into JSON. Newlines are kept so
// byte offsets and line numbers stay meaningful.
func stripJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inStr, esc := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case inStr:
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' {
					out = append(out, '\n')
				}
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	// Trailing commas: ",  ]" / ",\n}".
	res := out[:0:0]
	for i := 0; i < len(out); i++ {
		if out[i] == ',' {
			j := i + 1
			for j < len(out) && (out[j] == ' ' || out[j] == '\t' || out[j] == '\r' || out[j] == '\n') {
				j++
			}
			if j < len(out) && (out[j] == ']' || out[j] == '}') {
				continue
			}
		}
		res = append(res, out[i])
	}
	return res
}
