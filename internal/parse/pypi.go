package parse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/omni-line/mal-check/internal/manifest"
)

// TOMLPackages parses the [[package]] tables shared by poetry.lock, uv.lock
// and Cargo.lock (name/version keys, TOML subset). With registryOnly, entries
// without a `source = "registry+..."` key (path and git crates) are dropped,
// because they never came from the public registry.
func TOMLPackages(ecosystem string, registryOnly bool) func([]byte) ([]Package, error) {
	return func(data []byte) ([]Package, error) {
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		var (
			out                   []Package
			inPkg                 bool
			name, version, source string
			nameLine, lineNo      int
		)
		flush := func() {
			if inPkg && name != "" && version != "" &&
				(!registryOnly || strings.HasPrefix(source, "registry+") || strings.HasPrefix(source, "sparse+")) {
				out = append(out, Package{Ecosystem: ecosystem, Name: name, Version: version, Exact: true, Line: nameLine})
			}
			name, version, source, nameLine = "", "", "", 0
		}
		for sc.Scan() {
			lineNo++
			t := strings.TrimSpace(sc.Text())
			if t == "" || t[0] == '#' {
				continue
			}
			if t[0] == '[' {
				if t == "[[package]]" {
					flush()
					inPkg = true
				} else if !strings.HasPrefix(t, "[package.") {
					// [metadata], [[package.wheels]] stay inside; anything
					// else ends the package table.
					flush()
					inPkg = false
				}
				continue
			}
			if !inPkg {
				continue
			}
			key, val, ok := tomlKeyVal(t)
			if !ok {
				continue
			}
			switch key {
			case "name":
				if name == "" {
					name, nameLine = val, lineNo
				}
			case "version":
				if version == "" {
					version = val
				}
			case "source":
				source = val
			}
		}
		flush()
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// tomlKeyVal splits `key = "value"`, unquoting basic and literal strings.
// Inline tables and arrays are returned verbatim.
func tomlKeyVal(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.TrimSpace(line[i+1:])
	for _, q := range []byte{'"', '\''} {
		if len(val) >= 2 && val[0] == q {
			if end := strings.IndexByte(val[1:], q); end >= 0 {
				return key, val[1 : 1+end], true
			}
		}
	}
	return key, val, true
}

// PipfileLock parses Pipfile.lock "default" and "develop" sections, whose
// versions are written as "==1.2.3".
func PipfileLock(data []byte) ([]Package, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for _, group := range []string{"default", "develop"} {
		var deps map[string]struct {
			Version string `json:"version"`
		}
		if raw, ok := lock[group]; !ok || json.Unmarshal(raw, &deps) != nil {
			continue
		}
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			v := strings.TrimPrefix(deps[name].Version, "==")
			if v == "" {
				continue // VCS or path dependency
			}
			out = append(out, Package{Ecosystem: "pypi", Name: name, Version: v, Exact: true, Group: group,
				Line: manifest.JSONKeyLine(data, group, name)})
		}
	}
	return out, nil
}

// Requirements parses pip requirements / constraints files. Options (-r, -e,
// --hash), URLs and local paths are skipped; `name==1.2.3` is an exact pin and
// anything else is a declared range.
func Requirements(data []byte) ([]Package, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var (
		out    []Package
		lineNo int
	)
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		line = strings.TrimSuffix(line, "\\")
		if line == "" || line[0] == '#' || line[0] == '-' || strings.Contains(line, "://") ||
			line[0] == '.' || line[0] == '/' {
			continue
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i] // environment marker
		}
		if i := strings.Index(line, " --"); i >= 0 {
			line = line[:i] // per-requirement options (--hash)
		}
		if i := strings.IndexByte(line, '@'); i >= 0 {
			continue // PEP 508 direct reference: name @ url
		}
		nameEnd := strings.IndexAny(line, "[<>=!~ ")
		name, spec := line, ""
		if nameEnd >= 0 {
			name, spec = line[:nameEnd], strings.TrimSpace(line[nameEnd:])
		}
		if strings.HasPrefix(spec, "[") {
			if j := strings.IndexByte(spec, ']'); j >= 0 {
				spec = strings.TrimSpace(spec[j+1:])
			}
		}
		if name == "" {
			continue
		}
		p := Package{Ecosystem: "pypi", Name: name, Version: spec, Line: lineNo}
		if v := strings.TrimSpace(strings.TrimPrefix(spec, "==")); strings.HasPrefix(spec, "==") &&
			!strings.HasPrefix(spec, "===") && exactVersion(v) {
			p.Version, p.Exact = v, true
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
