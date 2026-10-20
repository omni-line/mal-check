package parse

import (
	"reflect"
	"strings"
	"testing"
)

// brief is the comparable part of a Package for table tests.
type brief struct {
	Name, Version string
	Exact         bool
	Line          int
}

func briefs(pkgs []Package) []brief {
	out := make([]brief, len(pkgs))
	for i, p := range pkgs {
		out[i] = brief{p.Name, p.Version, p.Exact, p.Line}
	}
	return out
}

func mustParse(t *testing.T, fn func([]byte) ([]Package, error), data string) []Package {
	t.Helper()
	pkgs, err := fn([]byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return pkgs
}

func eq(t *testing.T, got []Package, want []brief) {
	t.Helper()
	if g := briefs(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got  %+v\nwant %+v", g, want)
	}
}

func TestClassify(t *testing.T) {
	kinds := Default()
	tests := map[string]string{
		"package-lock.json":         "npm",
		"a/npm-shrinkwrap.json":     "npm",
		"yarn.lock":                 "npm",
		"pnpm-lock.yaml":            "npm",
		"apps/web/package.json":     "npm",
		"poetry.lock":               "pypi",
		"uv.lock":                   "pypi",
		"Pipfile.lock":              "pypi",
		"requirements-dev.txt":      "pypi",
		"constraints.txt":           "pypi",
		"requirements/base.txt":     "pypi",
		"Gemfile.lock":              "rubygems",
		"packages.lock.json":        "nuget",
		"src/App/App.csproj":        "nuget",
		"Directory.Packages.props":  "nuget",
		"packages.config":           "nuget",
		"Cargo.lock":                "cargo",
		"go.mod":                    "go",
		"composer.lock":             "composer",
		"composer.json":             "composer",
		".vscode/extensions.json":   "vscode",
		"notes.txt":                 "",
		"extensions.json":           "",
		"docs/requirements.md":      "",
		"node_modules/x/README.txt": "",
	}
	for rel, want := range tests {
		got := ""
		if k := Classify(kinds, rel); k != nil {
			got = k.Ecosystem
		}
		if got != want {
			t.Errorf("Classify(%q) = %q, want %q", rel, got, want)
		}
	}
}

func TestFileWrapsErrors(t *testing.T) {
	k := Classify(Default(), "x/package-lock.json")
	if _, err := File(k, "x/package-lock.json", []byte("{")); err == nil || !strings.Contains(err.Error(), "package-lock.json") {
		t.Fatalf("want wrapped error, got %v", err)
	}
}

func TestExactVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.3": true, "v1.2.3": true, "1.0.0-beta.1": true, "2": true,
		"^1.2.3": false, "~1": false, ">=1": false, "1.x": false, "*": false,
		"latest": false, "": false, "1 - 2": false, "1.0 || 2.0": false,
	} {
		if got := exactVersion(v); got != want {
			t.Errorf("exactVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNPMLockV3(t *testing.T) {
	got := mustParse(t, NPMLock, `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "root"},
    "node_modules/a": {"version": "1.0.0"},
    "node_modules/a/node_modules/@s/b": {"version": "2.0.0", "dev": true},
    "node_modules/alias": {"name": "real", "version": "3.0.0"},
    "node_modules/ws": {"link": true},
    "packages/ws": {"version": "0.0.1"},
    "node_modules/dup": {"version": "1.0.0"},
    "node_modules/x/node_modules/dup": {"version": "1.0.0"}
  }
}`)
	eq(t, got, []brief{
		{"a", "1.0.0", true, 5},
		{"@s/b", "2.0.0", true, 6},
		{"real", "3.0.0", true, 7},
		{"dup", "1.0.0", true, 10},
	})
	if got[1].Group != "devDependencies" {
		t.Errorf("dev flag not mapped: %+v", got[1])
	}
}

func TestNPMLockV1(t *testing.T) {
	got := mustParse(t, NPMLock, `{
  "lockfileVersion": 1,
  "dependencies": {
    "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": true}}},
    "git-dep": {"version": "github:user/repo#abc"}
  }
}`)
	eq(t, got, []brief{{"a", "1.0.0", true, 4}, {"b", "2.0.0", true, 4}})
}

func TestNPMLockErrors(t *testing.T) {
	for _, in := range []string{"{", `{"packages": []}`, `{"dependencies": 3}`} {
		if _, err := NPMLock([]byte(in)); err == nil {
			t.Errorf("NPMLock(%s): want error", in)
		}
	}
	if got := mustParse(t, NPMLock, `{"packages": null}`); len(got) != 0 {
		t.Errorf("null packages: %+v", got)
	}
}

func TestPackageJSON(t *testing.T) {
	got := mustParse(t, PackageJSON, `{
  "dependencies": {
    "exact": "1.2.3",
    "ranged": "^2.0.0",
    "alias": "npm:@real/pkg@^3.0.0",
    "local": "file:../x",
    "gh": "user/repo",
    "ws": "workspace:*"
  },
  "devDependencies": {"@scope/dev": "~4.0.0"},
  "peerDependencies": "not an object"
}`)
	eq(t, got, []brief{
		{"@real/pkg", "^3.0.0", false, 5},
		{"exact", "1.2.3", true, 3},
		{"ranged", "^2.0.0", false, 4},
		{"@scope/dev", "~4.0.0", false, 10},
	})
	if _, err := PackageJSON([]byte("[")); err == nil {
		t.Error("want error for invalid JSON")
	}
}

func TestYarnLockClassic(t *testing.T) {
	got := mustParse(t, YarnLock, `# yarn lockfile v1

"@s/a@^1.0.0", "@s/a@^1.1.0":
  version "1.2.0"
  resolved "https://registry.yarnpkg.com/@s/a/-/a-1.2.0.tgz"

b@2.0.0:
  version "2.0.0"
`)
	eq(t, got, []brief{{"@s/a", "1.2.0", true, 3}, {"b", "2.0.0", true, 7}})
}

func TestYarnLockBerry(t *testing.T) {
	got := mustParse(t, YarnLock, `__metadata:
  version: 8

"alias@npm:real@^1.0.0":
  version: 1.4.0

"c@npm:^3.0.0, c@npm:^3.1.0":
  version: 3.1.0

"app@workspace:.":
  version: 0.0.0-use.local
`)
	eq(t, got, []brief{{"real", "1.4.0", true, 4}, {"c", "3.1.0", true, 7}})
}

func TestPNPMLock(t *testing.T) {
	got := mustParse(t, PNPMLock, `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  a@1.0.0:
    resolution: {integrity: sha512-x}

  '@s/b@2.0.0':
    resolution: {integrity: sha512-y}

  /c@3.0.0(react@18.0.0):
    resolution: {integrity: sha512-z}

  /old/4.0.0:
    resolution: {integrity: sha512-w}

  link-dep@link:../x:
    resolution: {directory: ../x}

snapshots:

  a@1.0.0: {}
`)
	eq(t, got, []brief{
		{"a", "1.0.0", true, 12},
		{"@s/b", "2.0.0", true, 15},
		{"c", "3.0.0", true, 18},
		{"old", "4.0.0", true, 21},
	})
}

func TestTOMLPackages(t *testing.T) {
	poetry := mustParse(t, TOMLPackages("pypi", false), `[[package]]
name = "requests"
version = "2.32.3"

[package.dependencies]
name = "ignored"

[[package]]
name = 'six'
version = '1.16.0'

[metadata]
content-hash = "x"
`)
	eq(t, poetry, []brief{{"requests", "2.32.3", true, 2}, {"six", "1.16.0", true, 9}})

	cargo := mustParse(t, TOMLPackages("cargo", true), `version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local"
version = "0.1.0"

[[package]]
name = "gitdep"
version = "0.2.0"
source = "git+https://github.com/x/y#abc"

[[package]]
name = "sparse"
version = "0.3.0"
source = "sparse+https://index.crates.io/"
`)
	eq(t, cargo, []brief{{"serde", "1.0.0", true, 4}, {"sparse", "0.3.0", true, 18}})
}

func TestPipfileLock(t *testing.T) {
	got := mustParse(t, PipfileLock, `{
  "default": {"requests": {"version": "==2.32.3"}, "vcs": {"git": "https://x"}},
  "develop": {"pytest": {"version": "==8.0.0"}}
}`)
	eq(t, got, []brief{{"requests", "2.32.3", true, 2}, {"pytest", "8.0.0", true, 3}})
	if _, err := PipfileLock([]byte("x")); err == nil {
		t.Error("want error")
	}
}

func TestRequirements(t *testing.T) {
	got := mustParse(t, Requirements, `# comment
requests==2.32.3
Django>=4.2,<5  # range
uvicorn[standard]==0.30.0 ; python_version >= "3.9"
pinned==1.0 --hash=sha256:abc
-r base.txt
-e .
./local
pkg @ https://example.com/pkg.whl
https://example.com/x.tar.gz
arbitrary===1.0
bare
`)
	eq(t, got, []brief{
		{"requests", "2.32.3", true, 2},
		{"Django", ">=4.2,<5", false, 3},
		{"uvicorn", "0.30.0", true, 4},
		{"pinned", "1.0", true, 5},
		{"arbitrary", "===1.0", false, 11},
		{"bare", "", false, 12},
	})
}

func TestGemfileLock(t *testing.T) {
	got := mustParse(t, GemfileLock, `PATH
  remote: .
  specs:
    local (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0-x86_64-linux)
      racc (~> 1.4)
    racc (1.8.1)

PLATFORMS
  ruby
`)
	eq(t, got, []brief{{"nokogiri", "1.16.0", true, 9}, {"racc", "1.8.1", true, 11}})
}

func TestNuGetLock(t *testing.T) {
	got := mustParse(t, NuGetLock, `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
      "MyLib": {"type": "Project"}
    },
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}
    }
  }
}`)
	eq(t, got, []brief{{"Newtonsoft.Json", "13.0.3", true, 5}})
	if _, err := NuGetLock([]byte("[")); err == nil {
		t.Error("want error")
	}
}

func TestNuGetProject(t *testing.T) {
	got := mustParse(t, NuGetProject, `<Project>
  <ItemGroup>
    <PackageReference Include="Exact" Version="1.2.3" />
    <PackageReference Include="Bracketed" Version="[2.0.0]" />
    <PackageReference Include="Floating" Version="3.*" />
    <PackageVersion Include="Central" Version="4.0.0" />
    <PackageReference Update="Updated" Version="[1.0,2.0)" />
    <PackageReference Version="9.9.9" />
  </ItemGroup>
</Project>`)
	eq(t, got, []brief{
		{"Exact", "1.2.3", true, 3},
		{"Bracketed", "2.0.0", true, 4},
		{"Floating", "3.*", false, 5},
		{"Central", "4.0.0", true, 6},
		{"Updated", "[1.0,2.0)", false, 7},
	})
	cfg := mustParse(t, NuGetProject, `<?xml version="1.0"?>
<packages>
  <package id="Legacy" version="5.0.0" targetFramework="net48" />
</packages>`)
	eq(t, cfg, []brief{{"Legacy", "5.0.0", true, 3}})
	if _, err := NuGetProject([]byte("<Project><PackageReference Include=\"x\"")); err == nil {
		t.Error("want XML error")
	}
}

func TestGoMod(t *testing.T) {
	got := mustParse(t, GoMod, `module example.com/app

go 1.22

require github.com/a/b v1.0.0

require (
	github.com/c/d v2.0.0+incompatible // indirect
	// comment only
	golang.org/x/e v0.1.0
)

replace github.com/a/b => ../b
`)
	eq(t, got, []brief{
		{"github.com/a/b", "v1.0.0", true, 5},
		{"github.com/c/d", "v2.0.0+incompatible", true, 8},
		{"golang.org/x/e", "v0.1.0", true, 10},
	})
}

func TestComposer(t *testing.T) {
	lock := mustParse(t, ComposerLock, `{
  "packages": [{"name": "acme/a", "version": "v1.0.0"}, {"name": ""}],
  "packages-dev": [{"name": "acme/b", "version": "dev-main"}]
}`)
	eq(t, lock, []brief{{"acme/a", "v1.0.0", true, 2}, {"acme/b", "dev-main", true, 3}})

	manifest := mustParse(t, ComposerJSON, `{
  "require": {"php": ">=8.1", "ext-json": "*", "acme/a": "^1.0"},
  "require-dev": {"acme/b": "2.0.0"}
}`)
	eq(t, manifest, []brief{{"acme/a", "^1.0", false, 2}, {"acme/b", "2.0.0", true, 3}})
	for _, fn := range []func([]byte) ([]Package, error){ComposerLock, ComposerJSON} {
		if _, err := fn([]byte("x")); err == nil {
			t.Error("want error")
		}
	}
}

func TestVSCodeExtensions(t *testing.T) {
	got := mustParse(t, VSCodeExtensions, `{
  // line comment with "quotes"
  /* block
     comment */
  "recommendations": [
    "esbenp.prettier-vscode",
    "odd//name",
  ],
}`)
	eq(t, got, []brief{{"esbenp.prettier-vscode", "", false, 6}, {"odd//name", "", false, 7}})
	if _, err := VSCodeExtensions([]byte("{")); err == nil {
		t.Error("want error")
	}
}
