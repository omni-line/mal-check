package maldb

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
)

// snapshot gzips records the way scripts/update-data writes them.
func snapshot(t *testing.T, recs ...Record) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestNormalize(t *testing.T) {
	tests := []struct{ eco, in, want string }{
		{PyPI, "Torchflow_Experimental", "torchflow-experimental"},
		{PyPI, "zope.interface", "zope-interface"},
		{PyPI, "a__-.b", "a-b"},
		{Cargo, "Proc_Macro1", "proc-macro1"},
		{NuGet, "Newtonsoft.Json", "newtonsoft.json"},
		{Composer, "Acme/Pkg", "acme/pkg"},
		{VSCode, "Checkmarx.AST-Results", "checkmarx.ast-results"},
		{NPM, "  left-pad ", "left-pad"},
		{NPM, "JSONStream", "JSONStream"},
		{RubyGems, "Rack", "Rack"},
	}
	for _, tt := range tests {
		if got := Normalize(tt.eco, tt.in); got != tt.want {
			t.Errorf("Normalize(%s, %q) = %q, want %q", tt.eco, tt.in, got, tt.want)
		}
	}
}

func TestCheck(t *testing.T) {
	all := Record{All: true}
	listed := Record{Versions: []string{"1.0.0", "v2.0.0"}}
	ranged := Record{Ranges: []Range{
		{Type: "SEMVER", Introduced: "3.0.0", Fixed: "3.2.0"},
		{Type: "SEMVER", Introduced: "4.0.0", LastAffected: "4.1.0"},
		{Type: "SEMVER", Introduced: "9.0.0"},
	}}
	tests := []struct {
		name    string
		rec     Record
		version string
		want    Verdict
	}{
		{"all versions", all, "1.2.3", Affected},
		{"all versions, unknown version", all, "", Affected},
		{"listed hit", listed, "1.0.0", Affected},
		{"listed hit with v prefix on record", listed, "2.0.0", Affected},
		{"listed hit with v prefix on input", listed, "v1.0.0", Affected},
		{"listed miss", listed, "1.0.1", Clean},
		{"listed, version unknown", listed, "", Unknown},
		{"range below", ranged, "2.9.9", Clean},
		{"range inside fixed", ranged, "3.1.5", Affected},
		{"range at fixed", ranged, "3.2.0", Clean},
		{"range at last_affected", ranged, "4.1.0", Affected},
		{"range above last_affected", ranged, "4.1.1", Clean},
		{"open range", ranged, "12.0.0", Affected},
		{"pre-release before introduced", ranged, "3.0.0-rc.1", Clean},
		{"uncomparable", ranged, "dev-main", Unknown},
	}
	for _, tt := range tests {
		if got := Check(tt.rec, tt.version); got != tt.want {
			t.Errorf("%s: Check(%q) = %v, want %v", tt.name, tt.version, got, tt.want)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.2.3", "1.2.3", 0, true},
		{"1.2", "1.2.0", 0, true},
		{"1.10.0", "1.9.0", 1, true},
		{"v2.0.0", "2.0.1", -1, true},
		{"1.0.0-alpha", "1.0.0", -1, true},
		{"1.0.0", "1.0.0-alpha", 1, true},
		{"1.0.0-alpha", "1.0.0-beta", -1, true},
		{"1.0.0-beta", "1.0.0-alpha", 1, true},
		{"1.0.0+build.1", "1.0.0", 0, true},
		{"1.x", "1.0.0", 0, false},
		{"", "1.0.0", 0, false},
	}
	for _, tt := range tests {
		got, ok := compare(tt.a, tt.b)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("compare(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
}

func TestLoadAndLookup(t *testing.T) {
	db, err := Load(snapshot(t,
		Record{ID: "MAL-1", Ecosystem: PyPI, Name: "Evil_Pkg", All: true},
		Record{ID: "MAL-2", Ecosystem: PyPI, Name: "evil-pkg", Versions: []string{"1.0"}},
		Record{ID: "MAL-3", Ecosystem: NPM, Name: "evil"},
	), Meta{Commit: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 3 || db.Meta().Commit != "abc" {
		t.Fatalf("Len=%d Meta=%+v", db.Len(), db.Meta())
	}
	if got := db.Lookup(PyPI, "EVIL.pkg"); len(got) != 2 {
		t.Fatalf("pypi lookup = %+v, want both spellings", got)
	}
	if got := db.Lookup(NPM, "Evil"); len(got) != 0 {
		t.Fatalf("npm is case-sensitive, got %+v", got)
	}
	if got := db.Lookup(Cargo, "evil"); got != nil {
		t.Fatalf("unknown ecosystem lookup = %+v", got)
	}
	var nilDB *DB
	if nilDB.Lookup(NPM, "evil") != nil {
		t.Fatal("nil DB lookup should be empty")
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(strings.NewReader("not gzip"), Meta{}); err == nil {
		t.Error("want error for non-gzip input")
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("{\"i\":\"MAL-1\"}\n{broken\n"))
	_ = zw.Close()
	if _, err := Load(bytes.NewReader(buf.Bytes()), Meta{}); err == nil || !strings.Contains(err.Error(), "record 2") {
		t.Errorf("want record-numbered error, got %v", err)
	}
}

// The committed snapshot must load and contain the incidents the README
// and the hub corpus use as examples.
func TestDefaultSnapshot(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() < 100000 {
		t.Fatalf("snapshot has %d records; looks truncated", db.Len())
	}
	if m := db.Meta(); m.Records != db.Len() || len(m.Commit) != 40 {
		t.Fatalf("meta out of sync with snapshot: %+v (len %d)", m, db.Len())
	}
	for _, c := range []struct{ eco, name string }{
		{Cargo, "proc-macro1"},
		{NPM, "@oku-ui/presence"},
		{RubyGems, "turboscan-client"},
	} {
		if len(db.Lookup(c.eco, c.name)) == 0 {
			t.Errorf("snapshot missing %s %s", c.eco, c.name)
		}
	}
	if URL("MAL-2026-14338") != "https://osv.dev/vulnerability/MAL-2026-14338" {
		t.Error("unexpected advisory URL")
	}
}
