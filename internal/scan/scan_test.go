package scan

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/omni-line/mal-check/internal/match"
	"github.com/omni-line/mal-check/pkg/maldb"
)

func testDB(t *testing.T) *maldb.DB {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	for _, r := range []maldb.Record{
		{ID: "MAL-1", Ecosystem: maldb.NPM, Name: "evil", All: true, Campaign: "tea-xyz-token-farming", Published: "2025-01-01"},
		{ID: "MAL-2", Ecosystem: maldb.NPM, Name: "hijacked", Versions: []string{"2.0.0", "2.0.1"}, Published: "2025-02-01"},
		{ID: "MAL-3", Ecosystem: maldb.NPM, Name: "hijacked", Versions: []string{"3.0.0"}, Published: "2025-03-01"},
		{ID: "MAL-4", Ecosystem: maldb.PyPI, Name: "bad-pkg", Versions: []string{"1.0"}, Finders: []string{"kam193"}},
	} {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := maldb.Load(bytes.NewReader(buf.Bytes()), maldb.Meta{Records: 4})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func write(t *testing.T, dir, rel, content string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

type got struct{ Package, Version, Manifest, Reason, Severity string }

func summarize(fs []Finding) []got {
	out := make([]got, len(fs))
	for i, f := range fs {
		out[i] = got{f.Package, f.Version, f.Manifest, f.Reason, f.Severity}
	}
	return out
}

func TestRunVerdicts(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app/package.json", `{"dependencies": {"evil": "^1.0.0", "hijacked": "^2.0.0", "fine": "1.0.0"}}`)
	write(t, dir, "app/package-lock.json", `{"lockfileVersion": 3, "packages": {
		"node_modules/hijacked": {"version": "2.0.1"},
		"node_modules/fine": {"version": "1.0.0"}}}`)
	write(t, dir, "other/package-lock.json", `{"lockfileVersion": 3, "packages": {"node_modules/hijacked": {"version": "2.5.0"}}}`)
	write(t, dir, "py/requirements.txt", "Bad_Pkg>=0.9\n")
	write(t, dir, "node_modules/evil/package.json", `{"dependencies": {"evil": "1.0.0"}}`)

	res, err := Run(context.Background(), dir, Options{DB: testDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	want := []got{
		// declared only: every version is malicious, so the range is too
		{"evil", "^1.0.0", "app/package.json", ReasonMalicious, SeverityCritical},
		// locked to a listed malicious version
		{"hijacked", "2.0.1", "app/package-lock.json", ReasonMalicious, SeverityCritical},
		// unpinned requirement on a version-specific record
		{"Bad_Pkg", ">=0.9", "py/requirements.txt", ReasonMalicious, SeverityHigh},
		// locked to a clean version of a hijacked package
		{"hijacked", "2.5.0", "other/package-lock.json", ReasonCompromised, SeverityLow},
	}
	if g := summarize(res.Findings); !reflect.DeepEqual(g, want) {
		t.Fatalf("findings:\n got  %+v\n want %+v", g, want)
	}

	hij := res.Findings[1]
	if !reflect.DeepEqual(hij.IDs, []string{"MAL-2", "MAL-3"}) || hij.URL != maldb.URL("MAL-2") {
		t.Errorf("hijacked ids/url = %v %s", hij.IDs, hij.URL)
	}
	if len(hij.MaliciousVersions) != 3 {
		t.Errorf("malicious versions = %v", hij.MaliciousVersions)
	}
	if res.Findings[0].Campaign != "tea-xyz-token-farming" || res.Findings[0].MaliciousVersions != nil {
		t.Errorf("all-versions finding = %+v", res.Findings[0])
	}

	s := res.Stats
	// package.json: hijacked and fine are covered by the lockfile (skipped);
	// node_modules is never walked.
	if s.Files != 4 || s.Lockfiles != 2 || s.Packages != 5 || s.Skipped != 2 || s.Findings != 4 || s.UniquePackages != 4 {
		t.Errorf("stats = %+v", s)
	}
	if !res.Complete() || res.Database.Records != 4 {
		t.Errorf("complete=%v database=%+v", res.Complete(), res.Database)
	}
}

func TestRunIgnoreExcludeAndWarnings(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a/package-lock.json", `{"lockfileVersion": 3, "packages": {"node_modules/evil": {"version": "1.0.0"}}}`)
	write(t, dir, "fixtures/package-lock.json", `{"lockfileVersion": 3, "packages": {"node_modules/evil": {"version": "1.0.0"}}}`)
	write(t, dir, "b/Cargo.lock", "[[package]]\nname = \"x\"\n")
	write(t, dir, "c/package-lock.json", `{broken`)

	res, err := Run(context.Background(), dir, Options{
		DB:      testDB(t),
		Ignore:  match.New("evil"),
		Exclude: match.New("fixtures"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.Stats.Skipped != 1 {
		t.Fatalf("ignore not applied: %+v", res)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Kind != WarnFile || res.Warnings[0].Manifest != "c/package-lock.json" {
		t.Fatalf("warnings = %+v", res.Warnings)
	}
	if res.Complete() || res.Stats.Errors != 1 {
		t.Errorf("an unparsable lockfile must make the scan incomplete: %+v", res.Stats)
	}
}

func TestRunSingleFile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "requirements.txt", "bad-pkg==1.0\n")
	res, err := Run(context.Background(), p, Options{DB: testDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != SeverityCritical || res.Findings[0].Finders[0] != "kam193" {
		t.Fatalf("findings = %+v", res.Findings)
	}

	if _, err := Run(context.Background(), write(t, dir, "notes.md", "x"), Options{DB: testDB(t)}); err == nil {
		t.Error("want error for an unsupported single file")
	}
	if _, err := Run(context.Background(), filepath.Join(dir, "missing"), Options{DB: testDB(t)}); err == nil {
		t.Error("want error for a missing path")
	}
}

func TestRunCanceled(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package-lock.json", `{"packages": {}}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, dir, Options{DB: testDB(t)}); err == nil {
		t.Error("want context error")
	}
}

func TestRunDefaultDB(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Cargo.lock", "[[package]]\nname = \"proc-macro1\"\nversion = \"1.0.95\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")
	res, err := Run(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].IDs[0] != "MAL-2026-14338" {
		t.Fatalf("embedded snapshot lookup: %+v", res.Findings)
	}
}

func TestSeverity(t *testing.T) {
	for _, s := range []string{"low", "MEDIUM", " high ", "critical"} {
		if _, err := ParseSeverity(s); err != nil {
			t.Errorf("ParseSeverity(%q): %v", s, err)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("want error")
	}
	if SeverityRank("critical") <= SeverityRank("high") || SeverityRank("nope") != 0 {
		t.Error("rank order")
	}
}
