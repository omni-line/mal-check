package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omni-line/mal-check/internal/report"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	lock := `[[package]]
name = "proc-macro1"
version = "1.0.95"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunFindingsJSON(t *testing.T) {
	code, out, _ := runCLI(t, fixture(t), "--format", "json", "--no-marketing")
	if code != report.ExitFindings {
		t.Fatalf("exit %d, want %d", code, report.ExitFindings)
	}
	var doc report.JSONDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || doc.Findings[0].IDs[0] != "MAL-2026-14338" || doc.Sponsor != nil {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestRunFlagsAfterPath(t *testing.T) {
	dir := fixture(t)
	if code, _, _ := runCLI(t, "--fail-on=none", dir, "-q"); code != report.ExitOK {
		t.Fatalf("--fail-on none: exit %d", code)
	}
	if code, out, _ := runCLI(t, dir, "--ignore", "proc-*", "--color", "never"); code != report.ExitOK || !strings.Contains(out, "No known malicious packages") {
		t.Fatalf("--ignore: exit %d\n%s", code, out)
	}
	if code, _, _ := runCLI(t, "--", dir); code != report.ExitFindings {
		t.Fatalf("-- separator: exit %d", code)
	}
}

func TestRunInfoAndHelp(t *testing.T) {
	if code, out, _ := runCLI(t, "--version"); code != report.ExitOK || strings.TrimSpace(out) == "" {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, out, _ := runCLI(t, "--db-info"); code != report.ExitOK || !strings.Contains(out, "github.com/ossf/malicious-packages") {
		t.Errorf("--db-info: %d %q", code, out)
	}
	if code, _, errOut := runCLI(t, "-h"); code != report.ExitOK || !strings.Contains(errOut, "Usage: mal-check") {
		t.Errorf("-h: %d %q", code, errOut)
	}
}

func TestRunErrors(t *testing.T) {
	tests := [][]string{
		{"--format", "xml"},
		{"--color", "rainbow"},
		{"--fail-on", "sometimes"},
		{"--min-severity", "urgent"},
		{"--ignore", "["},
		{"--exclude", "["},
		{"a", "b"},
		{"--format"},
		{"--no-such-flag"},
		{filepath.Join(t.TempDir(), "missing")},
	}
	for _, args := range tests {
		if code, _, errOut := runCLI(t, args...); code != report.ExitError || !strings.Contains(errOut, "error") && !strings.Contains(errOut, "flag") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
}

func TestRunStrict(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, dir, "-q"); code != report.ExitOK {
		t.Errorf("non-strict incomplete: exit %d", code)
	}
	if code, _, _ := runCLI(t, dir, "-q", "--strict"); code != report.ExitError {
		t.Errorf("strict incomplete: exit %d", code)
	}
}

func TestRunCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{fixture(t)}, &out, &errOut); code != report.ExitError || !strings.Contains(errOut.String(), "interrupted") {
		t.Errorf("canceled: exit %d %q", code, errOut.String())
	}
}

func TestEnvTruthy(t *testing.T) {
	t.Setenv("MAL_CHECK_TEST_ENV", " Yes ")
	if !envTruthy("MAL_CHECK_TEST_ENV") {
		t.Error("yes is truthy")
	}
	t.Setenv("MAL_CHECK_TEST_ENV", "0")
	if envTruthy("MAL_CHECK_TEST_ENV") {
		t.Error("0 is falsy")
	}
}
