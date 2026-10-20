package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/omni-line/mal-check/internal/maldb"
	"github.com/omni-line/mal-check/internal/scan"
)

func sample() *scan.Result {
	return &scan.Result{
		Findings: []scan.Finding{
			{Ecosystem: "cargo", Package: "proc-macro1", Version: "1.0.95", Exact: true, Manifest: "Cargo.lock", Line: 4,
				Reason: scan.ReasonMalicious, Severity: scan.SeverityCritical, IDs: []string{"MAL-2026-14338"},
				URL: maldb.URL("MAL-2026-14338"), Finders: []string{"SafeDep"}},
			{Ecosystem: "npm", Package: "spam\x1b[31m", Manifest: "package.json", Reason: scan.ReasonMalicious,
				Severity: scan.SeverityCritical, IDs: []string{"MAL-1", "MAL-2"}, Campaign: "tea-xyz-token-farming"},
			{Ecosystem: "pypi", Package: "bad", Version: ">=1", Manifest: "requirements.txt", Reason: scan.ReasonMalicious,
				Severity: scan.SeverityHigh, IDs: []string{"MAL-3"}, MaliciousVersions: []string{"1.0"}},
			{Ecosystem: "npm", Package: "nx", Version: "21.4.0", Exact: true, Manifest: "package-lock.json",
				Reason: scan.ReasonCompromised, Severity: scan.SeverityLow, IDs: []string{"MAL-2025-41443"}},
		},
		Stats:    scan.Stats{Files: 3, Lockfiles: 2, Packages: 10, UniquePackages: 9, Findings: 4, DurationMS: 12},
		Database: maldb.Meta{Records: 239358, GeneratedAt: "2026-10-20T20:33:01Z"},
	}
}

func TestParseFormat(t *testing.T) {
	for _, f := range []string{"text", "json", "sarif"} {
		if _, err := ParseFormat(f); err != nil {
			t.Error(err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("want error")
	}
}

func TestExitCode(t *testing.T) {
	res := sample()
	low := &scan.Result{Findings: []scan.Finding{{Severity: scan.SeverityLow}}}
	incomplete := &scan.Result{Warnings: []scan.Warning{{Message: "x"}}}
	tests := []struct {
		name string
		res  *scan.Result
		p    Policy
		want int
	}{
		{"findings fail", res, Policy{FailOnFindings: true}, ExitFindings},
		{"fail-on none", res, Policy{}, ExitOK},
		{"low does not fail by default", low, Policy{FailOnFindings: true}, ExitOK},
		{"low fails at --min-severity low", low, Policy{FailOnFindings: true, MinSeverity: "low"}, ExitFindings},
		{"high is below critical", &scan.Result{Findings: []scan.Finding{{Severity: scan.SeverityHigh}}},
			Policy{FailOnFindings: true, MinSeverity: "critical"}, ExitOK},
		{"strict incomplete", incomplete, Policy{FailOnFindings: true, Strict: true}, ExitError},
		{"non-strict incomplete", incomplete, Policy{FailOnFindings: true}, ExitOK},
		{"nil", nil, Policy{}, ExitError},
	}
	for _, tt := range tests {
		if got := ExitCode(tt.res, tt.p); got != tt.want {
			t.Errorf("%s: ExitCode = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestWriteText(t *testing.T) {
	var out, errOut bytes.Buffer
	res := sample()
	res.Warnings = []scan.Warning{{Kind: scan.WarnFile, Manifest: "bad/yarn.lock", Message: "boom"}}
	if err := Write(&out, &errOut, res, Options{Format: FormatText, Version: "v1.2.3", ForceMarket: true, Verbose: true, Color: ColorNever, MinSeverity: "low"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"mal-check v1.2.3 — Malicious package check",
		"✗ 3 known malicious packages found",
		"! 1 package with past malicious releases",
		"Cargo.lock:4",
		"MAL-1 (+1)",
		"tea-xyz-token-farming",
		"version not pinned; some versions malicious",
		"past malicious versions; yours is clean",
		"installed version is malicious",
		"↳ https://osv.dev/vulnerability/MAL-2026-14338",
		"reported by SafeDep",
		"malicious versions: 1.0",
		"How to fix",
		"Scanned 3 files (2 lockfiles) · 10 packages (9 unique) · 4 findings",
		"in 12ms",
		"Database: 239,358 known malicious packages (OpenSSF, 2026-10-20)",
		"blocks MAL- packages",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("text output missing %q\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b[31m") {
		t.Error("escape sequence from a scanned file reached the terminal")
	}
	if !strings.Contains(errOut.String(), "Warnings (1)") || !strings.Contains(errOut.String(), "bad/yarn.lock: boom") {
		t.Errorf("warnings: %q", errOut.String())
	}
}

// By default low findings (clean versions of once-hijacked packages) are
// summarized, not listed: on a real monorepo they are hundreds of rows.
func TestDefaultThresholdHidesLow(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, &bytes.Buffer{}, sample(), Options{Format: FormatText, Color: ColorNever}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Contains(s, "nx ") || !strings.Contains(s, "1 finding below --min-severity not listed") {
		t.Errorf("low finding should be summarized:\n%s", s)
	}

	onlyLow := &scan.Result{Findings: sample().Findings[3:], Stats: scan.Stats{Files: 1, Findings: 1}}
	out.Reset()
	if err := Write(&out, &bytes.Buffer{}, onlyLow, Options{Format: FormatText, Color: ColorNever}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "✓ No known malicious packages found.") {
		t.Errorf("only-low scan should read as clean:\n%s", out.String())
	}

	var sarif bytes.Buffer
	if err := Write(&sarif, nil, sample(), Options{Format: FormatSARIF}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(sarif.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if n := len(log.Runs[0].Results); n != 3 {
		t.Errorf("SARIF results = %d, want 3 (low hidden)", n)
	}
}

func TestWriteTextStates(t *testing.T) {
	tests := []struct {
		name string
		res  *scan.Result
		want string
	}{
		{"clean", &scan.Result{Stats: scan.Stats{Files: 2}}, "✓ No known malicious packages found."},
		{"nothing found", &scan.Result{}, "No supported lockfiles or manifests found."},
		{"incomplete", &scan.Result{Stats: scan.Stats{Files: 1}, Warnings: []scan.Warning{{Message: "x"}}}, "scan is incomplete"},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		if err := Write(&out, &bytes.Buffer{}, tt.res, Options{Format: FormatText}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), tt.want) {
			t.Errorf("%s: got %q", tt.name, out.String())
		}
	}
}

func TestWriteTextQuietAndPiped(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Write(&out, &errOut, sample(), Options{Format: FormatText, Quiet: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "How to fix") || strings.Contains(out.String(), "Scanned") || errOut.Len() > 0 {
		t.Errorf("quiet leaked prose: %q / %q", out.String(), errOut.String())
	}

	// A TTY on stderr only: marketing goes there, never into piped stdout.
	out.Reset()
	errOut.Reset()
	if err := Write(&out, &errOut, sample(), Options{Format: FormatText, StderrIsTTY: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "omniline.app") || !strings.Contains(errOut.String(), "omniline.app") {
		t.Errorf("marketing routing: stdout %q stderr %q", out.String(), errOut.String())
	}
}

func TestWriteTextColor(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, &bytes.Buffer{}, sample(), Options{Format: FormatText, ForceMarket: true, Color: ColorAlways}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\x1b[1;31mcritical") {
		t.Error("expected colored severity")
	}
}

func TestWriteJSON(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, nil, sample(), Options{Format: FormatJSON, Version: "1.0.0"}); err != nil {
		t.Fatal(err)
	}
	var doc JSONDocument
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != 1 || len(doc.Findings) != 4 || doc.Sponsor == nil || doc.Database.Records != 239358 {
		t.Fatalf("doc = %+v", doc)
	}
	if doc.Sponsor.Message != SharpMessage() {
		t.Error("findings should get the sharp sponsor message")
	}

	out.Reset()
	if err := Write(&out, nil, &scan.Result{}, Options{Format: FormatJSON, NoMarketing: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"findings": []`) || strings.Contains(out.String(), "sponsor") {
		t.Errorf("clean JSON: %s", out.String())
	}
	if NewSponsor(0).Message != SoftMessage() {
		t.Error("clean scans get the soft message")
	}
}

func TestWriteSARIF(t *testing.T) {
	var out bytes.Buffer
	res := sample()
	res.Warnings = []scan.Warning{{Manifest: "x", Message: "y"}}
	if err := Write(&out, nil, res, Options{Format: FormatSARIF, Version: "v0.1.0", MinSeverity: "low"}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Version != "0.1.0" || len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 4 {
		t.Fatalf("run = %+v", run)
	}
	if run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].ToolExecutionNotifications) != 1 {
		t.Error("warnings should mark the invocation incomplete")
	}
	levels := map[string]string{}
	for _, r := range run.Results {
		levels[r.Properties["package"]+"/"+r.RuleID] = r.Level
	}
	if levels["proc-macro1/MC001"] != "error" || levels["nx/MC002"] != "note" || levels["bad/MC001"] != "error" {
		t.Errorf("levels = %v", levels)
	}
	if run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 4 {
		t.Error("line not carried")
	}
	if a, b := run.Results[0].PartialFingerprints[fingerprintK], run.Results[1].PartialFingerprints[fingerprintK]; a == "" || a == b {
		t.Error("fingerprints must be set and distinct")
	}
	if _, sev := sarifSeverity(scan.SeverityMedium); sev != "5.5" {
		t.Error("medium security-severity")
	}
}

func TestColorMode(t *testing.T) {
	for in, want := range map[string]ColorMode{"": ColorAuto, "always": ColorAlways, "off": ColorNever} {
		got, err := ParseColorMode(in)
		if err != nil || got != want {
			t.Errorf("ParseColorMode(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseColorMode("rainbow"); err == nil {
		t.Error("want error")
	}
	t.Setenv("NO_COLOR", "1")
	if NewPalette(ColorAuto, true).Enabled() {
		t.Error("NO_COLOR must win in auto mode")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	if !NewPalette(ColorAuto, false).Enabled() {
		t.Error("FORCE_COLOR enables color on non-TTY")
	}
}

func TestClean(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"a\x1b[2Jb", "a\\u001b[2Jb"},
		{"rtl\u202eover", "rtl\\u202eover"},
		{"bad\xffbyte", "bad\\xffbyte"},
		{"ünïcödé is fine", "ünïcödé is fine"},
	}
	for _, tt := range tests {
		if got := clean(tt.in); got != tt.want {
			t.Errorf("clean(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsTTY(t *testing.T) {
	if IsTTY(nil) {
		t.Error("nil is not a TTY")
	}
}
