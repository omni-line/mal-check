package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/omni-line/mal-check/internal/maldb"
	"github.com/omni-line/mal-check/internal/scan"
)

// maxWarnings is how many warnings are printed without --verbose.
const maxWarnings = 10

func writeText(stdout, stderr io.Writer, res *scan.Result, opts Options) {
	c := NewPalette(opts.Color, opts.StdoutIsTTY)
	ec := NewPalette(opts.Color, opts.StderrIsTTY)
	showMarketing := shouldShowMarketing(opts)
	mw, mTTY := marketingWriter(stdout, stderr, opts)
	mc := NewPalette(opts.Color, mTTY)

	if showMarketing {
		fmt.Fprintln(mw, mc.BoldCyan(HeaderLine(opts.Version)))
		fmt.Fprintln(mw, mc.Dim(HeaderSubtitle()))
		fmt.Fprintln(mw)
	}

	shown, hidden := visible(res.Findings, opts.MinSeverity)
	malicious, compromised := splitFindings(shown)
	if len(shown) > 0 {
		if !opts.Quiet {
			writeFindingHeadlines(stdout, c, malicious, compromised)
			fmt.Fprintln(stdout)
		}
		writeFindingsTable(stdout, c, shown, opts.Verbose)
		if !opts.Quiet {
			writeGuidance(stdout, c, malicious, compromised)
		}
	} else if !opts.Quiet {
		switch {
		case res.Stats.Files == 0:
			fmt.Fprintln(stdout, c.BoldYellow("! No supported lockfiles or manifests found."))
		case !res.Complete():
			fmt.Fprintln(stdout, c.BoldYellow("! No known malicious packages, but the scan is incomplete (see warnings)."))
		default:
			fmt.Fprintln(stdout, c.BoldGreen("✓ No known malicious packages found."))
		}
	}

	if opts.Quiet {
		return
	}
	if hidden > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, c.Dim(fmt.Sprintf("%s below --min-severity not listed (packages that shipped malicious releases before; your versions are not among them). Use --min-severity low to list them.",
			plural(hidden, "finding", "findings"))))
	}

	writeWarnings(stderr, ec, res.Warnings, opts.Verbose)

	fmt.Fprintln(stdout)
	summary := summaryLine(res)
	if res.Stats.Findings > 0 {
		fmt.Fprintln(stdout, c.BoldYellow(summary))
	} else {
		fmt.Fprintln(stdout, c.Dim(summary))
	}

	if showMarketing {
		fmt.Fprintln(mw)
		fmt.Fprintln(mw, colorFooter(mc, len(malicious), len(compromised)))
	}
}

func writeFindingHeadlines(w io.Writer, c Palette, malicious, compromised []scan.Finding) {
	if len(malicious) > 0 {
		head := plural(distinct(malicious), "known malicious package", "known malicious packages") + " found"
		if n := len(malicious); n != distinct(malicious) {
			head += fmt.Sprintf(" (%d occurrences)", n)
		}
		fmt.Fprintln(w, c.BoldRed("✗ "+head))
	}
	if len(compromised) > 0 {
		fmt.Fprintln(w, c.BoldYellow(fmt.Sprintf("! %s with past malicious releases (your version is not one of them)",
			plural(distinct(compromised), "package", "packages"))))
	}
}

// distinct counts packages, not rows: one package can appear in several files.
func distinct(findings []scan.Finding) int {
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.Ecosystem+"\x00"+maldb.Normalize(f.Ecosystem, f.Package)] = true
	}
	return len(seen)
}

type column struct {
	header string
	style  func(string) string
}

func writeFindingsTable(w io.Writer, c Palette, findings []scan.Finding, verbose bool) {
	cols := []column{
		{"SEVERITY", severityStyle(c)},
		{"ECOSYSTEM", c.Yellow},
		{"PACKAGE", c.Bold},
		{"VERSION", c.Dim},
		{"LOCATION", c.Cyan},
		{"ADVISORY", c.Dim},
		{"NOTE", c.Dim},
	}
	rows := make([][]string, len(findings))
	for i, f := range findings {
		version := f.Version
		if version == "" {
			version = "-"
		}
		loc := f.Manifest
		if f.Line > 0 {
			loc += ":" + strconv.Itoa(f.Line)
		}
		advisory := "-"
		if len(f.IDs) > 0 {
			advisory = f.IDs[0]
			if len(f.IDs) > 1 {
				advisory += fmt.Sprintf(" (+%d)", len(f.IDs)-1)
			}
		}
		rows[i] = []string{clean(f.Severity), clean(f.Ecosystem), clean(f.Package), clean(version), clean(loc), clean(advisory), clean(note(f))}
	}

	widths := make([]int, len(cols))
	for i, col := range cols {
		widths[i] = utf8.RuneCountInString(col.header)
	}
	for _, row := range rows {
		for i, cell := range row {
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}

	line := func(cells []string, style func(i int, s string) string) string {
		var b strings.Builder
		b.WriteString("  ")
		for i, cell := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			pad := ""
			if i < len(cells)-1 {
				pad = strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell))
			}
			b.WriteString(style(i, cell))
			b.WriteString(pad)
		}
		return strings.TrimRight(b.String(), " ")
	}

	headers := make([]string, len(cols))
	for i, col := range cols {
		headers[i] = col.header
	}
	fmt.Fprintln(w, line(headers, func(_ int, s string) string { return c.Dim(s) }))
	for i, row := range rows {
		fmt.Fprintln(w, line(row, func(i int, s string) string { return cols[i].style(s) }))
		if verbose {
			f := findings[i]
			if f.URL != "" {
				fmt.Fprintf(w, "  %s %s\n", c.Dim("↳"), c.Dim(clean(f.URL)))
			}
			if len(f.Finders) > 0 {
				fmt.Fprintf(w, "  %s %s\n", c.Dim("↳"), c.Dim("reported by "+clean(strings.Join(f.Finders, ", "))))
			}
			if len(f.MaliciousVersions) > 0 {
				fmt.Fprintf(w, "  %s %s\n", c.Dim("↳"), c.Dim("malicious versions: "+clean(strings.Join(f.MaliciousVersions, ", "))))
			}
		}
	}
}

// note is the short NOTE cell: why the verdict is what it is.
func note(f scan.Finding) string {
	switch {
	case f.Reason == scan.ReasonCompromised:
		return "past malicious versions; yours is clean"
	case f.Severity == scan.SeverityHigh:
		return "version not pinned; some versions malicious"
	case f.Campaign != "":
		return f.Campaign
	case f.Exact:
		return "installed version is malicious"
	default:
		return "every version is malicious"
	}
}

func writeGuidance(w io.Writer, c Palette, malicious, compromised []scan.Finding) {
	if len(malicious) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "These packages were published to a public registry as malware (OpenSSF MAL-")
		fmt.Fprintln(w, "advisories). Install hooks run on `npm install` / `pip install`, so a machine")
		fmt.Fprintln(w, "that installed one may already have leaked its environment variables and tokens.")
	}
	if len(compromised) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "These packages were hijacked at some point and shipped malicious releases.")
		fmt.Fprintln(w, "The version you lock is not one of them.")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.Bold("How to fix"))
	if len(malicious) > 0 {
		fmt.Fprintf(w, "  %s  %s\n", c.Yellow("malicious  "), scan.Remediation)
	}
	if len(compromised) > 0 {
		fmt.Fprintf(w, "  %s  %s\n", c.Yellow("compromised"), scan.RemediationCompromised)
	}
}

func writeWarnings(w io.Writer, c Palette, warnings []scan.Warning, verbose bool) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.BoldYellow(fmt.Sprintf("Warnings (%d) — results may be incomplete", len(warnings))))
	shown := warnings
	if !verbose && len(shown) > maxWarnings {
		shown = shown[:maxWarnings]
	}
	for _, wn := range shown {
		kind := wn.Kind
		if kind == "" {
			kind = "warn"
		}
		fmt.Fprintf(w, "  %s %s: %s\n", c.Yellow(kind), clean(wn.Manifest), clean(wn.Message))
	}
	if hidden := len(warnings) - len(shown); hidden > 0 {
		fmt.Fprintf(w, "  %s\n", c.Dim(fmt.Sprintf("… and %d more (use -v to show all)", hidden)))
	}
}

func summaryLine(res *scan.Result) string {
	s := res.Stats
	packages := plural(s.Packages, "package", "packages")
	if s.UniquePackages > 0 && s.UniquePackages != s.Packages {
		packages += fmt.Sprintf(" (%d unique)", s.UniquePackages)
	}
	files := plural(s.Files, "file", "files")
	if s.Lockfiles > 0 {
		files += fmt.Sprintf(" (%d %s)", s.Lockfiles, pick(s.Lockfiles, "lockfile", "lockfiles"))
	}
	line := strings.Join([]string{
		"Scanned " + files,
		packages,
		plural(s.Findings, "finding", "findings"),
		fmt.Sprintf("%d skipped", s.Skipped),
		plural(s.Errors, "error", "errors"),
	}, " · ")
	if s.DurationMS > 0 {
		line += " in " + formatDuration(time.Duration(s.DurationMS)*time.Millisecond)
	}
	if db := res.Database; db.Records > 0 {
		line += fmt.Sprintf("\nDatabase: %s known malicious packages (OpenSSF, %s)", thousands(db.Records), dateOf(db.GeneratedAt))
	}
	return line
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func plural(n int, one, many string) string {
	return strconv.Itoa(n) + " " + pick(n, one, many)
}

func pick(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func dateOf(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return "unknown date"
}

func severityStyle(c Palette) func(string) string {
	return func(s string) string {
		switch s {
		case scan.SeverityCritical:
			return c.BoldRed(s)
		case scan.SeverityHigh:
			return c.BoldYellow(s)
		case scan.SeverityMedium:
			return c.Yellow(s)
		default:
			return c.Dim(s)
		}
	}
}

func splitFindings(findings []scan.Finding) (malicious, compromised []scan.Finding) {
	for _, f := range findings {
		if f.Reason == scan.ReasonCompromised {
			compromised = append(compromised, f)
		} else {
			malicious = append(malicious, f)
		}
	}
	return malicious, compromised
}

func colorFooter(c Palette, malicious, compromised int) string {
	plain := FooterText(malicious, compromised)
	if !c.Enabled() {
		return plain
	}
	lines := strings.Split(plain, "\n")
	out := make([]string, 0, len(lines))
	findingCount := malicious + compromised
	for i, line := range lines {
		switch {
		case i == 0 && strings.HasPrefix(line, "───"):
			out = append(out, c.Dim(line))
		case strings.Contains(line, "https://"):
			out = append(out, c.BoldCyan(line))
		case i == 1 && findingCount > 0:
			out = append(out, c.BoldYellow(line))
		case i == 1:
			out = append(out, c.Green(line))
		default:
			out = append(out, c.Dim(line))
		}
	}
	return strings.Join(out, "\n")
}
