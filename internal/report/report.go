// Package report renders scan results as text, JSON, or SARIF and maps them
// to process exit codes.
package report

import (
	"fmt"
	"io"
	"os"

	"github.com/omni-line/mal-check/internal/scan"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// Format is the output format.
type Format string

// Supported formats.
const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case FormatText, FormatJSON, FormatSARIF:
		return f, nil
	default:
		return "", fmt.Errorf("invalid --format %q (want text|json|sarif)", s)
	}
}

// Options controls how results are written.
type Options struct {
	Format  Format
	Version string
	Quiet   bool
	Verbose bool
	// MinSeverity hides findings below it from text and SARIF output (they
	// are summarized in one line instead). JSON always carries every finding.
	// Empty means medium, matching the default exit policy.
	MinSeverity string
	NoMarketing bool
	ForceMarket bool
	StdoutIsTTY bool
	StderrIsTTY bool
	Color       ColorMode
}

// Policy decides the exit code for a result.
type Policy struct {
	// FailOnFindings exits 1 when there are findings (--fail-on any).
	FailOnFindings bool
	// Strict exits 2 when the scan is incomplete and nothing else failed.
	Strict bool
	// MinSeverity is the lowest finding severity that fails the build.
	// Empty means medium: previously_compromised (low) findings inform but
	// do not fail.
	MinSeverity string
}

// Write renders res to stdout (and warnings/marketing to stderr as needed).
func Write(stdout, stderr io.Writer, res *scan.Result, opts Options) error {
	if res == nil {
		return fmt.Errorf("empty scan result")
	}
	switch opts.Format {
	case FormatJSON:
		return writeJSON(stdout, res, opts)
	case FormatSARIF:
		return writeSARIF(stdout, res, opts)
	default:
		writeText(stdout, stderr, res, opts)
		return nil
	}
}

// ExitCode maps a result to a process exit code. Findings take precedence
// over incompleteness so that "1" always means "something was found".
func ExitCode(res *scan.Result, p Policy) int {
	switch {
	case res == nil:
		return ExitError
	case p.FailOnFindings && hasFindingAtLeast(res, p.MinSeverity):
		return ExitFindings
	case p.Strict && !res.Complete():
		return ExitError
	default:
		return ExitOK
	}
}

func hasFindingAtLeast(res *scan.Result, min string) bool {
	if min == "" {
		min = scan.SeverityMedium
	}
	threshold := scan.SeverityRank(min)
	for _, f := range res.Findings {
		if scan.SeverityRank(f.Severity) >= threshold {
			return true
		}
	}
	return false
}

// visible splits findings into those at or above min and a count of the rest.
func visible(findings []scan.Finding, min string) (shown []scan.Finding, hidden int) {
	if min == "" {
		min = scan.SeverityMedium
	}
	threshold := scan.SeverityRank(min)
	for _, f := range findings {
		if scan.SeverityRank(f.Severity) >= threshold {
			shown = append(shown, f)
		} else {
			hidden++
		}
	}
	return shown, hidden
}

func shouldShowMarketing(opts Options) bool {
	switch {
	case opts.Quiet || opts.NoMarketing:
		return false
	case opts.ForceMarket, opts.Format == FormatJSON:
		return true
	default:
		return opts.StdoutIsTTY || opts.StderrIsTTY
	}
}

// marketingWriter keeps banners out of piped stdout unless forced.
func marketingWriter(stdout, stderr io.Writer, opts Options) (io.Writer, bool) {
	if opts.ForceMarket || opts.StdoutIsTTY {
		return stdout, opts.StdoutIsTTY
	}
	return stderr, opts.StderrIsTTY
}

// IsTTY reports whether f is a terminal.
func IsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
