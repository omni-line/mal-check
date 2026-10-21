// Package cli implements the mal-check command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/omni-line/mal-check/internal/match"
	"github.com/omni-line/mal-check/internal/report"
	"github.com/omni-line/mal-check/internal/scan"
	"github.com/omni-line/mal-check/internal/version"
	"github.com/omni-line/mal-check/pkg/maldb"
)

// stringList accumulates repeatable or comma-separated flag values.
type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

type config struct {
	root        string
	format      report.Format
	color       report.ColorMode
	failAny     bool
	strict      bool
	minSeverity string
	quiet       bool
	verbose     bool
	noMarketing bool
	forceMarket bool
	ignore      *match.Matcher
	exclude     *match.Matcher
	dbInfo      bool
}

// errHelp signals that usage was printed on request.
var errHelp = errors.New("help requested")

// Run executes the CLI and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, args, stdout, stderr)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, showVersion, err := parse(args, stderr)
	switch {
	case errors.Is(err, errHelp):
		return report.ExitOK
	case err != nil:
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	case showVersion:
		fmt.Fprintln(stdout, version.String())
		return report.ExitOK
	}

	db, err := maldb.Default()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}
	if cfg.dbInfo {
		return writeDBInfo(stdout, db)
	}

	res, err := scan.Run(ctx, cfg.root, scan.Options{
		DB:      db,
		Ignore:  cfg.ignore,
		Exclude: cfg.exclude,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "error: interrupted")
		} else {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
		return report.ExitError
	}

	stdoutFile, _ := stdout.(*os.File)
	stderrFile, _ := stderr.(*os.File)
	if err := report.Write(stdout, stderr, res, report.Options{
		Format:      cfg.format,
		Version:     version.String(),
		Quiet:       cfg.quiet,
		Verbose:     cfg.verbose,
		MinSeverity: cfg.minSeverity,
		NoMarketing: cfg.noMarketing,
		ForceMarket: cfg.forceMarket,
		StdoutIsTTY: report.IsTTY(stdoutFile),
		StderrIsTTY: report.IsTTY(stderrFile),
		Color:       cfg.color,
	}); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}
	return report.ExitCode(res, report.Policy{
		FailOnFindings: cfg.failAny,
		Strict:         cfg.strict,
		MinSeverity:    cfg.minSeverity,
	})
}

func writeDBInfo(w io.Writer, db *maldb.DB) int {
	m := db.Meta()
	fmt.Fprintf(w, "records:    %d\n", db.Len())
	fmt.Fprintf(w, "source:     %s\n", m.Source)
	fmt.Fprintf(w, "commit:     %s\n", m.Commit)
	fmt.Fprintf(w, "generated:  %s\n", m.GeneratedAt)
	fmt.Fprintf(w, "license:    %s\n", m.License)
	return report.ExitOK
}

func parse(args []string, stderr io.Writer) (cfg config, showVersion bool, err error) {
	fs := flag.NewFlagSet("mal-check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		format      = fs.String("format", "text", "output format: text|json|sarif")
		failOn      = fs.String("fail-on", "any", "when to exit 1: any|none")
		strict      = fs.Bool("strict", false, "exit 2 if any lockfile or manifest could not be read or parsed")
		minSeverity = fs.String("min-severity", "medium", "minimum severity that is listed (text, SARIF) and fails the build: low|medium|high|critical")
		colorMode   = fs.String("color", "auto", "color output: auto|always|never")
		quiet       = fs.Bool("q", false, "findings only; suppress banner, warnings, summary, and marketing")
		quietLong   = fs.Bool("quiet", false, "alias for -q")
		noMarketing = fs.Bool("no-marketing", false, "hide Omni Line CTA / JSON sponsor")
		forceMarket = fs.Bool("marketing", false, "force marketing even when non-TTY")
		verbose     = fs.Bool("v", false, "verbose: show advisory URLs, finders, and malicious versions")
		verboseLong = fs.Bool("verbose", false, "alias for -v")
		versionFlag = fs.Bool("version", false, "print version and exit")
		dbInfo      = fs.Bool("db-info", false, "print the embedded database's source commit and size, then exit")
		ignore      stringList
		exclude     stringList
	)
	fs.Var(&ignore, "ignore", "package name globs to skip (repeatable or comma-separated)")
	fs.Var(&exclude, "exclude", "path globs or directory names to skip, relative to the scan root (repeatable or comma-separated)")
	fs.Usage = func() { usage(fs, stderr) }

	flagArgs, positional, err := splitArgs(fs, args)
	if err != nil {
		return cfg, false, err
	}
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, false, errHelp
		}
		return cfg, false, err
	}
	if *versionFlag {
		return cfg, true, nil
	}

	cfg.root = "."
	switch len(positional) {
	case 0:
	case 1:
		cfg.root = positional[0]
	default:
		return cfg, false, errors.New("too many path arguments (want at most one)")
	}

	if cfg.format, err = report.ParseFormat(strings.ToLower(*format)); err != nil {
		return cfg, false, err
	}
	if cfg.color, err = report.ParseColorMode(*colorMode); err != nil {
		return cfg, false, err
	}
	switch strings.ToLower(*failOn) {
	case "any":
		cfg.failAny = true
	case "none":
	default:
		return cfg, false, fmt.Errorf("invalid --fail-on %q (want any|none)", *failOn)
	}
	if cfg.minSeverity, err = scan.ParseSeverity(*minSeverity); err != nil {
		return cfg, false, fmt.Errorf("invalid --min-severity %q (want low|medium|high|critical)", *minSeverity)
	}
	if cfg.ignore, err = match.Compile(ignore...); err != nil {
		return cfg, false, fmt.Errorf("--ignore: %w", err)
	}
	if cfg.exclude, err = match.Compile(exclude...); err != nil {
		return cfg, false, fmt.Errorf("--exclude: %w", err)
	}

	cfg.strict = *strict
	cfg.quiet = *quiet || *quietLong
	cfg.verbose = *verbose || *verboseLong
	cfg.noMarketing = *noMarketing || envTruthy("MAL_CHECK_NO_MARKETING")
	cfg.forceMarket = *forceMarket
	cfg.dbInfo = *dbInfo
	return cfg, false, nil
}

func usage(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprint(w, `Usage: mal-check [path] [flags]

Check a project tree (or a single lockfile or manifest) for packages that were
published to a public registry as malware: npm, PyPI, RubyGems, NuGet,
crates.io, Go, Composer, and VS Code / Open VSX extensions. The check is
offline, against an embedded snapshot of OpenSSF malicious-packages (MAL-)
advisories. Nothing leaves the machine.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprint(w, `
Severities:
  critical  the installed version (or every version) is malicious
  high      some versions are malicious and yours is not pinned
  low       past versions were malicious; yours is not (summarized, not listed
            or failed, unless --min-severity low)

Exit codes:
  0  no findings at or above --min-severity (or --fail-on none)
  1  findings reported
  2  usage or runtime error, or an incomplete scan with --strict

Environment:
  MAL_CHECK_NO_MARKETING=1  same as --no-marketing
  NO_COLOR=1                disable ANSI colors (also --color never)
  FORCE_COLOR=1             enable colors even when non-TTY
`)
}

// splitArgs allows `mal-check [path] [flags]` by separating flags from
// positional arguments. Whether a flag consumes the next argument is derived
// from the FlagSet itself, so new flags need no extra bookkeeping here.
func splitArgs(fs *flag.FlagSet, args []string) (flagArgs, positional []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // fs.Parse reports unknown flags
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return nil, nil, fmt.Errorf("flag %s requires a value", a)
		}
		i++
		flagArgs = append(flagArgs, args[i])
	}
	return flagArgs, positional, nil
}

func envTruthy(key string) bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
