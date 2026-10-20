// Command update-data rebuilds the embedded malicious-package snapshot from a
// local checkout of https://github.com/ossf/malicious-packages.
//
//	git clone --depth 1 https://github.com/ossf/malicious-packages /tmp/mp
//	go run ./scripts/update-data -src /tmp/mp -out internal/maldb
//
// It reads only osv/malicious/**: osv/withdrawn holds false positives, and a
// snapshot whose every record means "malware" must not carry them. It is not
// used at scan time; scans read the committed snapshot offline.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/omni-line/mal-check/internal/maldb"
)

// osvEcosystems maps OSV ecosystem names to snapshot ids (and registry, when
// one id spans several registries). Unknown ecosystems are counted and skipped.
var osvEcosystems = map[string][2]string{
	"npm":                         {maldb.NPM, ""},
	"PyPI":                        {maldb.PyPI, ""},
	"RubyGems":                    {maldb.RubyGems, ""},
	"NuGet":                       {maldb.NuGet, ""},
	"crates.io":                   {maldb.Cargo, ""},
	"Go":                          {maldb.Go, ""},
	"Packagist":                   {maldb.Composer, ""},
	"Maven":                       {maldb.Maven, ""},
	"VSCode":                      {maldb.VSCode, "marketplace.visualstudio.com"},
	"VSCode:https://open-vsx.org": {maldb.VSCode, "open-vsx.org"},
}

// campaigns label mass campaigns whose records share one boilerplate body.
var campaigns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`(?i)tea\.xyz token reward`), "tea-xyz-token-farming"},
	{regexp.MustCompile(`(?i)EsqueleSquad`), "esquelesquad"},
}

type osvRecord struct {
	ID        string `json:"id"`
	Published string `json:"published"`
	Withdrawn string `json:"withdrawn"`
	Details   string `json:"details"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Versions []string `json:"versions"`
		Ranges   []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Credits []struct {
		Name string `json:"name"`
	} `json:"credits"`
}

func main() {
	src := flag.String("src", "", "path to a checkout of ossf/malicious-packages")
	out := flag.String("out", "internal/maldb", "output directory for malicious.json.gz and meta.json")
	flag.Parse()
	if *src == "" {
		fmt.Fprintln(os.Stderr, "update-data: -src is required")
		os.Exit(2)
	}
	if err := run(*src, *out); err != nil {
		fmt.Fprintf(os.Stderr, "update-data: %v\n", err)
		os.Exit(1)
	}
}

func run(src, out string) error {
	root := filepath.Join(src, "osv", "malicious")
	var (
		records []maldb.Record
		skipped = map[string]int{}
	)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "MAL-") || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r osvRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if r.Withdrawn != "" {
			skipped["withdrawn"]++
			return nil
		}
		for _, a := range r.Affected {
			eco, ok := osvEcosystems[a.Package.Ecosystem]
			if !ok || a.Package.Name == "" {
				skipped["ecosystem:"+a.Package.Ecosystem]++
				continue
			}
			rec := maldb.Record{
				ID:        r.ID,
				Ecosystem: eco[0],
				Registry:  eco[1],
				Name:      a.Package.Name,
				Published: dateOnly(r.Published),
				Campaign:  campaignOf(r.Details),
				Finders:   finders(r),
			}
			rec.All, rec.Ranges = intervals(a.Ranges)
			if !rec.All {
				rec.Versions = a.Versions
				if len(rec.Versions) == 0 && len(rec.Ranges) == 0 {
					// No version data at all: the advisory names the package
					// without bounding it, so treat every version as affected.
					rec.All = true
				}
			} else {
				rec.Ranges = nil
			}
			records = append(records, rec)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Ecosystem != records[j].Ecosystem {
			return records[i].Ecosystem < records[j].Ecosystem
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].ID < records[j].ID
	})

	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}
	// Fixed header so the same input produces byte-identical output.
	zw.ModTime = time.Time{}
	enc := json.NewEncoder(zw)
	for i := range records {
		if err := enc.Encode(&records[i]); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "malicious.json.gz"), buf.Bytes(), 0o644); err != nil {
		return err
	}

	meta := maldb.Meta{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      "https://github.com/ossf/malicious-packages",
		Commit:      gitHead(src),
		License:     "Apache-2.0",
		Records:     len(records),
		Ecosystems:  map[string]int{},
	}
	for _, r := range records {
		meta.Ecosystems[r.Ecosystem]++
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "meta.json"), append(mb, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d records (%d bytes gz) from %s @%s\n", len(records), buf.Len(), src, meta.Commit)
	for k, n := range skipped {
		fmt.Printf("  skipped %s: %d\n", k, n)
	}
	return nil
}

// intervals converts OSV range events to closed/half-open intervals. all is
// true when any range is introduced "0" with no end, which affects every
// version and makes the rest irrelevant.
func intervals(ranges []struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}) (all bool, out []maldb.Range) {
	for _, r := range ranges {
		var cur *maldb.Range
		for _, ev := range r.Events {
			switch {
			case ev["introduced"] != "":
				if cur != nil {
					out = append(out, *cur)
				}
				cur = &maldb.Range{Type: r.Type, Introduced: ev["introduced"]}
			case ev["fixed"] != "" || ev["last_affected"] != "":
				if cur == nil {
					cur = &maldb.Range{Type: r.Type, Introduced: "0"}
				}
				cur.Fixed, cur.LastAffected = ev["fixed"], ev["last_affected"]
				out = append(out, *cur)
				cur = nil
			}
		}
		if cur != nil {
			out = append(out, *cur)
		}
	}
	for _, r := range out {
		if r.Introduced == "0" && r.Fixed == "" && r.LastAffected == "" {
			return true, nil
		}
	}
	for i := range out {
		if out[i].Introduced == "0" {
			out[i].Introduced = ""
		}
	}
	return false, out
}

func campaignOf(details string) string {
	for _, c := range campaigns {
		if c.re.MatchString(details) {
			return c.label
		}
	}
	return ""
}

func finders(r osvRecord) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range r.Credits {
		if n := strings.TrimSpace(c.Name); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func dateOnly(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

func gitHead(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
