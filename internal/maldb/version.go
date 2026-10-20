package maldb

import (
	"strconv"
	"strings"
)

// Verdict is how a record relates to one concrete version.
type Verdict int

// Verdicts, from most to least certain that the installed code is malware.
const (
	// Affected: this exact version is malicious (or every version is).
	Affected Verdict = iota
	// Unknown: the record bounds specific versions and the installed
	// version is unknown or cannot be compared.
	Unknown
	// Clean: specific versions were malicious and this one is not among them.
	Clean
)

// Check reports whether version is covered by rec. An empty version means
// "declared without a concrete version" (a range in package.json, an unpinned
// requirement).
func Check(rec Record, version string) Verdict {
	if rec.All {
		return Affected
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return Unknown
	}
	v := strings.TrimPrefix(version, "v")
	for _, mv := range rec.Versions {
		if mv == version || strings.TrimPrefix(mv, "v") == v {
			return Affected
		}
	}
	verdict := Clean
	for _, r := range rec.Ranges {
		switch inRange(r, v) {
		case Affected:
			return Affected
		case Unknown:
			verdict = Unknown
		}
	}
	return verdict
}

func inRange(r Range, v string) Verdict {
	if r.Introduced != "" {
		c, ok := compare(v, r.Introduced)
		if !ok {
			return Unknown
		}
		if c < 0 {
			return Clean
		}
	}
	if r.Fixed != "" {
		c, ok := compare(v, r.Fixed)
		if !ok {
			return Unknown
		}
		if c >= 0 {
			return Clean
		}
	}
	if r.LastAffected != "" {
		c, ok := compare(v, r.LastAffected)
		if !ok {
			return Unknown
		}
		if c > 0 {
			return Clean
		}
	}
	return Affected
}

// compare orders two versions by dot-separated numeric release segments,
// then by SemVer pre-release (a pre-release sorts before its release). ok is
// false when either side has a non-numeric release segment; callers then
// treat the comparison as unknown rather than guessing.
func compare(a, b string) (c int, ok bool) {
	ar, ap, ok1 := split(a)
	br, bp, ok2 := split(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < len(ar) || i < len(br); i++ {
		var x, y int
		if i < len(ar) {
			x = ar[i]
		}
		if i < len(br) {
			y = br[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case ap == bp:
		return 0, true
	case ap == "":
		return 1, true
	case bp == "":
		return -1, true
	case ap < bp:
		return -1, true
	default:
		return 1, true
	}
}

func split(v string) (release []int, pre string, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, pre = v[:i], v[i+1:]
	}
	if v == "" {
		return nil, "", false
	}
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, "", false
		}
		release = append(release, n)
	}
	return release, pre, true
}
