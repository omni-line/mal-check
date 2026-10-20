package maldb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

//go:embed malicious.json.gz meta.json
var files embed.FS

// maxSnapshotSize caps the decompressed snapshot as a guard against a
// corrupted or malicious data refresh.
const maxSnapshotSize = 256 << 20

// Meta describes when and from which upstream commit the snapshot was built.
type Meta struct {
	GeneratedAt string         `json:"generated_at"`
	Source      string         `json:"source"`
	Commit      string         `json:"commit"`
	License     string         `json:"license"`
	Records     int            `json:"records"`
	Ecosystems  map[string]int `json:"ecosystems"`
}

// DB is an in-memory index of the snapshot, keyed by ecosystem and
// normalized package name.
type DB struct {
	meta  Meta
	index map[string]map[string][]Record
	count int
}

var (
	defaultOnce sync.Once
	defaultDB   *DB
	defaultErr  error
)

// Default returns the embedded snapshot, loaded once.
func Default() (*DB, error) {
	defaultOnce.Do(func() {
		gz, err := files.ReadFile("malicious.json.gz")
		if err != nil {
			defaultErr = fmt.Errorf("maldb: %w", err)
			return
		}
		raw, err := files.ReadFile("meta.json")
		if err != nil {
			defaultErr = fmt.Errorf("maldb meta: %w", err)
			return
		}
		var meta Meta
		if err := json.Unmarshal(raw, &meta); err != nil {
			defaultErr = fmt.Errorf("maldb meta: %w", err)
			return
		}
		defaultDB, defaultErr = Load(bytes.NewReader(gz), meta)
	})
	return defaultDB, defaultErr
}

// Load builds a DB from a gzip-compressed JSON-lines snapshot.
func Load(r io.Reader, meta Meta) (*DB, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("maldb: %w", err)
	}
	defer zr.Close()
	lr := &io.LimitedReader{R: zr, N: maxSnapshotSize + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 64*1024), 4<<20)

	db := &DB{meta: meta, index: map[string]map[string][]Record{}}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("maldb: record %d: %w", db.count+1, err)
		}
		byName := db.index[rec.Ecosystem]
		if byName == nil {
			byName = map[string][]Record{}
			db.index[rec.Ecosystem] = byName
		}
		key := Normalize(rec.Ecosystem, rec.Name)
		byName[key] = append(byName[key], rec)
		db.count++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("maldb: %w", err)
	}
	if lr.N <= 0 {
		return nil, errors.New("maldb: snapshot exceeds size limit")
	}
	return db, nil
}

// Meta returns snapshot provenance.
func (db *DB) Meta() Meta { return db.meta }

// Len is the number of records loaded.
func (db *DB) Len() int { return db.count }

// Lookup returns every record for a package name in an ecosystem.
func (db *DB) Lookup(ecosystem, name string) []Record {
	if db == nil {
		return nil
	}
	return db.index[ecosystem][Normalize(ecosystem, name)]
}

// Normalize folds a package name the way its registry compares names, so a
// lockfile spelling and an advisory spelling of the same package meet.
func Normalize(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch ecosystem {
	case PyPI:
		// PEP 503: case-insensitive, runs of -, _ and . are equivalent.
		var b strings.Builder
		sep := false
		for _, r := range strings.ToLower(name) {
			if r == '-' || r == '_' || r == '.' {
				sep = true
				continue
			}
			if sep && b.Len() > 0 {
				b.WriteByte('-')
			}
			sep = false
			b.WriteRune(r)
		}
		return b.String()
	case Cargo:
		// crates.io treats - and _ as the same character, case-insensitively.
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case NuGet, Composer, VSCode:
		return strings.ToLower(name)
	default:
		// npm, RubyGems, Go and Maven compare names exactly.
		return name
	}
}
