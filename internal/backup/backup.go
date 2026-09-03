// Package backup moves a whole ENCLAVE data set in and out of a single file.
//
// It exists for one situation above all others: somebody downloads a newer
// build, puts it in a different folder, and expects their enclaves, assets,
// findings and assessments to still be there. Copying the data directory does
// that too, and is documented, but it requires knowing where the directory is
// and that it matters. A backup file is one button at each end.
//
// The bundle is an ordinary zip. Anyone can open it and read the JSON inside,
// which is the same property the data directory has and is worth keeping: a
// record nobody can inspect is a record nobody can audit.
package backup

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/store"
)

// Format identifies an ENCLAVE bundle. A zip that does not carry it is
// rejected rather than half-extracted over somebody's data.
const Format = "enclave-backup"

// manifestName is the first entry in the bundle, so that reading the manifest
// never means scanning the whole archive.
const manifestName = "manifest.json"

// dataPrefix is where the data directory's contents live inside the bundle.
const dataPrefix = "data/"

// BackupsDir holds bundles the application writes for itself, and is excluded
// from bundles so that backups never accumulate inside backups.
const BackupsDir = "backups"

// Manifest describes a bundle well enough to decide whether to trust it before
// anything is written.
type Manifest struct {
	Format    string         `json:"format"`
	Schema    int            `json:"schema"`
	Created   time.Time      `json:"created"`
	CreatedBy string         `json:"created_by,omitempty"`
	Host      string         `json:"host,omitempty"`
	Counts    map[string]int `json:"counts,omitempty"`
	Files     []string       `json:"files,omitempty"`
}

// Describe is a one-line summary for a page or a terminal.
func (m Manifest) Describe() string {
	parts := []string{m.Created.Local().Format("2 Jan 2006 15:04")}
	if m.CreatedBy != "" {
		parts = append(parts, "ENCLAVE "+m.CreatedBy)
	}
	for _, k := range []string{"enclaves", "assets", "findings"} {
		if n := m.Counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	return strings.Join(parts, ", ")
}

// Write packages a data directory into w.
func Write(dataDir string, w io.Writer, buildVersion string) (Manifest, error) {
	files, err := collect(dataDir)
	if err != nil {
		return Manifest{}, err
	}
	if !hasRecords(dataDir) {
		return Manifest{}, fmt.Errorf("there is nothing in %s to back up yet", dataDir)
	}
	stamp, _, err := store.ReadStamp(dataDir)
	if err != nil {
		return Manifest{}, err
	}
	host, _ := os.Hostname()
	man := Manifest{
		Format: Format, Schema: stamp.Schema, Created: time.Now().UTC(),
		CreatedBy: buildVersion, Host: host, Files: files,
	}
	if counts, err := countRecords(dataDir); err == nil {
		man.Counts = counts
	}

	zw := zip.NewWriter(w)
	body, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := writeEntry(zw, manifestName, body); err != nil {
		return Manifest{}, err
	}
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(name)))
		if err != nil {
			return Manifest{}, fmt.Errorf("reading %s: %w", name, err)
		}
		if err := writeEntry(zw, dataPrefix+name, b); err != nil {
			return Manifest{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return Manifest{}, err
	}
	return man, nil
}

func writeEntry(zw *zip.Writer, name string, body []byte) error {
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()}
	f, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	return err
}

// collect lists the files that make up a data set, as forward-slash paths
// relative to the directory. Only the shapes ENCLAVE writes are included, so a
// stray file somebody dropped in the directory is not carried around forever.
func collect(dataDir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dataDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dataDir, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == BackupsDir || strings.HasPrefix(rel, ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if wanted(rel) {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// excluded never travels in a bundle. Credentials for another system are the
// one thing in the data directory that must not be copied around casually: a
// backup gets emailed, and a Security Center key in it is a key anyone who
// receives the file now holds.
var excluded = map[string]bool{
	"tenable-credentials.json": true,
}

// wanted decides whether a file belongs in a bundle.
func wanted(rel string) bool {
	if strings.HasPrefix(rel, BackupsDir+"/") || strings.HasPrefix(rel, ".") {
		return false
	}
	if strings.HasSuffix(rel, ".tmp") || excluded[rel] {
		return false
	}
	dir, _ := path.Split(rel)
	switch dir {
	case "":
		return strings.HasSuffix(rel, ".json")
	case "catalogs/", "mappings/":
		return true
	}
	return false
}

func countRecords(dataDir string) (map[string]int, error) {
	s, err := store.Open(dataDir)
	if err != nil {
		return nil, err
	}
	c := s.Counts()
	return map[string]int{
		"enclaves": c.Enclaves, "assets": c.Assets, "findings": c.Findings,
		"scans": c.Scans, "risks": c.Risks,
	}, nil
}
