// Package store persists ENCLAVE's records.
//
// The store is deliberately small: every collection is a slice held in memory,
// written to a JSON file beside the others whenever it changes. There is no
// database engine, no driver and no schema migration tool, because the whole
// application has to be a single file that a person can copy onto a system and
// run without asking anyone for anything.
//
// Writes are serialised behind one mutex and land through a temporary file and
// a rename, so a process that dies mid-save leaves the previous good file in
// place rather than a truncated one.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// Store holds every record and the indexes that make the pages fast enough to
// render without pagination tricks.
type Store struct {
	mu  sync.RWMutex
	dir string

	enclaves    map[string]*model.Enclave
	assets      map[string]*model.Asset
	scans       map[string]*model.Scan
	findings    map[string]*model.Finding
	assessments map[string]*model.Assessment
	risks       map[string]*model.RiskEntry

	// findingsByAsset and findingsByEnclave avoid a full scan on every page.
	findingsByAsset   map[string][]string
	findingsByEnclave map[string][]string
	assetsByEnclave   map[string][]string
	// assetEnclave records which bucket each asset is filed under. Callers
	// routinely hand back the stored record itself after editing it, so the
	// record cannot be asked which enclave it used to be in.
	assetEnclave map[string]string
	// fingerprints deduplicates repeat imports: the same rule against the same
	// asset updates the existing finding rather than adding another row.
	fingerprints map[string]string

	seq   uint64
	dirty map[string]bool
}

// Open loads a store from dir, creating it when it does not exist.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("data directory %s: %w", dir, err)
	}
	s := &Store{
		dir:               dir,
		enclaves:          map[string]*model.Enclave{},
		assets:            map[string]*model.Asset{},
		scans:             map[string]*model.Scan{},
		findings:          map[string]*model.Finding{},
		assessments:       map[string]*model.Assessment{},
		risks:             map[string]*model.RiskEntry{},
		findingsByAsset:   map[string][]string{},
		findingsByEnclave: map[string][]string{},
		assetsByEnclave:   map[string][]string{},
		assetEnclave:      map[string]string{},
		fingerprints:      map[string]string{},
		dirty:             map[string]bool{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir is the directory the store persists into.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(name string) string { return filepath.Join(s.dir, name+".json") }

func (s *Store) load() error {
	type target struct {
		name string
		into any
	}
	var (
		enclaves    []*model.Enclave
		assets      []*model.Asset
		scans       []*model.Scan
		findings    []*model.Finding
		assessments []*model.Assessment
		risks       []*model.RiskEntry
	)
	for _, t := range []target{
		{"enclaves", &enclaves}, {"assets", &assets}, {"scans", &scans},
		{"findings", &findings}, {"assessments", &assessments}, {"risks", &risks},
	} {
		b, err := os.ReadFile(s.path(t.name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("reading %s: %w", t.name, err)
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			continue
		}
		if err := json.Unmarshal(b, t.into); err != nil {
			return fmt.Errorf("parsing %s.json: %w", t.name, err)
		}
	}
	for _, e := range enclaves {
		s.enclaves[e.ID] = e
	}
	for _, a := range assets {
		s.assets[a.ID] = a
		s.assetsByEnclave[a.EnclaveID] = append(s.assetsByEnclave[a.EnclaveID], a.ID)
		s.assetEnclave[a.ID] = a.EnclaveID
	}
	for _, sc := range scans {
		s.scans[sc.ID] = sc
	}
	for _, f := range findings {
		s.findings[f.ID] = f
		s.indexFinding(f)
	}
	for _, a := range assessments {
		s.assessments[a.Key()] = a
	}
	for _, r := range risks {
		s.risks[r.ID] = r
	}
	return nil
}

func (s *Store) indexFinding(f *model.Finding) {
	s.findingsByAsset[f.AssetID] = append(s.findingsByAsset[f.AssetID], f.ID)
	s.findingsByEnclave[f.EnclaveID] = append(s.findingsByEnclave[f.EnclaveID], f.ID)
	if f.Fingerprint != "" {
		s.fingerprints[f.Fingerprint] = f.ID
	}
}

// Save writes every collection marked dirty. It is called at the end of each
// mutating operation, and again on shutdown.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	writers := map[string]func() any{
		"enclaves":    func() any { return sortedEnclaves(s.enclaves) },
		"assets":      func() any { return sortedAssets(s.assets) },
		"scans":       func() any { return sortedScans(s.scans) },
		"findings":    func() any { return sortedFindings(s.findings) },
		"assessments": func() any { return sortedAssessments(s.assessments) },
		"risks":       func() any { return sortedRisks(s.risks) },
	}
	for name := range s.dirty {
		fn, ok := writers[name]
		if !ok {
			continue
		}
		if err := writeJSON(s.path(name), fn()); err != nil {
			return err
		}
		delete(s.dirty, name)
	}
	return nil
}

// writeJSON writes through a temporary file so an interrupted save cannot
// truncate a good file.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// NextID mints an identifier that sorts by creation time and is unique within
// the store. It is not a UUID: readable identifiers make the JSON files, the
// URLs and the CSV exports easier to work with by hand.
func (s *Store) NextID(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s-%s-%04d", prefix, time.Now().UTC().Format("20060102150405"), s.seq%10000)
}

func sortedEnclaves(m map[string]*model.Enclave) []*model.Enclave {
	out := make([]*model.Enclave, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedAssets(m map[string]*model.Asset) []*model.Asset {
	out := make([]*model.Asset, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedScans(m map[string]*model.Scan) []*model.Scan {
	out := make([]*model.Scan, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedFindings(m map[string]*model.Finding) []*model.Finding {
	out := make([]*model.Finding, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedAssessments(m map[string]*model.Assessment) []*model.Assessment {
	out := make([]*model.Assessment, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

func sortedRisks(m map[string]*model.RiskEntry) []*model.RiskEntry {
	out := make([]*model.RiskEntry, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
