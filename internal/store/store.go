// Package store is the durable half of the application: an append-only log of
// observations, and a small state file for the things a person decided.
//
// Nothing is ever edited in place. The host view is derived by replaying the
// log, so a wrong import can be explained rather than merely corrected.
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/pkittelson/enclave/internal/connector"
	"github.com/pkittelson/enclave/internal/model"
)

const (
	logName   = "observations.jsonl"
	stateName = "state.json"
)

// Mapping is a saved description of one feed's file format, so a recurring
// export is described once rather than every collection.
type Mapping struct {
	Name       string               `json:"name"`
	SourceID   string               `json:"source_id"`
	SourceKind string               `json:"source_kind"`
	Columns    map[string]string    `json:"columns"`
	TimeLayout string               `json:"time_layout,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
	ColumnMap  *connector.ColumnMap `json:"-"`
}

// ImportRecord is one line of import history.
type ImportRecord struct {
	At           time.Time `json:"at"`
	Filename     string    `json:"filename"`
	SourceID     string    `json:"source_id"`
	SourceKind   string    `json:"source_kind"`
	Observations int       `json:"observations"`
}

// Decision records a placement a person made by hand, which always beats the
// address ranges. Keeping it separate from the log means a re-import cannot
// silently undo somebody's judgement.
type Decision struct {
	HostID    string    `json:"host_id"`
	EnclaveID string    `json:"enclave_id,omitempty"`
	Status    string    `json:"status,omitempty"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
	By        string    `json:"by"`
}

// state is everything that is not an observation.
type state struct {
	Enclaves  []*model.Enclave     `json:"enclaves"`
	Mappings  []*Mapping           `json:"mappings"`
	Imports   []ImportRecord       `json:"imports"`
	Decisions map[string]*Decision `json:"decisions"`
}

// Store owns the data directory.
type Store struct {
	mu    sync.Mutex
	dir   string
	state state
}

// Open prepares a data directory, creating it if this is the first run.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir reports where the data lives, so the startup banner can say so.
func (s *Store) Dir() string { return s.dir }

func (s *Store) statePath() string { return filepath.Join(s.dir, stateName) }
func (s *Store) logPath() string   { return filepath.Join(s.dir, logName) }

func (s *Store) loadState() error {
	b, err := os.ReadFile(s.statePath())
	if os.IsNotExist(err) {
		s.state = state{Decisions: map[string]*Decision{}}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &s.state); err != nil {
		return fmt.Errorf("%s is not readable: %w", stateName, err)
	}
	if s.state.Decisions == nil {
		s.state.Decisions = map[string]*Decision{}
	}
	return nil
}

// saveState writes the state file through a temporary file, so an interrupted
// write cannot leave a half-written file where the settings used to be.
func (s *Store) saveState() error {
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath())
}

// Append adds observations to the log. It is the only way data enters.
func (s *Store) Append(obs []model.Observation) error {
	if len(obs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for i := range obs {
		if err := enc.Encode(obs[i]); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return f.Sync()
}

// Replay hands every observation, oldest first, to fn. A line that will not
// parse is skipped rather than aborting the replay: one bad row should not
// take the whole inventory offline.
func (s *Store) Replay(fn func(model.Observation)) (int, error) {
	f, err := os.Open(s.logPath())
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	n := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var obs model.Observation
		if err := json.Unmarshal(line, &obs); err != nil {
			continue
		}
		fn(obs)
		n++
	}
	return n, sc.Err()
}

// RecordImport adds a line to the import history.
func (s *Store) RecordImport(rec ImportRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Imports = append([]ImportRecord{rec}, s.state.Imports...)
	if len(s.state.Imports) > 200 {
		s.state.Imports = s.state.Imports[:200]
	}
	return s.saveState()
}

// Imports returns the import history, newest first.
func (s *Store) Imports() []ImportRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ImportRecord(nil), s.state.Imports...)
}

// PutEnclave adds or replaces an enclave definition.
func (s *Store) PutEnclave(e *model.Enclave) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.state.Enclaves {
		if existing.ID == e.ID {
			e.CreatedAt = existing.CreatedAt
			s.state.Enclaves[i] = e
			return s.saveState()
		}
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	s.state.Enclaves = append(s.state.Enclaves, e)
	return s.saveState()
}

// DeleteEnclave removes an enclave. It refuses while hosts are still placed in
// it, because deleting one silently would leave those hosts unowned.
func (s *Store) DeleteEnclave(id string, hosts int) error {
	if hosts > 0 {
		return fmt.Errorf("%s still holds %d host(s). Move them first, or change its address range.", id, hosts)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Enclaves[:0]
	for _, e := range s.state.Enclaves {
		if e.ID != id {
			out = append(out, e)
		}
	}
	s.state.Enclaves = out
	return s.saveState()
}

// ActiveEnclaves returns the defined enclaves, ordered by identifier.
func (s *Store) ActiveEnclaves() []*model.Enclave {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]*model.Enclave(nil), s.state.Enclaves...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Enclave returns one enclave by identifier.
func (s *Store) Enclave(id string) *model.Enclave {
	for _, e := range s.ActiveEnclaves() {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// PutMapping saves a column mapping under a name.
func (s *Store) PutMapping(m *Mapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.state.Mappings {
		if existing.Name == m.Name {
			m.CreatedAt = existing.CreatedAt
			s.state.Mappings[i] = m
			return s.saveState()
		}
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now()
	}
	s.state.Mappings = append(s.state.Mappings, m)
	return s.saveState()
}

// DeleteMapping forgets a saved mapping.
func (s *Store) DeleteMapping(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Mappings[:0]
	for _, m := range s.state.Mappings {
		if m.Name != name {
			out = append(out, m)
		}
	}
	s.state.Mappings = out
	return s.saveState()
}

// SortedMappings returns the saved mappings by name.
func (s *Store) SortedMappings() []*Mapping {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]*Mapping(nil), s.state.Mappings...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Mapping returns one saved mapping by name.
func (s *Store) Mapping(name string) *Mapping {
	for _, m := range s.SortedMappings() {
		if m.Name == name {
			return m
		}
	}
	return nil
}

// PutDecision records a manual placement.
func (s *Store) PutDecision(d *Decision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.At.IsZero() {
		d.At = time.Now()
	}
	s.state.Decisions[d.HostID] = d
	return s.saveState()
}

// Decisions returns the manual placements, keyed by host.
func (s *Store) Decisions() map[string]*Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*Decision, len(s.state.Decisions))
	for k, v := range s.state.Decisions {
		out[k] = v
	}
	return out
}
