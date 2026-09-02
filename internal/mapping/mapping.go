// Package mapping turns scan results into control evidence.
//
// A STIG rule cites Control Correlation Identifiers; a Nessus plugin cites
// CVEs; a CIS benchmark item cites a safeguard number. None of those is a
// control identifier on its own. This package holds the tables that translate
// them, and the rule that decides which table to try first.
//
// No mapping is invented. Tables are loaded from files the organisation
// supplies (the DISA CCI list, a CIS crosswalk, a spreadsheet of local
// decisions), and anything that does not resolve is reported as unmapped
// rather than quietly attributed to a control it might not belong to.
package mapping

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/model"
)

// Scheme names the vocabulary a mapping's keys are drawn from.
type Scheme string

const (
	SchemeCCI       Scheme = "cci"       // CCI-000366
	SchemeCVE       Scheme = "cve"       // CVE-2024-0001
	SchemeRule      Scheme = "rule"      // SV-230221r1000 or a scanner plugin id
	SchemeGroup     Scheme = "group"     // V-230221
	SchemeControl   Scheme = "control"   // a control in another catalogue: a crosswalk
	SchemeKeyword   Scheme = "keyword"   // a word in the rule title, matched case-insensitively
	SchemeBenchmark Scheme = "benchmark" // a benchmark rule identifier, e.g. a CIS section number
)

var Schemes = []Scheme{SchemeCCI, SchemeControl, SchemeRule, SchemeGroup, SchemeCVE, SchemeBenchmark, SchemeKeyword}

func (s Scheme) Label() string {
	switch s {
	case SchemeCCI:
		return "Control Correlation Identifier"
	case SchemeCVE:
		return "CVE"
	case SchemeRule:
		return "Rule or plugin identifier"
	case SchemeGroup:
		return "Group identifier"
	case SchemeControl:
		return "Control crosswalk"
	case SchemeKeyword:
		return "Title keyword"
	case SchemeBenchmark:
		return "Benchmark section"
	}
	return string(s)
}

// Set is one mapping table: keys in a source scheme to control identifiers in
// one target catalogue.
type Set struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Scheme   Scheme              `json:"scheme"`
	Target   string              `json:"target_catalog"`
	Source   string              `json:"source,omitempty"`
	Note     string              `json:"note,omitempty"`
	BuiltIn  bool                `json:"built_in"`
	Entries  map[string][]string `json:"entries"`
	Filename string              `json:"-"`
}

// Lookup resolves one key, tolerating case and spacing differences.
func (s *Set) Lookup(key string) []string {
	if s == nil || s.Entries == nil {
		return nil
	}
	return s.Entries[normKey(key)]
}

// Size is the number of keys the table carries.
func (s *Set) Size() int { return len(s.Entries) }

func normKey(k string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(k), " ", ""))
}

// Registry holds every mapping table and answers the question the rest of the
// application asks: given this finding and this catalogue, which controls is it
// evidence about?
type Registry struct {
	mu   sync.RWMutex
	dir  string
	sets map[string]*Set
}

// NewRegistry loads the seed tables and then any file in dir.
func NewRegistry(dir string) (*Registry, error) {
	r := &Registry{dir: dir, sets: map[string]*Set{}}
	for _, s := range seedSets() {
		r.sets[s.ID] = s
	}
	if dir == "" {
		return r, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mapping directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		set, err := LoadFile(path)
		if err != nil {
			r.sets["!error:"+e.Name()] = &Set{
				ID: "!error:" + e.Name(), Name: e.Name(),
				Note: "could not be loaded: " + err.Error(),
			}
			continue
		}
		r.sets[set.ID] = set
	}
	return r, nil
}

// Sets returns every table, seeds first.
func (r *Registry) Sets() []*Set {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Set, 0, len(r.sets))
	for _, s := range r.sets {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BuiltIn != out[j].BuiltIn {
			return out[i].BuiltIn
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Get returns one table.
func (r *Registry) Get(id string) (*Set, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sets[id]
	return s, ok
}

// Add installs a table and persists it as CSV so it can be reviewed by hand.
func (r *Registry) Add(s *Set) error {
	if s.ID == "" {
		s.ID = catalog.Slug(s.Name)
	}
	if s.ID == "" || len(s.Entries) == 0 {
		return fmt.Errorf("a mapping needs a name and at least one entry")
	}
	if r.dir != "" {
		path := filepath.Join(r.dir, s.ID+".csv")
		if err := writeSetCSV(path, s); err != nil {
			return err
		}
		s.Filename = path
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets[s.ID] = s
	return nil
}

// Remove deletes an imported table. Seed tables cannot be removed.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	s, ok := r.sets[id]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("no mapping %q", id)
	}
	if s.BuiltIn {
		return fmt.Errorf("%s ships with ENCLAVE and cannot be removed", s.Name)
	}
	if s.Filename != "" {
		_ = os.Remove(s.Filename)
	}
	r.mu.Lock()
	delete(r.sets, id)
	r.mu.Unlock()
	return nil
}

// Resolve returns the controls in catalogID that the finding is evidence
// about, along with the reason each one was reached. Tables are tried in
// order of how specific the evidence is: an explicit CCI reference beats a
// crosswalk from another catalogue, which beats a title keyword.
func (r *Registry) Resolve(f *model.Finding, cat *catalog.Catalog) ([]string, []string) {
	if cat == nil {
		return nil, nil
	}
	r.mu.RLock()
	sets := make([]*Set, 0, len(r.sets))
	for _, s := range r.sets {
		if s.Target == cat.ID || s.Scheme == SchemeControl {
			sets = append(sets, s)
		}
	}
	r.mu.RUnlock()

	hits := map[string]string{}
	add := func(ids []string, why string) {
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if !cat.Has(id) {
				// A finding may cite an enhancement the profile does not
				// select. Recording it against the base control keeps the
				// evidence rather than discarding it.
				if base := catalog.BaseID(id); base != id && cat.Has(base) {
					id = base
				} else {
					continue
				}
			}
			if _, seen := hits[id]; !seen {
				hits[id] = why
			}
		}
	}

	for _, s := range sets {
		if s.Scheme != SchemeCCI || s.Target != cat.ID {
			continue
		}
		for _, cci := range f.CCIs {
			add(s.Lookup(cci), "CCI "+cci)
		}
	}
	// A finding that already names a control in this catalogue needs no table.
	for _, ref := range f.Controls(cat.ID) {
		add([]string{ref}, "cited by the scan")
	}
	// Crosswalks: the finding resolves to a control in one catalogue, and a
	// crosswalk carries that across to this one.
	for _, s := range sets {
		if s.Scheme != SchemeControl || s.Target != cat.ID {
			continue
		}
		for otherCat, refs := range f.ControlRefs {
			if otherCat == cat.ID {
				continue
			}
			for _, ref := range refs {
				add(s.Lookup(ref), "crosswalk from "+ref)
			}
		}
	}
	for _, s := range sets {
		if s.Target != cat.ID {
			continue
		}
		switch s.Scheme {
		case SchemeRule:
			add(s.Lookup(f.RuleID), "rule "+f.RuleID)
		case SchemeGroup:
			add(s.Lookup(f.GroupID), "group "+f.GroupID)
		case SchemeBenchmark:
			add(s.Lookup(f.GroupID), "benchmark section "+f.GroupID)
			add(s.Lookup(f.RuleID), "benchmark section "+f.RuleID)
		case SchemeCVE:
			for _, cve := range f.CVEs {
				add(s.Lookup(cve), cve)
			}
			// A "*" key means "any finding that names a CVE at all", which is
			// how a vulnerability result reaches the flaw remediation controls
			// without a per-CVE table nobody could maintain.
			if len(f.CVEs) > 0 {
				add(s.Lookup("*"), "names a CVE")
			}
		case SchemeKeyword:
			title := strings.ToUpper(f.Title)
			for k, v := range s.Entries {
				if strings.Contains(title, k) {
					add(v, "title mentions "+strings.ToLower(k))
				}
			}
		}
	}

	ids := make([]string, 0, len(hits))
	for id := range hits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	reasons := make([]string, len(ids))
	for i, id := range ids {
		reasons[i] = hits[id]
	}
	return ids, reasons
}

// Annotate fills in a finding's control references for every catalogue an
// enclave is measured against. It is called after ingest and again whenever a
// mapping table changes.
func (r *Registry) Annotate(f *model.Finding, cats []*catalog.Catalog) {
	for _, cat := range cats {
		ids, _ := r.Resolve(f, cat)
		if len(ids) == 0 {
			continue
		}
		if f.ControlRefs == nil {
			f.ControlRefs = map[string][]string{}
		}
		f.ControlRefs[cat.ID] = ids
	}
}

// ---------- file formats ----------

// LoadFile reads a mapping table, choosing the parser by extension.
func LoadFile(path string) (*Set, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	name := filepath.Base(path)
	var set *Set
	if strings.HasSuffix(strings.ToLower(name), ".xml") {
		set, err = ParseCCIList(fh)
	} else {
		set, err = ParseCSV(fh)
	}
	if err != nil {
		return nil, err
	}
	if set.ID == "" {
		set.ID = catalog.Slug(strings.TrimSuffix(name, filepath.Ext(name)))
	}
	set.Filename = path
	return set, nil
}

// ParseCSV reads a mapping from a spreadsheet export. Three header shapes are
// accepted, all of which appear in the wild:
//
//	key, control                 one row per pair
//	key, controls                one row per key, controls comma-separated
//	source, target               the same thing under crosswalk headings
//
// Directive rows at the top set the table's metadata:
//
//	#name, CCI to 800-53 Rev 5
//	#scheme, cci
//	#target, nist-800-53r5
func ParseCSV(r io.Reader) (*Set, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	set := &Set{Entries: map[string][]string{}, Scheme: SchemeCCI, Source: "CSV import"}
	body := rows
	for len(body) > 0 && len(body[0]) > 0 && strings.HasPrefix(strings.TrimSpace(body[0][0]), "#") {
		key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(body[0][0]), "#"))
		val := ""
		if len(body[0]) > 1 {
			val = strings.TrimSpace(body[0][1])
		}
		switch key {
		case "name":
			set.Name = val
		case "id":
			set.ID = catalog.Slug(val)
		case "scheme":
			set.Scheme = Scheme(strings.ToLower(val))
		case "target", "target_catalog", "catalog":
			set.Target = val
		case "note":
			set.Note = val
		}
		body = body[1:]
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("the file has no rows")
	}
	keyCol, valCol := 0, 1
	if len(body[0]) > 0 && isHeadingRow(body[0][0]) {
		body = body[1:]
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("the file has a header row but no entries")
	}
	for _, row := range body {
		if len(row) <= valCol {
			continue
		}
		k := normKey(row[keyCol])
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		for _, v := range strings.FieldsFunc(row[valCol], func(r rune) bool {
			return r == ',' || r == ';' || r == '|'
		}) {
			if v = strings.TrimSpace(v); v != "" {
				set.Entries[k] = append(set.Entries[k], v)
			}
		}
	}
	if len(set.Entries) == 0 {
		return nil, fmt.Errorf("no key-to-control rows were found")
	}
	for k := range set.Entries {
		set.Entries[k] = model.Dedup(set.Entries[k])
	}
	if set.Name == "" {
		set.Name = "Imported mapping"
	}
	if set.Target == "" {
		set.Target = "nist-800-53r5"
	}
	return set, nil
}

// isHeadingRow decides whether the first row names the columns or is already
// data. Every key ENCLAVE maps on carries a digit somewhere (CCI-000366,
// CVE-2024-1, AC-2, 5.1); a column heading such as "key" or "source" does not.
func isHeadingRow(firstCell string) bool {
	for _, r := range firstCell {
		if r >= '0' && r <= '9' {
			return false
		}
	}
	return true
}

func writeSetCSV(path string, s *Set) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	w := csv.NewWriter(fh)
	defer w.Flush()
	for _, row := range [][]string{
		{"#name", s.Name}, {"#id", s.ID}, {"#scheme", string(s.Scheme)},
		{"#target", s.Target}, {"#note", s.Note},
		{"key", "controls"},
	} {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	keys := make([]string, 0, len(s.Entries))
	for k := range s.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := w.Write([]string{k, strings.Join(s.Entries[k], ",")}); err != nil {
			return err
		}
	}
	return nil
}

// ParseCCIList reads the DISA Control Correlation Identifier list
// (U_CCI_List.xml). Each CCI carries one or more references into a revision of
// SP 800-53; the highest revision present is taken, because that is the one a
// current STIG is written against.
func ParseCCIList(r io.Reader) (*Set, error) {
	var doc struct {
		Items []struct {
			ID         string `xml:"id,attr"`
			References []struct {
				Creator string `xml:"creator,attr"`
				Title   string `xml:"title,attr"`
				Version string `xml:"version,attr"`
				Index   string `xml:"index,attr"`
			} `xml:"references>reference"`
		} `xml:"cci_items>cci_item"`
	}
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a CCI list: %w", err)
	}
	if len(doc.Items) == 0 {
		return nil, fmt.Errorf("the file contains no CCI items")
	}
	set := &Set{
		ID: "disa-cci-list", Name: "DISA CCI list to NIST SP 800-53",
		Scheme: SchemeCCI, Target: "nist-800-53r5",
		Source:  "U_CCI_List.xml",
		Note:    "Imported from the authoritative DISA Control Correlation Identifier list.",
		Entries: map[string][]string{},
	}
	for _, it := range doc.Items {
		best := ""
		bestVer := ""
		for _, ref := range it.References {
			if ref.Index == "" {
				continue
			}
			if ref.Version >= bestVer {
				bestVer, best = ref.Version, ref.Index
			}
		}
		if best == "" {
			continue
		}
		// An index reads "AC-2 (1)" or "AC-2 (1) (a)"; only the control and its
		// enhancement identify the control.
		id := cleanIndex(best)
		if id == "" {
			continue
		}
		set.Entries[normKey(it.ID)] = []string{id}
	}
	if len(set.Entries) == 0 {
		return nil, fmt.Errorf("no CCI carried a usable control reference")
	}
	return set, nil
}

// cleanIndex turns "AC-2 (1) (a)" into "AC-2(1)".
func cleanIndex(index string) string {
	index = strings.TrimSpace(index)
	fields := strings.Fields(index)
	if len(fields) == 0 {
		return ""
	}
	out := strings.ToUpper(fields[0])
	if len(fields) > 1 && strings.HasPrefix(fields[1], "(") {
		inner := strings.Trim(fields[1], "()")
		// Numeric parentheses are enhancements; alphabetic ones are statement
		// items, which are not separately assessable controls.
		if inner != "" && inner[0] >= '0' && inner[0] <= '9' {
			out += "(" + inner + ")"
		}
	}
	return out
}

// Reload discards every loaded table and reads them again from the seed set
// and the directory, so that a restore takes effect without a restart.
func (r *Registry) Reload() error {
	fresh := map[string]*Set{}
	for _, s := range seedSets() {
		fresh[s.ID] = s
	}
	if r.dir != "" {
		if err := os.MkdirAll(r.dir, 0o755); err != nil {
			return err
		}
		entries, err := os.ReadDir(r.dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(r.dir, e.Name())
			set, err := LoadFile(path)
			if err != nil {
				fresh["!error:"+e.Name()] = &Set{
					ID: "!error:" + e.Name(), Name: e.Name(),
					Note: "could not be loaded: " + err.Error(),
				}
				continue
			}
			fresh[set.ID] = set
		}
	}
	r.mu.Lock()
	r.sets = fresh
	r.mu.Unlock()
	return nil
}
