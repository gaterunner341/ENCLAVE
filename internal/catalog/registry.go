package catalog

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

//go:embed data/*.catalog
var builtinFS embed.FS

// Registry holds every catalogue available to the application: the built-in
// ones compiled into the binary and any the organisation has imported. An
// imported catalogue whose id matches a built-in one replaces it, which is how
// the abridged built-in 800-53 is upgraded to the authoritative OSCAL release.
type Registry struct {
	mu   sync.RWMutex
	dir  string
	cats map[string]*Catalog
}

// NewRegistry loads the built-in catalogues, then any *.catalog, *.oscal.json
// or *.json file found in dir.
func NewRegistry(dir string) (*Registry, error) {
	r := &Registry{dir: dir, cats: map[string]*Catalog{}}
	if err := r.loadBuiltin(); err != nil {
		return nil, err
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("catalog directory: %w", err)
		}
		if err := r.loadDir(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Registry) loadBuiltin() error {
	entries, err := builtinFS.ReadDir("data")
	if err != nil {
		return err
	}
	for _, e := range entries {
		b, err := builtinFS.ReadFile("data/" + e.Name())
		if err != nil {
			return err
		}
		cat, err := ParseText(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("built-in catalog %s: %w", e.Name(), err)
		}
		cat.BuiltIn = true
		r.cats[cat.ID] = cat
	}
	return nil
}

func (r *Registry) loadDir() error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(r.dir, e.Name())
		cat, err := LoadFile(path)
		if err != nil {
			// A single bad file must not stop the application from starting;
			// it is reported on the Catalogues page instead.
			r.cats["!error:"+e.Name()] = &Catalog{
				ID: "!error:" + e.Name(), Name: e.Name(),
				Description: "could not be loaded: " + err.Error(),
			}
			continue
		}
		cat.BuiltIn = false
		r.cats[cat.ID] = cat
	}
	return nil
}

// LoadFile reads a catalogue from disk, choosing the parser by extension and
// falling back to sniffing the first non-blank byte.
func LoadFile(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(b, filepath.Base(path))
}

// Load parses catalogue bytes. name is used only to pick a parser and to seed
// an identifier for formats that do not carry one.
func Load(b []byte, name string) (*Catalog, error) {
	trimmed := bytes.TrimLeft(b, " \t\r\n")
	switch {
	case bytes.HasPrefix(trimmed, []byte("{")):
		return ParseOSCAL(bytes.NewReader(b))
	case strings.HasSuffix(strings.ToLower(name), ".csv"):
		base := strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
		return ParseCSV(bytes.NewReader(b), Slug(base), base)
	default:
		return ParseText(bytes.NewReader(b))
	}
}

// Get returns a catalogue by identifier.
func (r *Registry) Get(id string) (*Catalog, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.cats[id]
	return c, ok
}

// MustGet returns a catalogue or an empty placeholder, so that a page
// referencing a removed catalogue renders an explanation instead of crashing.
func (r *Registry) MustGet(id string) *Catalog {
	if c, ok := r.Get(id); ok {
		return c
	}
	return &Catalog{ID: id, Name: id + " (not loaded)"}
}

// All returns every catalogue, built-ins first, then alphabetically.
func (r *Registry) All() []*Catalog {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Catalog, 0, len(r.cats))
	for _, c := range r.cats {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BuiltIn != out[j].BuiltIn {
			return out[i].BuiltIn
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Add installs a catalogue and, when the registry has a directory, writes it
// there so that it survives a restart.
func (r *Registry) Add(cat *Catalog, raw []byte, filename string) error {
	if err := cat.Validate(); err != nil {
		return err
	}
	cat.Index()
	if r.dir != "" {
		ext := filepath.Ext(filename)
		if ext == "" {
			ext = ".catalog"
		}
		name := cat.ID + ext
		if err := os.WriteFile(filepath.Join(r.dir, name), raw, 0o644); err != nil {
			return fmt.Errorf("saving catalog: %w", err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cats[cat.ID] = cat
	return nil
}

// Remove deletes an imported catalogue. Built-in catalogues cannot be removed,
// only shadowed by an import with the same identifier.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	c, ok := r.cats[id]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("no catalog %q", id)
	}
	if c.BuiltIn {
		return fmt.Errorf("%s is built in and cannot be removed", c.Name)
	}
	if r.dir != "" {
		matches, _ := filepath.Glob(filepath.Join(r.dir, id+".*"))
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
	r.mu.Lock()
	delete(r.cats, id)
	r.mu.Unlock()
	// A removed import may have been shadowing a built-in; reload to restore it.
	return r.loadBuiltin()
}

// Dir is where imported catalogues are kept.
func (r *Registry) Dir() string { return r.dir }
