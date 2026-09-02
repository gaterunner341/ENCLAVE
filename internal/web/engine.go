package web

import (
	"strings"
	"sync"
	"time"

	"github.com/pkittelson/enclave/internal/coverage"
	"github.com/pkittelson/enclave/internal/model"
	"github.com/pkittelson/enclave/internal/resolve"
	"github.com/pkittelson/enclave/internal/store"
)

// Engine holds the derived view of the world and rebuilds it from the log.
//
// Nothing is cached across a rebuild. The log is small enough to replay in
// full, and a view that is always recomputed cannot drift from its evidence.
type Engine struct {
	st       *store.Store
	cfg      resolve.Config
	controls []coverage.Control

	mu    sync.RWMutex
	hosts []*model.Host
	byID  map[string]*model.Host
	obs   int
	built time.Time
}

// NewEngine returns an engine over a store. Call Rebuild before serving.
func NewEngine(st *store.Store, cfg resolve.Config, controls []coverage.Control) *Engine {
	return &Engine{st: st, cfg: cfg, controls: controls, byID: map[string]*model.Host{}}
}

// Rebuild replays the log, merges it into hosts and places them in enclaves.
func (e *Engine) Rebuild() error {
	r := resolve.New(e.cfg)
	n, err := e.st.Replay(func(obs model.Observation) { r.Add(obs) })
	if err != nil {
		return err
	}
	hosts := r.Hosts()

	manual := map[string]string{}
	for id, d := range e.st.Decisions() {
		manual[id] = d.EnclaveID
	}
	coverage.Assign(hosts, e.st.ActiveEnclaves(), manual)

	byID := make(map[string]*model.Host, len(hosts))
	for _, h := range hosts {
		byID[h.ID] = h
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.hosts, e.byID, e.obs, e.built = hosts, byID, n, time.Now()
	return nil
}

// Live returns the number of merged hosts.
func (e *Engine) Live() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.hosts)
}

// Stats returns what the page footer reports.
func (e *Engine) Stats() (hosts, obs int, built time.Time) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.hosts), e.obs, e.built
}

// Controls returns the measured control set.
func (e *Engine) Controls() []coverage.Control { return e.controls }

// Hosts returns every host, optionally filtered by a free-text query matched
// against the name, address, operating system and enclave.
func (e *Engine) Hosts(query string) []*model.Host {
	e.mu.RLock()
	defer e.mu.RUnlock()
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return append([]*model.Host(nil), e.hosts...)
	}
	var out []*model.Host
	for _, h := range e.hosts {
		hay := strings.ToLower(strings.Join([]string{
			h.DisplayName(),
			h.Field(model.FieldIP),
			h.Field(model.FieldOS),
			h.Field(model.FieldOwner),
			h.EnclaveID,
		}, " "))
		if strings.Contains(hay, q) {
			out = append(out, h)
		}
	}
	return out
}

// Host returns one host by identifier, or nil.
func (e *Engine) Host(id string) *model.Host {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.byID[id]
}

// Unassigned returns hosts whose address matched no enclave range.
func (e *Engine) Unassigned() []*model.Host {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []*model.Host
	for _, h := range e.hosts {
		if h.EnclaveID == "" {
			out = append(out, h)
		}
	}
	return out
}

// Conflicts returns hosts where two feeds disagree about a field.
func (e *Engine) Conflicts() []*model.Host {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []*model.Host
	for _, h := range e.hosts {
		if conflictCount(h.Fields) > 0 {
			out = append(out, h)
		}
	}
	return out
}

// enclaveView is one row of the coverage table.
type enclaveView struct {
	Enclave  *model.Enclave
	Hosts    int
	Affected int
	Percent  int
	Results  []coverage.Result
}

// enclaveViews measures every defined enclave.
func (e *Engine) enclaveViews(enclaves []*model.Enclave) ([]enclaveView, map[string]int) {
	e.mu.RLock()
	hosts := append([]*model.Host(nil), e.hosts...)
	e.mu.RUnlock()

	grouped := map[string][]*model.Host{}
	for _, h := range hosts {
		if h.EnclaveID != "" {
			grouped[h.EnclaveID] = append(grouped[h.EnclaveID], h)
		}
	}

	counts := make(map[string]int, len(enclaves))
	views := make([]enclaveView, 0, len(enclaves))
	for _, enc := range enclaves {
		members := grouped[enc.ID]
		counts[enc.ID] = len(members)
		v := enclaveView{
			Enclave:  enc,
			Hosts:    len(members),
			Affected: coverage.Affected(members, e.controls),
			Results:  coverage.Measure(members, e.controls),
		}
		if v.Hosts > 0 {
			v.Percent = v.Affected * 100 / v.Hosts
		}
		views = append(views, v)
	}
	return views, counts
}

// conflictCount reports how many fields on a host are disputed.
func conflictCount(fields map[string]model.FieldValue) int {
	n := 0
	for _, v := range fields {
		if len(v.Conflicts) > 0 {
			n++
		}
	}
	return n
}
