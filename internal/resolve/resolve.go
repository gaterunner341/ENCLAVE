// Package resolve merges observations into hosts.
//
// Two rules do all the work. Records are merged when they share any usable
// identifier, transitively. When two feeds disagree about a field, the more
// authoritative kind of tool wins, ties are broken by collection time, and the
// loser is kept as a conflict so the decision can be audited.
package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/pkittelson/enclave/internal/model"
)

// SourceKind is the kind of tool a feed came from. It, not the feed's name,
// decides who wins a disagreement, so a second EDR needs no new configuration.
type SourceKind string

// The source kinds an import can declare.
const (
	KindEDR           SourceKind = "edr"
	KindEndpointMgmt  SourceKind = "endpoint_mgmt"
	KindVulnScanner   SourceKind = "vuln_scanner"
	KindConfigScanner SourceKind = "config_scanner"
	KindCMDB          SourceKind = "cmdb"
	KindDirectory     SourceKind = "directory"
	KindIPAM          SourceKind = "ipam"
	KindNetflow       SourceKind = "netflow"
)

// Kind describes a source kind for the import screen.
type Kind struct {
	ID    SourceKind
	Label string
}

// Kinds are the source kinds offered at import, in the order they are shown.
func Kinds() []Kind {
	return []Kind{
		{KindEDR, "EDR / endpoint agent (CrowdStrike, Defender, SentinelOne)"},
		{KindEndpointMgmt, "Endpoint management (SCCM, Intune, Jamf)"},
		{KindVulnScanner, "Vulnerability scanner (Tenable, Qualys, Rapid7)"},
		{KindConfigScanner, "Configuration or benchmark scanner (SCAP, STIG)"},
		{KindCMDB, "Asset database or CMDB (ServiceNow)"},
		{KindDirectory, "Directory service (Active Directory, Entra ID)"},
		{KindIPAM, "Address management (IPAM, DHCP, DNS)"},
		{KindNetflow, "Network flow or discovery"},
	}
}

// KindLabel returns the human label for a source kind.
func KindLabel(k string) string {
	for _, c := range Kinds() {
		if string(c.ID) == k {
			return c.Label
		}
	}
	return k
}

// Precedence names the fields a set of source kinds is trusted for, most
// authoritative kind first.
type Precedence struct {
	Fields       []string
	OnSourceKind []SourceKind
}

// Config is the merge policy.
type Config struct {
	// MergeOn lists the identifier kinds records may be joined on, strongest
	// first. An identifier kind left out here is recorded but never merged on.
	MergeOn []string
	// Precedence is consulted field by field.
	Precedence []Precedence
	// Fallback applies to any field no rule covers.
	Fallback []SourceKind
}

// DefaultConfig is the policy the application ships with: believe the tool
// that owns the thing it is reporting on.
func DefaultConfig() Config {
	return Config{
		MergeOn: []string{
			model.IDSerial, model.IDUUID, model.IDMAC,
			model.IDFQDN, model.IDHostname, model.IDNetBIOS, model.IDAssetTag,
		},
		Precedence: []Precedence{
			{
				// The agent is on the machine; it knows what it is running.
				Fields:       []string{model.FieldOS, model.FieldOSVersion, model.FieldEDRStatus},
				OnSourceKind: []SourceKind{KindEDR, KindEndpointMgmt, KindConfigScanner, KindVulnScanner, KindCMDB, KindDirectory},
			},
			{
				// Addresses are managed by the address management system.
				Fields:       []string{model.FieldIP},
				OnSourceKind: []SourceKind{KindIPAM, KindNetflow, KindEDR, KindEndpointMgmt, KindVulnScanner, KindCMDB},
			},
			{
				// Ownership is a business fact, not a technical one.
				Fields:       []string{model.FieldOwner, model.FieldLocation, model.FieldDeviceRole},
				OnSourceKind: []SourceKind{KindCMDB, KindDirectory, KindEndpointMgmt, KindEDR},
			},
			{
				// Hardware facts come from whatever inventories hardware.
				Fields:       []string{model.FieldManufacturer, model.FieldHardwareModel},
				OnSourceKind: []SourceKind{KindEndpointMgmt, KindCMDB, KindEDR, KindConfigScanner},
			},
			{
				Fields:       []string{model.FieldDiskEncrypted},
				OnSourceKind: []SourceKind{KindEndpointMgmt, KindConfigScanner, KindEDR},
			},
			{
				Fields:       []string{model.FieldLastVulnScan},
				OnSourceKind: []SourceKind{KindVulnScanner},
			},
			{
				Fields:       []string{model.FieldLastBenchmarkScan},
				OnSourceKind: []SourceKind{KindConfigScanner},
			},
		},
		Fallback: []SourceKind{
			KindEDR, KindEndpointMgmt, KindConfigScanner, KindVulnScanner,
			KindCMDB, KindDirectory, KindIPAM, KindNetflow,
		},
	}
}

// record accumulates every observation that has been joined to one machine.
type record struct {
	ids   map[string]model.Identifier
	obs   []model.Observation
	dead  bool // merged into another record
	order int  // first-seen order, for a stable host id
}

// Resolver merges observations. It is not safe for concurrent use; the engine
// builds one per rebuild and throws it away.
type Resolver struct {
	cfg     Config
	index   map[string]*record
	records []*record
	auth    map[string]map[SourceKind]int
}

// New returns a resolver using the given policy.
func New(cfg Config) *Resolver {
	r := &Resolver{
		cfg:   cfg,
		index: map[string]*record{},
		auth:  map[string]map[SourceKind]int{},
	}
	for _, p := range cfg.Precedence {
		for _, f := range p.Fields {
			ranks := map[SourceKind]int{}
			for i, k := range p.OnSourceKind {
				ranks[k] = len(p.OnSourceKind) - i
			}
			r.auth[f] = ranks
		}
	}
	return r
}

// mergeable reports whether an identifier kind may be joined on.
func (r *Resolver) mergeable(kind string) bool {
	for _, k := range r.cfg.MergeOn {
		if k == kind {
			return true
		}
	}
	return false
}

// authority ranks a source kind for a field. Higher wins; zero means the kind
// is not trusted for that field at all.
func (r *Resolver) authority(field string, kind SourceKind) int {
	if ranks, ok := r.auth[field]; ok {
		return ranks[kind]
	}
	for i, k := range r.cfg.Fallback {
		if k == kind {
			return len(r.cfg.Fallback) - i
		}
	}
	return 0
}

// find returns every existing record that shares an identifier with ids.
func (r *Resolver) find(ids []model.Identifier) []*record {
	var hits []*record
	seen := map[*record]bool{}
	for _, id := range ids {
		rec := r.index[id.Key()]
		if rec == nil || seen[rec] {
			continue
		}
		seen[rec] = true
		hits = append(hits, rec)
	}
	return hits
}

// union folds src into dst. Identifiers are transitive: if one feed says a
// serial and a hostname belong together, everything keyed on either is the
// same machine.
func (r *Resolver) union(dst, src *record) {
	for key, id := range src.ids {
		dst.ids[key] = id
		r.index[key] = dst
	}
	dst.obs = append(dst.obs, src.obs...)
	if src.order < dst.order {
		dst.order = src.order
	}
	src.dead = true
	src.ids = nil
	src.obs = nil
}

// Add files one observation against the machine it describes, creating a new
// record if no identifier matches anything seen so far.
func (r *Resolver) Add(obs model.Observation) {
	var ids []model.Identifier
	for _, id := range obs.Identifiers {
		n := id.Normalize()
		if !n.Valid() || !r.mergeable(n.Kind) {
			continue
		}
		ids = append(ids, n)
	}
	if len(ids) == 0 {
		// Nothing to merge on. Keep the row rather than dropping it: an
		// unmergeable observation is still evidence a machine exists.
		rec := &record{ids: map[string]model.Identifier{}, order: len(r.records)}
		rec.obs = append(rec.obs, obs)
		r.records = append(r.records, rec)
		return
	}

	hits := r.find(ids)
	var rec *record
	switch len(hits) {
	case 0:
		rec = &record{ids: map[string]model.Identifier{}, order: len(r.records)}
		r.records = append(r.records, rec)
	default:
		rec = hits[0]
		for _, other := range hits[1:] {
			r.union(rec, other)
		}
	}
	for _, id := range ids {
		rec.ids[id.Key()] = id
		r.index[id.Key()] = rec
	}
	rec.obs = append(rec.obs, obs)
}

// Hosts returns the merged view, one host per machine.
func (r *Resolver) Hosts() []*model.Host {
	hosts := make([]*model.Host, 0, len(r.records))
	for _, rec := range r.records {
		if rec.dead || len(rec.obs) == 0 {
			continue
		}
		hosts = append(hosts, r.project(rec))
	}
	model.SortHosts(hosts)
	return hosts
}

// project turns one record's observations into a host, resolving every field
// against the precedence policy.
func (r *Resolver) project(rec *record) *model.Host {
	h := &model.Host{
		ID:     hostID(rec),
		Fields: map[string]model.FieldValue{},
	}

	for _, id := range rec.ids {
		h.Identifiers = append(h.Identifiers, id)
	}
	sort.Slice(h.Identifiers, func(i, j int) bool {
		a, b := h.Identifiers[i], h.Identifiers[j]
		ra, rb := r.idRank(a.Kind), r.idRank(b.Kind)
		if ra != rb {
			return ra > rb
		}
		return a.Value < b.Value
	})

	// Newest observation last, so an equally authoritative later reading wins.
	obs := append([]model.Observation(nil), rec.obs...)
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].CollectedAt.Before(obs[j].CollectedAt) })

	seenSource := map[string]bool{}
	rank := map[string]int{}
	for _, o := range obs {
		if o.SourceID != "" && !seenSource[o.SourceID] {
			seenSource[o.SourceID] = true
			h.Sources = append(h.Sources, o.SourceID)
		}
		if h.FirstSeen.IsZero() || o.CollectedAt.Before(h.FirstSeen) {
			h.FirstSeen = o.CollectedAt
		}
		if o.CollectedAt.After(h.LastSeen) {
			h.LastSeen = o.CollectedAt
		}

		for name, raw := range o.Fields {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			candidate := model.FieldValue{
				Value:       value,
				Source:      o.SourceID,
				CollectedAt: o.CollectedAt,
			}
			got := r.authority(name, SourceKind(o.SourceKind))
			current, exists := h.Fields[name]
			switch {
			case !exists:
				h.Fields[name] = candidate
				rank[name] = got
			case strings.EqualFold(current.Value, value):
				// Agreement. Keep the earlier attribution, take the better rank.
				if got > rank[name] {
					current.Source = o.SourceID
					current.CollectedAt = o.CollectedAt
					h.Fields[name] = current
					rank[name] = got
				}
			case got >= rank[name]:
				// The incumbent loses but is kept on the record.
				candidate.Conflicts = append(candidate.Conflicts, model.Conflict{
					Value:       current.Value,
					Source:      current.Source,
					CollectedAt: current.CollectedAt,
				})
				candidate.Conflicts = append(candidate.Conflicts, current.Conflicts...)
				h.Fields[name] = candidate
				rank[name] = got
			default:
				current.Conflicts = append(current.Conflicts, model.Conflict{
					Value:       value,
					Source:      o.SourceID,
					CollectedAt: o.CollectedAt,
				})
				h.Fields[name] = current
			}
		}
	}
	sort.Strings(h.Sources)
	return h
}

// idRank orders identifier kinds by how stable they are.
func (r *Resolver) idRank(kind string) int {
	for i, k := range r.cfg.MergeOn {
		if k == kind {
			return len(r.cfg.MergeOn) - i
		}
	}
	return 0
}

// hostID derives a stable identifier from the strongest identifier the record
// carries, so a host keeps its URL across rebuilds.
func hostID(rec *record) string {
	keys := make([]string, 0, len(rec.ids))
	for k := range rec.ids {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		sum := sha256.Sum256([]byte(time.Time{}.String() + itoa(rec.order)))
		return hex.EncodeToString(sum[:6])
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "|")))
	return hex.EncodeToString(sum[:6])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
