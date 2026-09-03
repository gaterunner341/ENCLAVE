// Package model holds the ENCLAVE domain: the enclaves being tracked, the
// assets inside them, the scan results imported against those assets, the
// control catalogues those results are measured against, and the risk entries
// that come out the other side.
//
// Nothing in this package touches storage, HTTP or file formats. Every type is
// plain data with JSON tags so that the store can persist it and the API can
// serve it without translation.
package model

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Network is one address range that belongs to an enclave. Assets are placed
// into an enclave by longest-prefix match across every network of every
// enclave, so ranges may be nested but must not be duplicated.
type Network struct {
	CIDR        string `json:"cidr"`
	Label       string `json:"label,omitempty"`
	VLAN        string `json:"vlan,omitempty"`
	Description string `json:"description,omitempty"`
}

// Prefix parses the CIDR. An unparseable range is reported rather than
// silently ignored, because a bad range means assets land in the wrong enclave.
func (n Network) Prefix() (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(n.CIDR))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("network %q: %w", n.CIDR, err)
	}
	return p.Masked(), nil
}

// BaselineRef binds a control catalogue and one of its profiles to an enclave.
// An enclave may carry several: a NIST 800-53 Moderate baseline for the
// authorisation package and CIS Implementation Group 2 for engineering, say.
type BaselineRef struct {
	CatalogID string    `json:"catalog_id"`
	ProfileID string    `json:"profile_id,omitempty"`
	Note      string    `json:"note,omitempty"`
	AddedAt   time.Time `json:"added_at"`
}

// Enclave is a bounded system: the unit that is inventoried, assessed,
// authorised and reported on. It maps onto whatever the organisation calls an
// authorisation boundary, a system, a site or a mission network.
type Enclave struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// Contacts maps a role identifier to the person who holds it over this
	// enclave. A role left out here falls back to the organisation-wide holder,
	// so a Chief Information Officer is recorded once rather than on every
	// system.
	Contacts map[string]string `json:"contacts,omitempty"`

	Organization string `json:"organization,omitempty"`
	Location     string `json:"location,omitempty"`
	Environment  string `json:"environment,omitempty"`
	Status       string `json:"status,omitempty"`

	Confidentiality Impact `json:"confidentiality"`
	Integrity       Impact `json:"integrity"`
	Availability    Impact `json:"availability"`

	Networks  []Network     `json:"networks,omitempty"`
	Baselines []BaselineRef `json:"baselines,omitempty"`

	AuthorizationStatus  string     `json:"authorization_status,omitempty"`
	AuthorizationExpires *time.Time `json:"authorization_expires,omitempty"`

	Tags    []string  `json:"tags,omitempty"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// Categorization is the enclave's overall impact level: the high-water mark of
// its confidentiality, integrity and availability ratings.
func (e *Enclave) Categorization() Impact {
	return HighWater(e.Confidentiality, e.Integrity, e.Availability)
}

// Prefixes returns every parseable network range on the enclave.
func (e *Enclave) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(e.Networks))
	for _, n := range e.Networks {
		if p, err := n.Prefix(); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// HasBaseline reports whether the catalogue is assigned to the enclave.
func (e *Enclave) HasBaseline(catalogID string) bool {
	for _, b := range e.Baselines {
		if b.CatalogID == catalogID {
			return true
		}
	}
	return false
}

// AuthorizationDaysLeft is negative once the authorisation has lapsed and zero
// when no expiry is recorded.
func (e *Enclave) AuthorizationDaysLeft(now time.Time) int {
	if e.AuthorizationExpires == nil {
		return 0
	}
	return int(e.AuthorizationExpires.Sub(now).Hours() / 24)
}

// Validate reports every problem with the enclave at once, so that a form does
// not have to be submitted repeatedly to discover them one at a time.
func (e *Enclave) Validate() error {
	var problems []string
	if strings.TrimSpace(e.Name) == "" {
		problems = append(problems, "a name is required")
	}
	if !idPattern.MatchString(e.ID) {
		problems = append(problems, "identifier must be 2-64 characters of letters, digits, dot, dash or underscore")
	}
	seen := map[string]bool{}
	for _, n := range e.Networks {
		p, err := n.Prefix()
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if seen[p.String()] {
			problems = append(problems, "network "+p.String()+" is listed twice")
		}
		seen[p.String()] = true
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)

// Asset is one host or network device inside an enclave. Hosts and network
// devices share a record because they share almost every field that matters to
// risk; Type is what keeps a switch from being measured against a control that
// only a workstation could ever meet.
type Asset struct {
	ID        string    `json:"id"`
	EnclaveID string    `json:"enclave_id"`
	Name      string    `json:"name"`
	FQDN      string    `json:"fqdn,omitempty"`
	Type      AssetType `json:"type"`
	Role      string    `json:"role,omitempty"`

	Criticality Criticality `json:"criticality"`

	OS        string `json:"os,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Model     string `json:"model,omitempty"`
	Firmware  string `json:"firmware,omitempty"`
	Serial    string `json:"serial,omitempty"`

	IPs  []string `json:"ips,omitempty"`
	MACs []string `json:"macs,omitempty"`

	Owner    string   `json:"owner,omitempty"`
	Location string   `json:"location,omitempty"`
	Status   string   `json:"status,omitempty"`
	Notes    string   `json:"notes,omitempty"`
	Tags     []string `json:"tags,omitempty"`

	// Baselines assigned directly to the asset, on top of whatever its enclave
	// carries. A jump box may be held to a stricter benchmark than its peers.
	Baselines []BaselineRef `json:"baselines,omitempty"`

	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	Created   time.Time  `json:"created"`
	Updated   time.Time  `json:"updated"`
}

// PrimaryIP is the first recorded address, used wherever one address has to
// stand for the asset.
func (a *Asset) PrimaryIP() string {
	if len(a.IPs) > 0 {
		return a.IPs[0]
	}
	return ""
}

// DisplayName prefers the hostname and falls back to an address so that an
// asset discovered by a network scan is still identifiable.
func (a *Asset) DisplayName() string {
	if strings.TrimSpace(a.Name) != "" {
		return a.Name
	}
	if ip := a.PrimaryIP(); ip != "" {
		return ip
	}
	return a.ID
}

// Platform is a short human description of what the asset runs.
func (a *Asset) Platform() string {
	parts := []string{}
	for _, s := range []string{a.Vendor, a.OS, a.OSVersion} {
		if strings.TrimSpace(s) != "" {
			parts = append(parts, strings.TrimSpace(s))
		}
	}
	if len(parts) == 0 {
		return "Unknown"
	}
	return strings.Join(parts, " ")
}

// Stale reports whether nothing has reported on the asset within the window.
func (a *Asset) Stale(now time.Time, window time.Duration) bool {
	if a.LastSeen == nil {
		return true
	}
	return now.Sub(*a.LastSeen) > window
}

// Validate checks the fields a person can get wrong on the asset form.
func (a *Asset) Validate() error {
	var problems []string
	if strings.TrimSpace(a.Name) == "" && len(a.IPs) == 0 {
		problems = append(problems, "an asset needs a name or at least one address")
	}
	if a.EnclaveID == "" {
		problems = append(problems, "an asset must belong to an enclave")
	}
	for _, ip := range a.IPs {
		if _, err := netip.ParseAddr(strings.TrimSpace(ip)); err != nil {
			problems = append(problems, "not an IP address: "+ip)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// Scan is one imported result file. It records where the results came from so
// that any finding can be traced back to the artefact that produced it.
type Scan struct {
	ID        string `json:"id"`
	EnclaveID string `json:"enclave_id"`

	Kind   string `json:"kind"`   // stig, scap, vulnerability, benchmark, manual
	Format string `json:"format"` // ckl, cklb, xccdf, nessus, csv

	Title       string `json:"title,omitempty"`
	BenchmarkID string `json:"benchmark_id,omitempty"`
	Version     string `json:"version,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ImportedBy  string `json:"imported_by,omitempty"`

	ScanDate   time.Time `json:"scan_date"`
	ImportedAt time.Time `json:"imported_at"`

	AssetIDs []string       `json:"asset_ids,omitempty"`
	Counts   map[string]int `json:"counts,omitempty"`
	Notes    string         `json:"notes,omitempty"`
}

// Total is the number of results the scan produced, open or not.
func (s *Scan) Total() int {
	n := 0
	for _, v := range s.Counts {
		n += v
	}
	return n
}

// Finding is one result about one asset. Findings from every source share this
// shape so that a STIG rule, a Nessus plugin and a CIS benchmark item can be
// counted, aged and mapped to controls the same way.
type Finding struct {
	ID        string `json:"id"`
	EnclaveID string `json:"enclave_id"`
	AssetID   string `json:"asset_id"`
	ScanID    string `json:"scan_id"`

	RuleID  string `json:"rule_id,omitempty"`  // SV-230221r1000 or a plugin id
	GroupID string `json:"group_id,omitempty"` // V-230221
	Title   string `json:"title"`

	Severity    Severity      `json:"severity"`
	RawSeverity string        `json:"raw_severity,omitempty"`
	Status      FindingStatus `json:"status"`

	Description    string `json:"description,omitempty"`
	CheckText      string `json:"check_text,omitempty"`
	FixText        string `json:"fix_text,omitempty"`
	FindingDetails string `json:"finding_details,omitempty"`
	Comments       string `json:"comments,omitempty"`

	CCIs       []string `json:"ccis,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	References []string `json:"references,omitempty"`

	// ControlRefs is filled in by the mapping layer: catalogue id to the
	// control identifiers within it that this finding is evidence about.
	ControlRefs map[string][]string `json:"control_refs,omitempty"`

	CVSS       float64 `json:"cvss,omitempty"`
	CVSSVector string  `json:"cvss_vector,omitempty"`
	Port       int     `json:"port,omitempty"`
	Protocol   string  `json:"protocol,omitempty"`
	Service    string  `json:"service,omitempty"`

	Fingerprint string `json:"fingerprint"`

	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	DueDate   *time.Time `json:"due_date,omitempty"`

	Disposition     Disposition `json:"disposition"`
	DispositionNote string      `json:"disposition_note,omitempty"`
	DispositionBy   string      `json:"disposition_by,omitempty"`
	DispositionAt   *time.Time  `json:"disposition_at,omitempty"`
}

// Age is how long the finding has been known about.
func (f *Finding) Age(now time.Time) time.Duration { return now.Sub(f.FirstSeen) }

// AgeDays is Age in whole days, which is the unit remediation targets use.
func (f *Finding) AgeDays(now time.Time) int { return int(f.Age(now).Hours() / 24) }

// Live reports whether the finding still represents an unresolved condition.
//
// A risk that has been accepted is still live. Accepting a risk is a decision,
// not a fix: the weakness is still there, it still counts against the control
// it weakens, and it still carries weight in the risk score. What it is not is
// work outstanding, which is a different question and NeedsWork answers it.
func (f *Finding) Live() bool {
	if !f.Status.Counts() {
		return false
	}
	return f.Disposition.Residual() > 0
}

// Accepted reports whether somebody has deliberately decided to live with this.
func (f *Finding) Accepted() bool { return f.Disposition == DispositionRiskAccepted }

// NeedsWork reports whether the finding is somebody's outstanding task. This is
// what "open" means on a page that is asking what to fix next: a live finding
// that nobody has decided to accept.
func (f *Finding) NeedsWork() bool { return f.Live() && !f.Accepted() }

// State is the single word that describes where a finding stands, for a page
// that has room for one. It resolves the scanner's result and the recorded
// decision into one answer rather than showing both and leaving the reader to
// work out which of "Open" and "Risk accepted" wins.
func (f *Finding) State() string {
	switch {
	case !f.Status.Counts():
		return f.Status.Label()
	case f.Disposition == DispositionOpen:
		return "Open"
	default:
		return f.Disposition.Label()
	}
}

// Decided reports whether anybody has recorded a decision about this, which is
// what tells a page whether the scanner's result still speaks for itself.
func (f *Finding) Decided() bool { return f.Disposition != DispositionOpen }

// Controls returns the control identifiers this finding is evidence about
// within one catalogue.
func (f *Finding) Controls(catalogID string) []string {
	if f.ControlRefs == nil {
		return nil
	}
	return f.ControlRefs[catalogID]
}

// Assessment is a judgement about one control within one enclave. It is the
// human half of the picture; findings are the machine half, and the gap
// analysis reconciles the two.
type Assessment struct {
	ID        string `json:"id"`
	EnclaveID string `json:"enclave_id"`
	CatalogID string `json:"catalog_id"`
	ControlID string `json:"control_id"`

	Status      ImplStatus `json:"status"`
	Origination string     `json:"origination,omitempty"` // system, inherited, hybrid
	Responsible string     `json:"responsible,omitempty"`
	Narrative   string     `json:"narrative,omitempty"`
	Evidence    []string   `json:"evidence,omitempty"`

	AssessedBy string     `json:"assessed_by,omitempty"`
	AssessedAt *time.Time `json:"assessed_at,omitempty"`
	ReviewDue  *time.Time `json:"review_due,omitempty"`
	Updated    time.Time  `json:"updated"`
}

// Key is the identity of an assessment: one per control per catalogue per
// enclave.
func (a *Assessment) Key() string {
	return a.EnclaveID + "|" + a.CatalogID + "|" + a.ControlID
}

// Milestone is one scheduled step towards closing a risk entry.
type Milestone struct {
	Description string     `json:"description"`
	Due         *time.Time `json:"due,omitempty"`
	Completed   *time.Time `json:"completed,omitempty"`
}

// RiskEntry is a tracked risk: the plan-of-action record that ties findings and
// controls to an owner and a date. It is generic enough to serve as a POA&M
// line, a risk register row, or a plain remediation ticket.
type RiskEntry struct {
	ID        string `json:"id"`
	EnclaveID string `json:"enclave_id"`
	Title     string `json:"title"`
	Weakness  string `json:"weakness,omitempty"`
	Source    string `json:"source,omitempty"` // scan, assessment, audit, manual

	ControlRefs map[string][]string `json:"control_refs,omitempty"`
	FindingIDs  []string            `json:"finding_ids,omitempty"`
	AssetIDs    []string            `json:"asset_ids,omitempty"`

	Likelihood int `json:"likelihood"` // 1..5
	Impact     int `json:"impact"`     // 1..5

	Status     string `json:"status"` // open, in_progress, completed, risk_accepted, closed
	Owner      string `json:"owner,omitempty"`
	Mitigation string `json:"mitigation,omitempty"`
	Resources  string `json:"resources,omitempty"`

	Milestones []Milestone `json:"milestones,omitempty"`

	Detected  time.Time  `json:"detected"`
	Due       *time.Time `json:"due,omitempty"`
	Completed *time.Time `json:"completed,omitempty"`
	Updated   time.Time  `json:"updated"`
}

// Score is the 1..25 likelihood-by-impact product used on the risk matrix.
func (r *RiskEntry) Score() int { return clampInt(r.Likelihood, 1, 5) * clampInt(r.Impact, 1, 5) }

// Band names the risk score for reporting.
func (r *RiskEntry) Band() string {
	switch s := r.Score(); {
	case s >= 20:
		return "Very high"
	case s >= 12:
		return "High"
	case s >= 6:
		return "Moderate"
	case s >= 3:
		return "Low"
	}
	return "Very low"
}

// Open reports whether the entry is still being worked.
func (r *RiskEntry) Open() bool {
	return r.Status != "completed" && r.Status != "closed"
}

// Overdue reports whether an open entry has passed its scheduled completion.
func (r *RiskEntry) Overdue(now time.Time) bool {
	return r.Open() && r.Due != nil && now.After(*r.Due)
}

// RiskStatuses is the selectable set for a risk entry.
var RiskStatuses = []string{"open", "in_progress", "completed", "risk_accepted", "closed"}

// Environments and lifecycle values offered on forms. They are suggestions
// rather than a closed set: the field is free text so an organisation can use
// its own vocabulary.
var (
	Environments  = []string{"Production", "Test", "Development", "Staging", "Disaster Recovery", "Lab", "Training"}
	EnclaveStatus = []string{"Active", "Planned", "In development", "Decommissioning", "Retired"}
	AuthStatuses  = []string{"Authorized", "Authorized with conditions", "Provisional", "In process", "Not authorized", "Not applicable"}
	AssetStatuses = []string{"Active", "Inactive", "Maintenance", "Retired"}
	RiskSources   = []string{"scan", "assessment", "audit", "manual", "inherited"}
	Originations  = []string{"system", "inherited", "hybrid", "provider"}
)

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// SortStrings returns a sorted copy, used wherever a set has to render stably.
func SortStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// Dedup removes blanks and duplicates while preserving first-seen order.
func Dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// SlugID turns free text into an identifier that is safe in a URL and in a
// filename while keeping the case a person typed. Enclave identifiers are read
// by people in exports and URLs, so "CORE-OPS" should not silently become
// "core-ops".
func SlugID(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-._")
}
