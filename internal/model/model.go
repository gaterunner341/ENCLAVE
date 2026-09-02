// Package model holds the value types every other package agrees on: the
// observations that come out of a feed, the hosts they merge into, and the
// enclaves those hosts are placed in.
package model

import (
	"sort"
	"strings"
	"time"
)

// Identifier is one way a feed names a machine. Merging is done on these and
// nothing else, so their normalisation rules are the most load-bearing code
// in the program.
type Identifier struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Identifier kinds, most stable first. A serial or hardware UUID survives a
// rebuild; a hostname or an address does not.
const (
	IDSerial   = "serial"
	IDUUID     = "uuid"
	IDMAC      = "mac"
	IDFQDN     = "fqdn"
	IDHostname = "hostname"
	IDNetBIOS  = "netbios"
	IDIPv4     = "ipv4"
	IDAssetTag = "asset_tag"
)

// Normalize returns the identifier in the form used for comparison. Feeds
// disagree about case, punctuation and domain suffixes for the same machine,
// so those differences are removed before anything is matched.
func (i Identifier) Normalize() Identifier {
	v := strings.TrimSpace(i.Value)
	switch i.Kind {
	case IDMAC:
		v = strings.ToLower(keepAlnum(v))
	case IDUUID:
		v = strings.ToLower(keepAlnum(v))
	case IDSerial, IDAssetTag:
		v = strings.ToUpper(keepAlnum(v))
	case IDHostname, IDNetBIOS:
		v = strings.ToLower(v)
		if host, _, ok := strings.Cut(v, "."); ok {
			v = host
		}
	case IDFQDN:
		v = strings.ToLower(strings.TrimSuffix(v, "."))
	default:
		v = strings.ToLower(v)
	}
	return Identifier{Kind: i.Kind, Value: v}
}

// Key is the map key a normalised identifier is stored under.
func (i Identifier) Key() string { return i.Kind + ":" + i.Value }

// Valid reports whether an identifier is worth merging on. Empty values and
// the placeholders tools emit for "unknown" are not.
func (i Identifier) Valid() bool {
	n := i.Normalize()
	if n.Kind == "" || n.Value == "" {
		return false
	}
	// Tools write "unknown" in a dozen ways. Compare on the reduced form so
	// none of them ends up merging every unidentified machine into one host.
	switch strings.ToLower(keepAlnum(n.Value)) {
	case "", "0", "unknown", "none", "na", "null", "nil", "notapplicable",
		"tobefilledbyoem", "systemserialnumber", "defaultstring",
		"invalid", "notspecified", "chassisserialnumber",
		"00000000000000000000000000000000", "000000000000",
		"ffffffffffffffffffffffffffffffff", "ffffffffffff":
		return false
	}
	if n.Kind == IDMAC && len(n.Value) != 12 {
		return false
	}
	return true
}

func keepAlnum(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Conflict is a value that lost to a more authoritative feed. Losers are kept
// rather than dropped so that a wrong record can be shown to be wrong.
type Conflict struct {
	Value       string    `json:"value"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
}

// FieldValue is the winning value for one field plus everything that lost.
type FieldValue struct {
	Value       string     `json:"value"`
	Source      string     `json:"source"`
	CollectedAt time.Time  `json:"collected_at"`
	Conflicts   []Conflict `json:"conflicts,omitempty"`
}

// Field keys. Every feed is mapped onto this vocabulary at import time, so
// nothing downstream has to know which tool a value came from.
const (
	FieldIP                = "ip"
	FieldOS                = "os"
	FieldOSVersion         = "os_version"
	FieldOwner             = "owner"
	FieldLocation          = "location"
	FieldDeviceRole        = "device_role"
	FieldManufacturer      = "manufacturer"
	FieldHardwareModel     = "hardware_model"
	FieldEDRStatus         = "edr_status"
	FieldDiskEncrypted     = "disk_encrypted"
	FieldLastVulnScan      = "last_vuln_scan"
	FieldLastBenchmarkScan = "last_benchmark_scan"
)

// Observation is one row of one import: what a single feed claimed about a
// single machine at a single point in time. Observations are append-only and
// are never edited; the host view is rebuilt from them.
type Observation struct {
	Identifiers []Identifier         `json:"identifiers"`
	Fields      map[string]string    `json:"fields"`
	BoolFields  map[string]bool      `json:"bool_fields,omitempty"`
	TimeFields  map[string]time.Time `json:"time_fields,omitempty"`
	SourceID    string               `json:"source_id"`
	SourceKind  string               `json:"source_kind"`
	CollectedAt time.Time            `json:"collected_at"`
	IngestedAt  time.Time            `json:"ingested_at"`
	Batch       string               `json:"batch,omitempty"`
}

// Host is the merged record for one machine: one row per asset, whatever the
// number of feeds that reported it.
type Host struct {
	ID          string                `json:"id"`
	Identifiers []Identifier          `json:"identifiers"`
	Fields      map[string]FieldValue `json:"fields"`
	Sources     []string              `json:"sources"`
	EnclaveID   string                `json:"enclave_id,omitempty"`
	FirstSeen   time.Time             `json:"first_seen"`
	LastSeen    time.Time             `json:"last_seen"`
	Retired     bool                  `json:"retired,omitempty"`
}

// Hostname returns the best name any feed supplied, preferring the short name
// over the fully qualified one.
func (h *Host) Hostname() string {
	for _, kind := range []string{IDHostname, IDNetBIOS, IDFQDN} {
		for _, id := range h.Identifiers {
			if id.Kind == kind && id.Value != "" {
				return id.Value
			}
		}
	}
	return ""
}

// Named reports whether the host has a name at all. One that does not is
// identified only by hardware address, which is worth flagging in the UI.
func (h *Host) Named() bool { return h.Hostname() != "" }

// DisplayName is what the host is called on screen.
func (h *Host) DisplayName() string {
	if n := h.Hostname(); n != "" {
		return n
	}
	for _, id := range h.Identifiers {
		switch id.Kind {
		case IDMAC:
			return "MAC-" + strings.ToUpper(id.Value)
		case IDSerial:
			return "SN-" + id.Value
		}
	}
	if ip, ok := h.Fields[FieldIP]; ok && ip.Value != "" {
		return ip.Value
	}
	return h.ID
}

// Field returns the winning value for a field, or the empty string.
func (h *Host) Field(name string) string { return h.Fields[name].Value }

// Enclave is a network segment with somebody accountable for it. Hosts are
// placed by matching their address against the ranges below.
type Enclave struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDRs     []string  `json:"cidrs"`
	Owner     string    `json:"owner"`
	Impact    string    `json:"impact"`
	Framework string    `json:"framework"`
	Exposed   bool      `json:"publicly_exposed"`
	CreatedAt time.Time `json:"created_at"`
}

// Retirement records that a host was taken out of service, and by whom.
type Retirement struct {
	HostID string    `json:"host_id"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	Reason string    `json:"reason"`
	Status string    `json:"status,omitempty"`
}

// SortHosts orders hosts the way every listing shows them: named hosts first,
// then alphabetically, so the same machine keeps the same place on the page.
func SortHosts(hosts []*Host) {
	sort.SliceStable(hosts, func(i, j int) bool {
		a, b := hosts[i], hosts[j]
		if a.Named() != b.Named() {
			return a.Named()
		}
		return strings.ToLower(a.DisplayName()) < strings.ToLower(b.DisplayName())
	})
}
