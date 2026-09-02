// Package coverage answers the only question the inventory exists to answer:
// of the machines somebody is accountable for, how many are actually covered
// by the controls that are supposed to cover them.
package coverage

import (
	"net/netip"
	"strings"
	"time"

	"github.com/pkittelson/enclave/internal/model"
)

// Control is one thing that is meant to be true of a machine.
//
// Eligible and Met are kept apart on purpose. A control a host cannot be
// judged on is not a failure, and counting it as one is how coverage numbers
// stop being believed.
type Control struct {
	ID    string
	Label string
	Hint  string
	// Target is the share of eligible hosts expected to meet the control.
	Target int
	// StaleAfter is how old a reading may be before it stops counting.
	StaleAfter time.Duration
	Eligible   func(*model.Host) bool
	Met        func(*model.Host) bool
}

// Result is one control measured over one set of hosts.
type Result struct {
	Control    Control
	Label      string
	Eligible   int
	Met        int
	Missing    int
	Percent    int
	Target     int
	OverTarget int // percentage points short of target; zero or less is fine
}

// DefaultControls is the set measured out of the box. Four, because four is
// what a person can hold in their head while reading a table.
func DefaultControls() []Control {
	const (
		vulnWindow      = 30 * 24 * time.Hour
		benchmarkWindow = 90 * 24 * time.Hour
	)
	return []Control{
		{
			ID:       "edr",
			Label:    "EDR",
			Hint:     "An endpoint agent is installed and reporting healthy",
			Target:   98,
			Eligible: func(h *model.Host) bool { return isEndpoint(h) },
			Met: func(h *model.Host) bool {
				return healthy(h.Field(model.FieldEDRStatus))
			},
		},
		{
			ID:       "encryption",
			Label:    "Encrypted",
			Hint:     "The system disk is encrypted at rest",
			Target:   95,
			Eligible: func(h *model.Host) bool { return isEndpoint(h) },
			Met: func(h *model.Host) bool {
				return affirmative(h.Field(model.FieldDiskEncrypted))
			},
		},
		{
			ID:         "vuln_scan",
			Label:      "Vuln scan",
			Hint:       "Scanned for vulnerabilities within the last 30 days",
			Target:     90,
			StaleAfter: vulnWindow,
			Eligible:   func(h *model.Host) bool { return true },
			Met: func(h *model.Host) bool {
				return within(h.Field(model.FieldLastVulnScan), vulnWindow)
			},
		},
		{
			ID:         "benchmark",
			Label:      "Benchmark",
			Hint:       "Checked against its hardening baseline within 90 days",
			Target:     85,
			StaleAfter: benchmarkWindow,
			Eligible:   func(h *model.Host) bool { return true },
			Met: func(h *model.Host) bool {
				return within(h.Field(model.FieldLastBenchmarkScan), benchmarkWindow)
			},
		},
	}
}

// Measure runs every control over a set of hosts.
func Measure(hosts []*model.Host, controls []Control) []Result {
	out := make([]Result, 0, len(controls))
	for _, c := range controls {
		r := Result{Control: c, Label: c.Label, Target: c.Target}
		for _, h := range hosts {
			if c.Eligible != nil && !c.Eligible(h) {
				continue
			}
			r.Eligible++
			if c.Met != nil && c.Met(h) {
				r.Met++
			}
		}
		r.Missing = r.Eligible - r.Met
		if r.Eligible > 0 {
			r.Percent = percent(r.Met, r.Eligible)
		}
		r.OverTarget = c.Target - r.Percent
		out = append(out, r)
	}
	return out
}

// Affected counts the hosts that fall short of at least one control they are
// eligible for. It is the number to act on: hosts, not findings.
func Affected(hosts []*model.Host, controls []Control) int {
	n := 0
	for _, h := range hosts {
		for _, c := range controls {
			if c.Eligible != nil && !c.Eligible(h) {
				continue
			}
			if c.Met == nil || !c.Met(h) {
				n++
				break
			}
		}
	}
	return n
}

// Assign places each host in an enclave by matching its address against the
// defined ranges, longest prefix first. A manual decision beats any range: a
// person who has looked at the machine knows more than its address does.
func Assign(hosts []*model.Host, enclaves []*model.Enclave, manual map[string]string) {
	type rule struct {
		prefix netip.Prefix
		id     string
	}
	var rules []rule
	for _, e := range enclaves {
		for _, c := range e.CIDRs {
			p, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				continue
			}
			rules = append(rules, rule{p.Masked(), e.ID})
		}
	}

	for _, h := range hosts {
		if id, ok := manual[h.ID]; ok && id != "" {
			h.EnclaveID = id
			continue
		}
		h.EnclaveID = ""
		addr, err := netip.ParseAddr(strings.TrimSpace(h.Field(model.FieldIP)))
		if err != nil {
			continue
		}
		best := -1
		for _, r := range rules {
			if !r.prefix.Contains(addr) {
				continue
			}
			if r.prefix.Bits() > best {
				best = r.prefix.Bits()
				h.EnclaveID = r.id
			}
		}
	}
}

// percent rounds to the nearest whole percent, but never reports 100 unless
// every eligible host really is covered.
func percent(part, whole int) int {
	if whole <= 0 {
		return 0
	}
	p := (part*200 + whole) / (whole * 2)
	if p >= 100 && part < whole {
		return 99
	}
	if p <= 0 && part > 0 {
		return 1
	}
	return p
}

// isEndpoint reports whether a host is the kind of machine an agent belongs
// on. Network gear and appliances are excluded rather than counted as failing.
func isEndpoint(h *model.Host) bool {
	role := strings.ToLower(h.Field(model.FieldDeviceRole))
	switch {
	case strings.Contains(role, "network"),
		strings.Contains(role, "switch"),
		strings.Contains(role, "router"),
		strings.Contains(role, "firewall"),
		strings.Contains(role, "printer"),
		strings.Contains(role, "appliance"),
		strings.Contains(role, "iot"),
		strings.Contains(role, "ot"):
		return false
	}
	os := strings.ToLower(h.Field(model.FieldOS))
	if os == "" {
		// Nothing known either way. Treat it as an endpoint: a machine nobody
		// can describe is exactly the one worth chasing.
		return true
	}
	for _, appliance := range []string{"ios", "nx-os", "junos", "fortios", "panos", "esxi", "vmkernel", "printer"} {
		if strings.Contains(os, appliance) {
			return false
		}
	}
	return true
}

// healthy reads the many ways an agent reports that it is working.
func healthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "unknown", "n/a", "none":
		return false
	case "normal", "healthy", "ok", "online", "active", "installed",
		"protected", "running", "yes", "true", "1", "enabled", "reporting":
		return true
	}
	return false
}

func affirmative(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on", "enabled", "encrypted", "protected", "compliant":
		return true
	}
	return false
}

// within reports whether a date is present and recent enough.
func within(v string, window time.Duration) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02 15:04:05", "01/02/2006"} {
		if t, err := time.Parse(layout, v); err == nil {
			return time.Since(t) <= window
		}
	}
	return false
}
