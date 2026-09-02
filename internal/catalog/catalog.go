// Package catalog holds control baselines: the frameworks an enclave is
// measured against. Three are built in (NIST SP 800-53 Rev 5, the CIS Critical
// Security Controls v8 and the NIST Cybersecurity Framework 2.0) and any
// number more can be loaded from disk, so an organisation that uses its own
// framework is a first-class citizen rather than a special case.
package catalog

import (
	"fmt"
	"sort"
	"strings"
)

// Control is one requirement within a catalogue. The same struct carries an
// 800-53 control, an 800-53 control enhancement, a CIS safeguard and a CSF
// subcategory, because all four are "a thing with an identifier that an enclave
// either satisfies or does not".
type Control struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	FamilyID   string   `json:"family_id"`
	Family     string   `json:"family"`
	Parent     string   `json:"parent,omitempty"`
	Class      string   `json:"class,omitempty"` // control, enhancement, safeguard, subcategory
	Statement  string   `json:"statement,omitempty"`
	Discussion string   `json:"discussion,omitempty"`
	Profiles   []string `json:"profiles,omitempty"`
	Related    []string `json:"related,omitempty"`
}

// IsEnhancement reports whether the control refines another one.
func (c Control) IsEnhancement() bool { return c.Parent != "" }

// InProfile reports membership of a named profile. An empty profile id means
// "the whole catalogue", which is what an enclave gets when no profile is set.
func (c Control) InProfile(profileID string) bool {
	if profileID == "" {
		return true
	}
	for _, p := range c.Profiles {
		if strings.EqualFold(p, profileID) {
			return true
		}
	}
	return false
}

// Profile is a named subset of a catalogue: an impact baseline in 800-53, an
// implementation group in CIS, a tier or overlay elsewhere.
type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Family groups controls for reporting. Gap analysis is nearly always read by
// family first and by individual control second.
type Family struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Catalog is a complete control framework.
type Catalog struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	Publisher   string    `json:"publisher,omitempty"`
	Description string    `json:"description,omitempty"`
	Source      string    `json:"source,omitempty"`
	BuiltIn     bool      `json:"built_in"`
	Profiles    []Profile `json:"profiles,omitempty"`
	Families    []Family  `json:"families,omitempty"`
	Controls    []Control `json:"controls"`

	index  map[string]int
	byFam  map[string][]int
	family map[string]string
}

// Index builds the lookup tables. It is called after load and after any
// mutation, and is safe to call repeatedly.
func (c *Catalog) Index() {
	c.index = make(map[string]int, len(c.Controls))
	c.byFam = make(map[string][]int)
	c.family = make(map[string]string, len(c.Families))
	for _, f := range c.Families {
		c.family[f.ID] = f.Name
	}
	for i := range c.Controls {
		ctl := &c.Controls[i]
		if ctl.Family == "" {
			ctl.Family = c.family[ctl.FamilyID]
		}
		c.index[normaliseID(ctl.ID)] = i
		c.byFam[ctl.FamilyID] = append(c.byFam[ctl.FamilyID], i)
	}
}

// Control looks a control up by identifier, tolerating spacing and case
// differences between "AC-2 (1)", "AC-2(1)" and "ac-2(1)".
func (c *Catalog) Control(id string) (Control, bool) {
	if c.index == nil {
		c.Index()
	}
	i, ok := c.index[normaliseID(id)]
	if !ok {
		return Control{}, false
	}
	return c.Controls[i], true
}

// Has reports whether the identifier resolves.
func (c *Catalog) Has(id string) bool { _, ok := c.Control(id); return ok }

// FamilyControls returns the controls of one family in catalogue order.
func (c *Catalog) FamilyControls(familyID string, profileID string) []Control {
	if c.byFam == nil {
		c.Index()
	}
	out := []Control{}
	for _, i := range c.byFam[familyID] {
		if c.Controls[i].InProfile(profileID) {
			out = append(out, c.Controls[i])
		}
	}
	return out
}

// Selected returns every control in the named profile, in catalogue order.
func (c *Catalog) Selected(profileID string) []Control {
	out := make([]Control, 0, len(c.Controls))
	for _, ctl := range c.Controls {
		if ctl.InProfile(profileID) {
			out = append(out, ctl)
		}
	}
	return out
}

// Profile looks up a profile by identifier.
func (c *Catalog) Profile(id string) (Profile, bool) {
	for _, p := range c.Profiles {
		if strings.EqualFold(p.ID, id) {
			return p, true
		}
	}
	return Profile{}, false
}

// ProfileName is the display name of a profile, or a readable fallback.
func (c *Catalog) ProfileName(id string) string {
	if id == "" {
		return "All controls"
	}
	if p, ok := c.Profile(id); ok {
		return p.Name
	}
	return id
}

// FamilyName resolves a family identifier for display.
func (c *Catalog) FamilyName(id string) string {
	if c.family == nil {
		c.Index()
	}
	if n, ok := c.family[id]; ok && n != "" {
		return n
	}
	return id
}

// Count is the number of controls in a profile.
func (c *Catalog) Count(profileID string) int {
	if profileID == "" {
		return len(c.Controls)
	}
	n := 0
	for _, ctl := range c.Controls {
		if ctl.InProfile(profileID) {
			n++
		}
	}
	return n
}

// Validate rejects a catalogue that cannot be reasoned about: no identifier, no
// controls, or duplicate control identifiers.
func (c *Catalog) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("catalog needs an id")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("catalog needs a name")
	}
	if len(c.Controls) == 0 {
		return fmt.Errorf("catalog %s has no controls", c.ID)
	}
	seen := map[string]bool{}
	for _, ctl := range c.Controls {
		k := normaliseID(ctl.ID)
		if k == "" {
			return fmt.Errorf("catalog %s has a control with no id", c.ID)
		}
		if seen[k] {
			return fmt.Errorf("catalog %s lists control %s twice", c.ID, ctl.ID)
		}
		seen[k] = true
	}
	return nil
}

// FamilyIDs returns the families that actually carry controls in the profile,
// in the order the catalogue declares them.
func (c *Catalog) FamilyIDs(profileID string) []string {
	if c.byFam == nil {
		c.Index()
	}
	out := []string{}
	seen := map[string]bool{}
	for _, f := range c.Families {
		if len(c.FamilyControls(f.ID, profileID)) > 0 {
			out = append(out, f.ID)
			seen[f.ID] = true
		}
	}
	extra := []string{}
	for id := range c.byFam {
		if !seen[id] && len(c.FamilyControls(id, profileID)) > 0 {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// normaliseID strips the spacing and case differences that different tools
// introduce into the same control identifier.
func normaliseID(id string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(id) {
		switch r {
		case ' ', '\t':
			continue
		}
		if r >= 'a' && r <= 'z' {
			r -= 32
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormaliseID is the exported form, used by the mapping layer so that mapped
// identifiers and catalogue identifiers agree.
func NormaliseID(id string) string { return normaliseID(id) }

// BaseID strips an enhancement suffix: AC-2(1) becomes AC-2. Findings often
// cite an enhancement that a catalogue profile does not select, and the base
// control is the right place to record the evidence in that case.
func BaseID(id string) string {
	if i := strings.IndexByte(id, '('); i > 0 {
		return strings.TrimSpace(id[:i])
	}
	return strings.TrimSpace(id)
}
