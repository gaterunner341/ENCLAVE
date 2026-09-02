package risk

import (
	"sort"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/model"
)

// GapState is what the analysis concluded about one control.
type GapState string

const (
	// GapSatisfied: claimed implemented (or inherited, or not applicable) and
	// no scan result contradicts the claim.
	GapSatisfied GapState = "satisfied"
	// GapContradicted: claimed implemented, but scan results against this
	// control are failing. This is the most valuable state the tool produces,
	// because it is the one nobody finds by reading a document.
	GapContradicted GapState = "contradicted"
	// GapFailing: not claimed implemented, and scan results are failing.
	GapFailing GapState = "failing"
	// GapClaimed: claimed implemented, with no evidence either way.
	GapClaimed GapState = "claimed"
	// GapPlanned: acknowledged as partial or planned.
	GapPlanned GapState = "planned"
	// GapGap: assessed as not implemented.
	GapGap GapState = "gap"
	// GapUnassessed: nobody has said anything and no scan speaks to it.
	GapUnassessed GapState = "unassessed"
)

// Label describes a state on a page.
func (g GapState) Label() string {
	switch g {
	case GapSatisfied:
		return "Satisfied"
	case GapContradicted:
		return "Contradicted by scans"
	case GapFailing:
		return "Failing"
	case GapClaimed:
		return "Claimed, no evidence"
	case GapPlanned:
		return "Partial or planned"
	case GapGap:
		return "Not implemented"
	}
	return "Not assessed"
}

// Open reports whether the state represents work outstanding.
func (g GapState) Open() bool {
	switch g {
	case GapSatisfied, GapClaimed:
		return false
	}
	return true
}

// Weight orders the states worst-first on the gap page.
func (g GapState) Weight() int {
	switch g {
	case GapContradicted:
		return 6
	case GapFailing:
		return 5
	case GapGap:
		return 4
	case GapUnassessed:
		return 3
	case GapPlanned:
		return 2
	case GapClaimed:
		return 1
	}
	return 0
}

// ControlGap is the analysis of one control within one enclave.
type ControlGap struct {
	Control    catalog.Control
	State      GapState
	Assessment *model.Assessment
	Findings   []*model.Finding
	OpenCount  int
	PassCount  int
	Worst      model.Severity
	Assets     int
	RiskScore  float64
}

// Evidence reports whether any scan result speaks to the control.
func (g ControlGap) Evidence() bool { return g.OpenCount+g.PassCount > 0 }

// FamilyGap aggregates the controls of one family.
type FamilyGap struct {
	ID       string
	Name     string
	Controls []ControlGap
	Counts   map[GapState]int
	Total    int
}

// Coverage is the share of the family's controls that are satisfied or
// claimed, expressed 0-100.
func (f FamilyGap) Coverage() float64 {
	if f.Total == 0 {
		return 0
	}
	ok := f.Counts[GapSatisfied] + f.Counts[GapClaimed]
	return float64(ok) / float64(f.Total) * 100
}

// OpenCount is the number of controls in the family with work outstanding.
func (f FamilyGap) OpenCount() int {
	n := 0
	for state, c := range f.Counts {
		if state.Open() {
			n += c
		}
	}
	return n
}

// Analysis is a whole baseline measured against one enclave.
type Analysis struct {
	Catalog   *catalog.Catalog
	ProfileID string
	Enclave   *model.Enclave
	Families  []FamilyGap
	Counts    map[GapState]int
	Total     int
	// UnmappedFindings are live findings that reached no control in this
	// catalogue. They are shown rather than hidden, because a large unmapped
	// count means the mapping tables need work, not that the estate is clean.
	UnmappedFindings int
}

// Coverage is the share of the baseline that is satisfied or claimed.
func (a Analysis) Coverage() float64 {
	if a.Total == 0 {
		return 0
	}
	ok := a.Counts[GapSatisfied] + a.Counts[GapClaimed]
	return float64(ok) / float64(a.Total) * 100
}

// Verified is the share backed by passing scan evidence rather than a claim
// alone. It is the number worth reporting upward.
func (a Analysis) Verified() float64 {
	if a.Total == 0 {
		return 0
	}
	return float64(a.Counts[GapSatisfied]) / float64(a.Total) * 100
}

// OpenCount is the number of controls with work outstanding.
func (a Analysis) OpenCount() int {
	n := 0
	for state, c := range a.Counts {
		if state.Open() {
			n += c
		}
	}
	return n
}

// Worst returns the controls in the worst states, most serious first, for the
// summary at the top of the page.
func (a Analysis) Worst(limit int) []ControlGap {
	out := []ControlGap{}
	for _, fam := range a.Families {
		for _, g := range fam.Controls {
			if g.State.Open() {
				out = append(out, g)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].State.Weight() != out[j].State.Weight() {
			return out[i].State.Weight() > out[j].State.Weight()
		}
		if out[i].RiskScore != out[j].RiskScore {
			return out[i].RiskScore > out[j].RiskScore
		}
		return out[i].Control.ID < out[j].Control.ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Analyse measures one enclave against one baseline.
//
// For each control in the selected profile it gathers the findings mapped to
// it and the assessment recorded against it, then applies one rule:
//
//   - failing scan evidence always wins over a claim, and when a claim exists
//     the control is reported as contradicted rather than merely failing,
//     because the two need different conversations;
//   - passing evidence upgrades a claim from "claimed" to "satisfied";
//   - with no evidence at all, the assessment stands on its own.
func Analyse(
	cat *catalog.Catalog, profileID string, e *model.Enclave,
	assets []*model.Asset, findings []*model.Finding,
	assessments map[string]*model.Assessment, now time.Time,
) Analysis {
	assetByID := make(map[string]*model.Asset, len(assets))
	for _, a := range assets {
		assetByID[a.ID] = a
	}

	byControl := map[string][]*model.Finding{}
	unmapped := 0
	for _, f := range findings {
		refs := f.Controls(cat.ID)
		if len(refs) == 0 {
			if f.Live() {
				unmapped++
			}
			continue
		}
		for _, id := range refs {
			key := catalog.NormaliseID(id)
			byControl[key] = append(byControl[key], f)
			// Evidence about an enhancement is also evidence about its base
			// control, so a profile that selects only the base still sees it.
			if base := catalog.NormaliseID(catalog.BaseID(id)); base != key {
				byControl[base] = append(byControl[base], f)
			}
		}
	}

	out := Analysis{
		Catalog: cat, ProfileID: profileID, Enclave: e,
		Counts: map[GapState]int{}, UnmappedFindings: unmapped,
	}

	for _, famID := range cat.FamilyIDs(profileID) {
		fam := FamilyGap{ID: famID, Name: cat.FamilyName(famID), Counts: map[GapState]int{}}
		for _, ctl := range cat.FamilyControls(famID, profileID) {
			g := ControlGap{Control: ctl, Worst: model.SeverityInfo}
			g.Assessment = assessments[cat.ID+"|"+ctl.ID]
			seenAsset := map[string]bool{}
			for _, f := range byControl[catalog.NormaliseID(ctl.ID)] {
				g.Findings = append(g.Findings, f)
				if f.Live() {
					g.OpenCount++
					g.RiskScore += FindingScore(f, assetByID[f.AssetID], now)
					if f.Severity.Rank() > g.Worst.Rank() {
						g.Worst = f.Severity.Normalise()
					}
					seenAsset[f.AssetID] = true
				} else if f.Status.Normalise() == model.StatusNotAFinding {
					g.PassCount++
				}
			}
			g.Assets = len(seenAsset)
			sort.Slice(g.Findings, func(i, j int) bool {
				a, b := g.Findings[i], g.Findings[j]
				if a.Live() != b.Live() {
					return a.Live()
				}
				return a.Severity.Rank() > b.Severity.Rank()
			})
			g.State = classify(g)
			fam.Controls = append(fam.Controls, g)
			fam.Counts[g.State]++
			fam.Total++
			out.Counts[g.State]++
			out.Total++
		}
		if fam.Total > 0 {
			out.Families = append(out.Families, fam)
		}
	}
	return out
}

func classify(g ControlGap) GapState {
	claimed := g.Assessment != nil && g.Assessment.Status.Satisfied()
	switch {
	case g.OpenCount > 0 && claimed:
		return GapContradicted
	case g.OpenCount > 0:
		return GapFailing
	case g.PassCount > 0 && claimed:
		return GapSatisfied
	case claimed:
		return GapClaimed
	case g.Assessment == nil || g.Assessment.Status == model.ImplNotAssessed:
		if g.PassCount > 0 {
			// Scans pass but nobody has assessed it. That is evidence, not an
			// assessment, so it is not counted as covered.
			return GapUnassessed
		}
		return GapUnassessed
	case g.Assessment.Status == model.ImplNotImplemented:
		return GapGap
	default:
		return GapPlanned
	}
}

// States is the display order for legends and summary rows.
var States = []GapState{
	GapContradicted, GapFailing, GapGap, GapUnassessed, GapPlanned, GapClaimed, GapSatisfied,
}
