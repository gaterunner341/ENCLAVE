package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/model"
)

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func finding(sev model.Severity, ageDays int) *model.Finding {
	return &model.Finding{
		Title: "f", Severity: sev, Status: model.StatusOpen,
		Disposition: model.DispositionOpen,
		FirstSeen:   now.AddDate(0, 0, -ageDays), LastSeen: now,
	}
}

func TestFindingScoreRespectsSeverityOrder(t *testing.T) {
	a := &model.Asset{Criticality: model.CritModerate}
	last := 1e9
	for _, sev := range []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow,
	} {
		got := FindingScore(finding(sev, 1), a, now)
		if got >= last {
			t.Errorf("%s scored %v, which is not below the band above it (%v)", sev, got, last)
		}
		last = got
	}
	if FindingScore(finding(model.SeverityInfo, 1), a, now) != 0 {
		t.Error("an informational finding should contribute nothing")
	}
}

func TestFindingScoreWeightsAssetCriticality(t *testing.T) {
	f := finding(model.SeverityHigh, 1)
	mission := FindingScore(f, &model.Asset{Criticality: model.CritMission}, now)
	lab := FindingScore(f, &model.Asset{Criticality: model.CritLow}, now)
	if mission <= lab {
		t.Errorf("the same finding should weigh more on a mission-critical host: %v vs %v", mission, lab)
	}
}

func TestAgeingIsBoundedAtDoubleWeight(t *testing.T) {
	a := &model.Asset{Criticality: model.CritModerate}
	fresh := FindingScore(finding(model.SeverityHigh, 1), a, now)
	overdue := FindingScore(finding(model.SeverityHigh, 90), a, now)
	ancient := FindingScore(finding(model.SeverityHigh, 3650), a, now)
	if overdue <= fresh {
		t.Error("a finding past its target should score higher than a fresh one")
	}
	if ancient > 2*fresh+0.001 {
		t.Errorf("ageing should stop at double weight, got %v against a base of %v", ancient, fresh)
	}
}

func TestDispositionReducesScore(t *testing.T) {
	a := &model.Asset{Criticality: model.CritModerate}
	base := finding(model.SeverityHigh, 1)
	open := FindingScore(base, a, now)

	mitigated := finding(model.SeverityHigh, 1)
	mitigated.Disposition = model.DispositionMitigated
	accepted := finding(model.SeverityHigh, 1)
	accepted.Disposition = model.DispositionRiskAccepted
	fixed := finding(model.SeverityHigh, 1)
	fixed.Disposition = model.DispositionRemediated

	if FindingScore(mitigated, a, now) >= open {
		t.Error("mitigating should reduce the score")
	}
	if FindingScore(accepted, a, now) >= FindingScore(mitigated, a, now) {
		t.Error("an accepted risk should score below a mitigated one")
	}
	if FindingScore(fixed, a, now) != 0 {
		t.Error("a remediated finding should score zero")
	}
}

func TestPastTargetIgnoresClosedFindings(t *testing.T) {
	old := finding(model.SeverityCritical, 3650)
	if !PastTarget(old, now) {
		t.Error("a critical finding open for ten years is past target")
	}
	old.Disposition = model.DispositionRemediated
	if PastTarget(old, now) {
		t.Error("a closed finding is never past target, however old")
	}
	explicit := finding(model.SeverityLow, 1)
	future := now.AddDate(0, 0, 30)
	explicit.DueDate = &future
	if PastTarget(explicit, now) {
		t.Error("an explicit due date in the future overrides the default target")
	}
}

func TestEnclaveIndexScalesWithImpact(t *testing.T) {
	assets := []*model.Asset{{ID: "a", Criticality: model.CritModerate}}
	findings := []*model.Finding{finding(model.SeverityHigh, 1)}
	findings[0].AssetID = "a"

	low := ScoreEnclave(&model.Enclave{Confidentiality: model.ImpactLow}, assets, findings, now)
	high := ScoreEnclave(&model.Enclave{Confidentiality: model.ImpactHigh}, assets, findings, now)
	if high.Index <= low.Index {
		t.Errorf("the same weakness should read worse on a high-impact system: %v vs %v", high.Index, low.Index)
	}
	if high.Index > 100 || low.Index < 0 {
		t.Errorf("the index must stay within 0 to 100, got %v and %v", high.Index, low.Index)
	}
	clean := ScoreEnclave(&model.Enclave{}, assets, nil, now)
	if clean.Index != 0 || clean.Band != "Clean" {
		t.Errorf("an enclave with no open findings should read clean, got %v %q", clean.Index, clean.Band)
	}
}

func TestEnclaveIndexIsComparableAcrossSizes(t *testing.T) {
	// Two enclaves with the same problem per asset should land close together,
	// which is the whole point of normalising by asset count.
	build := func(n int) EnclaveRisk {
		assets := make([]*model.Asset, n)
		findings := make([]*model.Finding, n)
		for i := range assets {
			id := string(rune('a' + i%26))
			assets[i] = &model.Asset{ID: id, Criticality: model.CritModerate}
			f := finding(model.SeverityHigh, 1)
			f.AssetID = id
			findings[i] = f
		}
		return ScoreEnclave(&model.Enclave{Confidentiality: model.ImpactModerate}, assets, findings, now)
	}
	small, large := build(3), build(20)
	if diff := small.Index - large.Index; diff > 0.5 || diff < -0.5 {
		t.Errorf("indexes should be comparable across sizes: %v vs %v", small.Index, large.Index)
	}
}

func TestAgeProfileBuckets(t *testing.T) {
	fs := []*model.Finding{
		finding(model.SeverityHigh, 5), finding(model.SeverityHigh, 45),
		finding(model.SeverityHigh, 120), finding(model.SeverityHigh, 400),
	}
	closed := finding(model.SeverityHigh, 400)
	closed.Disposition = model.DispositionRemediated
	fs = append(fs, closed)

	got := AgeProfile(fs, now)
	for i, want := range []int{1, 1, 1, 1} {
		if got[i].Count != want {
			t.Errorf("bucket %q = %d, want %d", got[i].Label, got[i].Count, want)
		}
	}
}

// ---------- gap analysis ----------

func gapFixture(t *testing.T) (*catalog.Catalog, *model.Enclave, []*model.Asset) {
	t.Helper()
	cat, err := catalog.ParseText(strings.NewReader(
		"@id test\n@name Test\n@profile core = Core\n@family AC = Access Control\n" +
			"AC-1 | Policy | core\nAC-2 | Account Management | core\nAC-2(1) | Automated | core\nAC-3 | Access Enforcement | core\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := &model.Enclave{ID: "E", Name: "E", Confidentiality: model.ImpactModerate}
	return cat, e, []*model.Asset{{ID: "a", EnclaveID: "E", Criticality: model.CritModerate}}
}

func evidence(control string, status model.FindingStatus) *model.Finding {
	f := finding(model.SeverityHigh, 1)
	f.AssetID = "a"
	f.Status = status
	f.ControlRefs = map[string][]string{"test": {control}}
	return f
}

func TestGapStatesCoverEveryCombination(t *testing.T) {
	cat, e, assets := gapFixture(t)
	findings := []*model.Finding{
		evidence("AC-2", model.StatusOpen),        // claimed, and failing
		evidence("AC-1", model.StatusNotAFinding), // claimed, and passing
		evidence("AC-3", model.StatusOpen),        // not claimed, and failing
	}
	assessments := map[string]*model.Assessment{
		"test|AC-1": {Status: model.ImplImplemented},
		"test|AC-2": {Status: model.ImplImplemented},
		// AC-2(1) is claimed with nothing to check it against.
		"test|AC-2(1)": {Status: model.ImplImplemented},
	}
	an := Analyse(cat, "core", e, assets, findings, assessments, now)

	want := map[string]GapState{
		"AC-1": GapSatisfied, "AC-2": GapContradicted,
		"AC-2(1)": GapClaimed, "AC-3": GapFailing,
	}
	got := map[string]GapState{}
	for _, fam := range an.Families {
		for _, g := range fam.Controls {
			got[g.Control.ID] = g.State
		}
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %q, want %q", id, got[id], w)
		}
	}
	if an.Total != 4 {
		t.Errorf("total = %d", an.Total)
	}
	// Coverage counts claimed and satisfied; verified counts only satisfied.
	if an.Coverage() != 50 {
		t.Errorf("coverage = %v, want 50", an.Coverage())
	}
	if an.Verified() != 25 {
		t.Errorf("verified = %v, want 25", an.Verified())
	}
	if an.OpenCount() != 2 {
		t.Errorf("open gaps = %d, want 2", an.OpenCount())
	}
}

func TestUnassessedAndNotImplementedAreDistinct(t *testing.T) {
	cat, e, assets := gapFixture(t)
	assessments := map[string]*model.Assessment{
		"test|AC-1": {Status: model.ImplNotImplemented},
		"test|AC-2": {Status: model.ImplPlanned},
		"test|AC-3": {Status: model.ImplNotApplicable},
	}
	an := Analyse(cat, "core", e, assets, nil, assessments, now)
	got := map[string]GapState{}
	for _, fam := range an.Families {
		for _, g := range fam.Controls {
			got[g.Control.ID] = g.State
		}
	}
	for id, want := range map[string]GapState{
		"AC-1": GapGap, "AC-2": GapPlanned, "AC-3": GapClaimed, "AC-2(1)": GapUnassessed,
	} {
		if got[id] != want {
			t.Errorf("%s = %q, want %q", id, got[id], want)
		}
	}
}

func TestEvidenceAboutAnEnhancementReachesItsBaseControl(t *testing.T) {
	cat, e, assets := gapFixture(t)
	findings := []*model.Finding{evidence("AC-2(1)", model.StatusOpen)}
	an := Analyse(cat, "core", e, assets, findings, nil, now)
	for _, fam := range an.Families {
		for _, g := range fam.Controls {
			if g.Control.ID == "AC-2" && g.OpenCount != 1 {
				t.Error("a failing enhancement should also show against its base control")
			}
		}
	}
}

func TestUnmappedFindingsAreReportedNotHidden(t *testing.T) {
	cat, e, assets := gapFixture(t)
	orphan := finding(model.SeverityHigh, 1)
	orphan.AssetID = "a"
	an := Analyse(cat, "core", e, assets, []*model.Finding{orphan}, nil, now)
	if an.UnmappedFindings != 1 {
		t.Errorf("unmapped = %d, want 1", an.UnmappedFindings)
	}
	for _, fam := range an.Families {
		for _, g := range fam.Controls {
			if g.Evidence() {
				t.Errorf("an unmapped finding was attributed to %s", g.Control.ID)
			}
		}
	}
}

func TestWorstOrdersContradictedFirst(t *testing.T) {
	cat, e, assets := gapFixture(t)
	findings := []*model.Finding{
		evidence("AC-2", model.StatusOpen),
		evidence("AC-3", model.StatusOpen),
	}
	assessments := map[string]*model.Assessment{"test|AC-2": {Status: model.ImplImplemented}}
	an := Analyse(cat, "core", e, assets, findings, assessments, now)
	worst := an.Worst(5)
	if len(worst) == 0 || worst[0].Control.ID != "AC-2" {
		t.Errorf("a contradicted control should be listed before a merely failing one, got %v", worst)
	}
}

func TestMatrixRowsReadTopDown(t *testing.T) {
	entries := []*model.RiskEntry{
		{Status: "open", Likelihood: 5, Impact: 5},
		{Status: "open", Likelihood: 1, Impact: 1},
		{Status: "completed", Likelihood: 3, Impact: 3},
	}
	rows := MatrixRows(entries)
	if len(rows) != 5 || len(rows[0]) != 5 {
		t.Fatalf("expected a 5 by 5 grid")
	}
	if rows[0][0].Likelihood != 5 {
		t.Error("the first row should be the highest likelihood")
	}
	if rows[0][4].Count != 1 || rows[4][0].Count != 1 {
		t.Error("open entries were not counted into the right squares")
	}
	if rows[2][2].Count != 0 {
		t.Error("a completed entry should not appear on the matrix")
	}
	if rows[0][4].Tier != 4 || rows[4][0].Tier != 1 {
		t.Error("shading tiers are wrong")
	}
}

func TestAnAcceptedRiskIsNeverPastTarget(t *testing.T) {
	old := finding(model.SeverityCritical, 3650)
	if !PastTarget(old, now) {
		t.Fatal("a critical open for ten years is past target")
	}
	old.Disposition = model.DispositionRiskAccepted
	if PastTarget(old, now) {
		t.Error("accepting a risk is the decision about when it gets fixed, so there is no deadline left to miss")
	}
	// It is still an exposure, though, and still carries weight.
	if !old.Live() {
		t.Error("an accepted risk is still live")
	}
	if FindingScore(old, &model.Asset{Criticality: model.CritModerate}, now) == 0 {
		t.Error("an accepted risk should still carry risk, at reduced weight")
	}
}

func TestEnclaveCountsAcceptedApartFromOpen(t *testing.T) {
	assets := []*model.Asset{{ID: "a", Criticality: model.CritModerate}}
	outstanding := finding(model.SeverityHigh, 1)
	outstanding.AssetID = "a"
	accepted := finding(model.SeverityHigh, 1)
	accepted.AssetID = "a"
	accepted.Disposition = model.DispositionRiskAccepted

	got := ScoreEnclave(&model.Enclave{}, assets, []*model.Finding{outstanding, accepted}, now)
	if got.Open != 1 {
		t.Errorf("Open = %d; an accepted risk must not be counted as work outstanding", got.Open)
	}
	if got.Accepted != 1 {
		t.Errorf("Accepted = %d, want 1", got.Accepted)
	}
	// Both still show in the severity mix, because both are still exposures.
	if got.BySev[model.SeverityHigh] != 2 {
		t.Errorf("severity mix = %v; both are still live", got.BySev)
	}
	if got.Overdue != 0 {
		t.Errorf("overdue = %d, want 0", got.Overdue)
	}
}

func TestAcceptedRiskStillContradictsAClaimedControl(t *testing.T) {
	// This is the point of keeping an accepted risk live: you cannot claim a
	// control is met because you decided to live with the thing breaking it.
	cat, e, assets := gapFixture(t)
	f := evidence("AC-2", model.StatusOpen)
	f.Disposition = model.DispositionRiskAccepted
	assessments := map[string]*model.Assessment{"test|AC-2": {Status: model.ImplImplemented}}
	an := Analyse(cat, "core", e, assets, []*model.Finding{f}, assessments, now)
	for _, fam := range an.Families {
		for _, g := range fam.Controls {
			if g.Control.ID == "AC-2" && g.State != GapContradicted {
				t.Errorf("AC-2 = %q; an accepted risk still contradicts a claim that the control is implemented", g.State)
			}
		}
	}
}
