package model

import (
	"testing"
	"time"
)

func TestSeverityNormalisationAcrossScanners(t *testing.T) {
	cases := map[string]Severity{
		"CAT I": SeverityHigh, "cat ii": SeverityMedium, "CAT III": SeverityLow,
		"high": SeverityHigh, "Medium": SeverityMedium, "  LOW  ": SeverityLow,
		"Critical": SeverityCritical, "4": SeverityCritical, "3": SeverityHigh,
		"2": SeverityMedium, "1": SeverityLow, "0": SeverityInfo, "": SeverityInfo,
		"None": SeverityInfo, "moderate": SeverityMedium,
	}
	for in, want := range cases {
		if got := SeverityFromCategory(in); got != want {
			t.Errorf("SeverityFromCategory(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSeverityFromCVSSFollowsFIRSTBands(t *testing.T) {
	cases := map[float64]Severity{
		10: SeverityCritical, 9.0: SeverityCritical, 8.9: SeverityHigh,
		7.0: SeverityHigh, 6.9: SeverityMedium, 4.0: SeverityMedium,
		3.9: SeverityLow, 0.1: SeverityLow, 0: SeverityInfo,
	}
	for score, want := range cases {
		if got := SeverityFromCVSS(score); got != want {
			t.Errorf("SeverityFromCVSS(%v) = %q, want %q", score, got, want)
		}
	}
}

func TestFindingStatusNormalisation(t *testing.T) {
	cases := map[string]FindingStatus{
		"Open": StatusOpen, "fail": StatusOpen, "Failed": StatusOpen,
		"NotAFinding": StatusNotAFinding, "pass": StatusNotAFinding,
		"Not_Applicable": StatusNotApplicable, "notapplicable": StatusNotApplicable,
		"Not_Reviewed": StatusNotReviewed, "": StatusNotReviewed, "unknown": StatusNotReviewed,
	}
	for in, want := range cases {
		if got := FindingStatus(in).Normalise(); got != want {
			t.Errorf("FindingStatus(%q) = %q, want %q", in, got, want)
		}
	}
	if StatusNotAFinding.Counts() {
		t.Error("a passing check must not count as open")
	}
}

func TestCategorizationIsHighWaterMark(t *testing.T) {
	e := &Enclave{Confidentiality: ImpactLow, Integrity: ImpactModerate, Availability: ImpactHigh}
	if got := e.Categorization(); got != ImpactHigh {
		t.Errorf("got %q, want high", got)
	}
	e.Availability = ImpactLow
	if got := e.Categorization(); got != ImpactModerate {
		t.Errorf("got %q, want moderate", got)
	}
}

func TestFindingLiveness(t *testing.T) {
	f := &Finding{Status: StatusOpen, Disposition: DispositionOpen}
	if !f.Live() {
		t.Error("an open finding with no decision is live")
	}
	f.Disposition = DispositionRemediated
	if f.Live() {
		t.Error("a remediated finding is not live")
	}
	f.Disposition = DispositionRiskAccepted
	if !f.Live() {
		t.Error("an accepted risk is still live: it is tracked, not gone")
	}
	f.Status = StatusNotAFinding
	f.Disposition = DispositionOpen
	if f.Live() {
		t.Error("a finding the scanner passes is not live")
	}
}

func TestDispositionResidualOrdering(t *testing.T) {
	if DispositionRemediated.Residual() != 0 {
		t.Error("a remediated finding carries no residual risk")
	}
	if DispositionRiskAccepted.Residual() >= DispositionMitigated.Residual() {
		t.Error("an accepted risk should score below a mitigated one, since it is a deliberate decision")
	}
	if DispositionInProgress.Residual() >= DispositionOpen.Residual() {
		t.Error("work in progress should score below untouched")
	}
}

func TestEnclaveValidationReportsEveryProblem(t *testing.T) {
	e := &Enclave{ID: "!", Networks: []Network{{CIDR: "not-a-range"}, {CIDR: "10.0.0.0/8"}, {CIDR: "10.0.0.0/8"}}}
	err := e.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"name is required", "identifier must be", "not-a-range", "twice"} {
		if !contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestAssetNeedsANameOrAnAddress(t *testing.T) {
	a := &Asset{EnclaveID: "x"}
	if a.Validate() == nil {
		t.Error("an asset with neither a name nor an address should be rejected")
	}
	a.IPs = []string{"10.1.2.3"}
	if err := a.Validate(); err != nil {
		t.Errorf("an asset with an address is valid: %v", err)
	}
	a.IPs = []string{"not an address"}
	if a.Validate() == nil {
		t.Error("a malformed address should be rejected")
	}
}

func TestRiskScoreAndBand(t *testing.T) {
	r := &RiskEntry{Likelihood: 5, Impact: 5}
	if r.Score() != 25 || r.Band() != "Very high" {
		t.Errorf("got %d %q", r.Score(), r.Band())
	}
	r = &RiskEntry{Likelihood: 0, Impact: 9} // out of range on both sides
	if r.Score() != 5 {
		t.Errorf("out-of-range values should clamp to 1 and 5, got %d", r.Score())
	}
}

func TestRiskOverdue(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	r := &RiskEntry{Status: "open", Due: &past}
	if !r.Overdue(time.Now()) {
		t.Error("an open entry past its due date is overdue")
	}
	r.Status = "completed"
	if r.Overdue(time.Now()) {
		t.Error("a completed entry is not overdue")
	}
}

func TestSlugIDKeepsCase(t *testing.T) {
	for in, want := range map[string]string{
		"CORE-OPS": "CORE-OPS", "Core Operations": "Core-Operations",
		"  a//b  ": "a-b", "!!!": "",
	} {
		if got := SlugID(in); got != want {
			t.Errorf("SlugID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDedupPreservesOrder(t *testing.T) {
	got := Dedup([]string{"b", "a", "", "b", " a ", "c"})
	want := []string{"b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (hay == needle ||
		len(needle) == 0 || indexOf(hay, needle) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestAcceptedRiskIsLiveButNotOutstandingWork(t *testing.T) {
	f := &Finding{Status: StatusOpen, Disposition: DispositionRiskAccepted}
	if !f.Live() {
		t.Error("an accepted risk is still an exposure, so it stays live and keeps counting against controls")
	}
	if !f.Accepted() {
		t.Error("Accepted should report the decision")
	}
	if f.NeedsWork() {
		t.Error("an accepted risk is not somebody's outstanding task; that is the point of accepting it")
	}
	if f.State() != "Risk accepted" {
		t.Errorf("State = %q; the recorded decision is what the page should say, not the scanner's word", f.State())
	}
	if !f.Decided() {
		t.Error("Decided should be true once a disposition is recorded")
	}
}

func TestStateResolvesScannerResultAndDecision(t *testing.T) {
	cases := []struct {
		status FindingStatus
		disp   Disposition
		want   string
	}{
		// Nothing decided: the scanner's word stands.
		{StatusOpen, DispositionOpen, "Open"},
		{StatusNotAFinding, DispositionOpen, "Not a finding"},
		{StatusNotApplicable, DispositionOpen, "Not applicable"},
		// A decision has been recorded: it is what the page should say.
		{StatusOpen, DispositionRiskAccepted, "Risk accepted"},
		{StatusOpen, DispositionMitigated, "Mitigated"},
		{StatusOpen, DispositionInProgress, "In progress"},
		// A scanner that has stopped reporting it wins over a stale decision.
		{StatusNotAFinding, DispositionInProgress, "Not a finding"},
	}
	for _, tc := range cases {
		f := &Finding{Status: tc.status, Disposition: tc.disp}
		if got := f.State(); got != tc.want {
			t.Errorf("status %q + disposition %q = %q, want %q", tc.status, tc.disp, got, tc.want)
		}
	}
}

func TestNeedsWorkAcrossDispositions(t *testing.T) {
	for disp, want := range map[Disposition]bool{
		DispositionOpen:          true,
		DispositionInProgress:    true,
		DispositionMitigated:     true,
		DispositionRiskAccepted:  false,
		DispositionRemediated:    false,
		DispositionFalsePositive: false,
	} {
		f := &Finding{Status: StatusOpen, Disposition: disp}
		if got := f.NeedsWork(); got != want {
			t.Errorf("NeedsWork with disposition %q = %v, want %v", disp, got, want)
		}
	}
}
