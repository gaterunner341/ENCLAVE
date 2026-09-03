package risk

import (
	"testing"

	"github.com/gaterunner341/enclave/internal/model"
)

func vuln(asset, cve string, sev model.Severity, cvss float64, ageDays int) *model.Finding {
	f := finding(sev, ageDays)
	f.AssetID = asset
	f.EnclaveID = "CORE"
	f.CVEs = []string{cve}
	f.CVSS = cvss
	f.Title = cve + " in something"
	return f
}

func TestNormaliseCVE(t *testing.T) {
	for in, want := range map[string]string{
		"CVE-2024-1086":    "CVE-2024-1086",
		"cve-2024-1086":    "CVE-2024-1086",
		"  CVE-2024-1086 ": "CVE-2024-1086",
		"(CVE-2024-1086)":  "CVE-2024-1086",
		"CVE-2023-20198":   "CVE-2023-20198",
		// Not CVEs, and must not become entries of their own.
		"":              "",
		"CVE":           "",
		"CVE-2024":      "",
		"CVE-24-1086":   "",
		"CVE-2024-108":  "",
		"CVE-YYYY-1086": "",
		"CVE-2024-abcd": "",
		"CCI-000366":    "",
		"see also":      "",
	} {
		if got := NormaliseCVE(in); got != want {
			t.Errorf("NormaliseCVE(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCVEsRollUpAcrossHosts(t *testing.T) {
	assets := map[string]*model.Asset{
		"a": {ID: "a", Criticality: model.CritMission},
		"b": {ID: "b", Criticality: model.CritModerate},
		"c": {ID: "c", Criticality: model.CritLow},
	}
	findings := []*model.Finding{
		vuln("a", "CVE-2024-1086", model.SeverityCritical, 9.8, 200),
		vuln("b", "CVE-2024-1086", model.SeverityHigh, 8.1, 10),
		vuln("c", "CVE-2023-20198", model.SeverityHigh, 10, 5),
	}
	got := CVEs(findings, assets, now)
	if len(got) != 2 {
		t.Fatalf("got %d rollups, want 2", len(got))
	}
	first := got[0]
	if first.CVE != "CVE-2024-1086" {
		t.Errorf("the worst CVE should sort first, got %s", first.CVE)
	}
	if first.Assets() != 2 {
		t.Errorf("hosts = %d, want 2", first.Assets())
	}
	// The rollup takes the worst reading of each measure across hosts.
	if first.Severity != model.SeverityCritical {
		t.Errorf("severity = %q, want critical", first.Severity)
	}
	if first.CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8", first.CVSS)
	}
	if first.Oldest != 200 {
		t.Errorf("oldest = %d, want 200", first.Oldest)
	}
	if first.PastTarget == 0 {
		t.Error("a 200-day-old critical is past target")
	}
	if len(first.Enclaves) != 1 {
		t.Errorf("enclaves = %v", first.Enclaves)
	}
}

func TestOneFindingCountsUnderEveryCVEItNames(t *testing.T) {
	f := vuln("a", "CVE-2024-0001", model.SeverityHigh, 7.5, 1)
	f.CVEs = []string{"CVE-2024-0001", "CVE-2024-0002", "not-a-cve"}
	got := CVEs([]*model.Finding{f}, nil, now)
	if len(got) != 2 {
		t.Fatalf("got %d rollups, want 2 (the third is not a CVE)", len(got))
	}
	for _, c := range got {
		if c.Assets() != 1 || c.Open != 1 {
			t.Errorf("%s: hosts=%d open=%d", c.CVE, c.Assets(), c.Open)
		}
	}
}

func TestClosedAndAcceptedAreCountedSeparately(t *testing.T) {
	open := vuln("a", "CVE-2024-1086", model.SeverityHigh, 8, 1)
	accepted := vuln("b", "CVE-2024-1086", model.SeverityHigh, 8, 1)
	accepted.Disposition = model.DispositionRiskAccepted
	fixed := vuln("c", "CVE-2024-1086", model.SeverityHigh, 8, 1)
	fixed.Disposition = model.DispositionRemediated

	got := CVEs([]*model.Finding{open, accepted, fixed}, nil, now)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	c := got[0]
	if c.Open != 2 {
		t.Errorf("open = %d; an accepted risk is still open, it is a decision not a fix", c.Open)
	}
	if c.Accepted != 1 {
		t.Errorf("accepted = %d", c.Accepted)
	}
	if c.Closed != 1 {
		t.Errorf("closed = %d", c.Closed)
	}
	if c.Assets() != 3 {
		t.Errorf("hosts = %d, want 3", c.Assets())
	}
}

func TestAFullyFixedCVEIsNotLive(t *testing.T) {
	f := vuln("a", "CVE-2024-1086", model.SeverityHigh, 8, 1)
	f.Disposition = model.DispositionRemediated
	got := CVEs([]*model.Finding{f}, nil, now)
	if got[0].Live() {
		t.Error("a CVE with nothing open is not live")
	}
	if s := Summarise(got); s.Open != 0 || s.Total != 1 {
		t.Errorf("summary = %+v", s)
	}
}

func TestFindCVE(t *testing.T) {
	findings := []*model.Finding{vuln("a", "CVE-2024-1086", model.SeverityHigh, 8, 1)}
	if _, ok := FindCVE(findings, nil, "cve-2024-1086", now); !ok {
		t.Error("lookup should ignore case")
	}
	if _, ok := FindCVE(findings, nil, "CVE-2024-9999", now); ok {
		t.Error("a CVE that is not recorded should not be found")
	}
}

func TestSummariseCountsSeverityAndHosts(t *testing.T) {
	findings := []*model.Finding{
		vuln("a", "CVE-2024-0001", model.SeverityCritical, 9.8, 400),
		vuln("b", "CVE-2024-0002", model.SeverityHigh, 8.1, 1),
		vuln("a", "CVE-2024-0003", model.SeverityLow, 2.0, 1),
	}
	s := Summarise(CVEs(findings, nil, now))
	if s.Total != 3 || s.Open != 3 {
		t.Errorf("total/open = %d/%d", s.Total, s.Open)
	}
	if s.Critical != 1 || s.High != 1 {
		t.Errorf("critical/high = %d/%d", s.Critical, s.High)
	}
	if s.Assets != 2 {
		t.Errorf("distinct hosts = %d, want 2", s.Assets)
	}
	if s.PastTarget != 1 {
		t.Errorf("past target = %d, want 1", s.PastTarget)
	}
}

func TestRollupRiskUsesAssetCriticality(t *testing.T) {
	onMission := CVEs([]*model.Finding{vuln("a", "CVE-2024-1086", model.SeverityHigh, 8, 1)},
		map[string]*model.Asset{"a": {ID: "a", Criticality: model.CritMission}}, now)
	onLab := CVEs([]*model.Finding{vuln("a", "CVE-2024-1086", model.SeverityHigh, 8, 1)},
		map[string]*model.Asset{"a": {ID: "a", Criticality: model.CritLow}}, now)
	if onMission[0].Score <= onLab[0].Score {
		t.Errorf("the same CVE should score higher on a mission-critical host: %v vs %v",
			onMission[0].Score, onLab[0].Score)
	}
}
