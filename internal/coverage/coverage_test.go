package coverage

import (
	"testing"
	"time"

	"github.com/pkittelson/enclave/internal/model"
)

func host(ip string, fields map[string]string) *model.Host {
	h := &model.Host{ID: ip, Fields: map[string]model.FieldValue{}}
	h.Fields[model.FieldIP] = model.FieldValue{Value: ip}
	for k, v := range fields {
		h.Fields[k] = model.FieldValue{Value: v}
	}
	return h
}

func TestAssignPrefersTheLongestPrefix(t *testing.T) {
	enclaves := []*model.Enclave{
		{ID: "CORP-CORE", CIDRs: []string{"10.12.0.0/16"}},
		{ID: "CORP-LAB", CIDRs: []string{"10.12.40.0/24"}},
	}
	hosts := []*model.Host{host("10.12.40.9", nil), host("10.12.1.4", nil), host("192.168.1.5", nil)}
	Assign(hosts, enclaves, nil)

	want := []string{"CORP-LAB", "CORP-CORE", ""}
	for i, h := range hosts {
		if h.EnclaveID != want[i] {
			t.Errorf("%s placed in %q, want %q", h.ID, h.EnclaveID, want[i])
		}
	}
}

func TestAssignHonoursAManualDecision(t *testing.T) {
	enclaves := []*model.Enclave{{ID: "CORP-CORE", CIDRs: []string{"10.12.0.0/16"}}}
	h := host("10.12.1.4", nil)
	Assign([]*model.Host{h}, enclaves, map[string]string{h.ID: "DMZ"})
	if h.EnclaveID != "DMZ" {
		t.Errorf("manual decision ignored: got %q", h.EnclaveID)
	}
}

func TestMeasureCountsOnlyEligibleHosts(t *testing.T) {
	recent := time.Now().Add(-24 * time.Hour).Format("2006-01-02")
	hosts := []*model.Host{
		host("10.0.0.1", map[string]string{
			model.FieldEDRStatus:     "normal",
			model.FieldDiskEncrypted: "yes",
			model.FieldLastVulnScan:  recent,
		}),
		host("10.0.0.2", map[string]string{
			model.FieldOS:           "Cisco IOS XE",
			model.FieldDeviceRole:   "network switch",
			model.FieldLastVulnScan: recent,
		}),
	}
	results := Measure(hosts, DefaultControls())

	byID := map[string]Result{}
	for _, r := range results {
		byID[r.Control.ID] = r
	}
	if got := byID["edr"].Eligible; got != 1 {
		t.Errorf("EDR eligible = %d, want 1: the switch is not an endpoint", got)
	}
	if got := byID["edr"].Percent; got != 100 {
		t.Errorf("EDR percent = %d, want 100", got)
	}
	if got := byID["vuln_scan"].Eligible; got != 2 {
		t.Errorf("vuln scan eligible = %d, want 2: everything gets scanned", got)
	}
	if got := byID["benchmark"].Missing; got != 2 {
		t.Errorf("benchmark missing = %d, want 2", got)
	}
}

func TestAffectedCountsHostsNotFindings(t *testing.T) {
	hosts := []*model.Host{
		host("10.0.0.1", nil), // fails several controls, counts once
	}
	if got := Affected(hosts, DefaultControls()); got != 1 {
		t.Errorf("Affected = %d, want 1", got)
	}
}
