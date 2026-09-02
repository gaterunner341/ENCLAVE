package store

import (
	"testing"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func seedEnclave(t *testing.T, s *Store, id string, cidrs ...string) *model.Enclave {
	t.Helper()
	e := &model.Enclave{ID: id, Name: id, Confidentiality: model.ImpactModerate}
	for _, c := range cidrs {
		e.Networks = append(e.Networks, model.Network{CIDR: c})
	}
	if err := s.PutEnclave(e); err != nil {
		t.Fatalf("PutEnclave: %v", err)
	}
	return e
}

func TestReopenReadsBackEverything(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedEnclave(t, s, "CORE", "10.0.0.0/8")
	a := &model.Asset{EnclaveID: "CORE", Name: "srv-1", IPs: []string{"10.1.1.1"}}
	if err := s.PutAsset(a); err != nil {
		t.Fatal(err)
	}
	f := &model.Finding{EnclaveID: "CORE", AssetID: a.ID, Title: "x",
		Status: model.StatusOpen, Fingerprint: "fp1"}
	if _, _, err := s.PutFinding(f); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Enclaves()) != 1 || len(again.AllAssets()) != 1 || len(again.Findings("")) != 1 {
		t.Fatalf("reopened store lost records: %d enclaves, %d assets, %d findings",
			len(again.Enclaves()), len(again.AllAssets()), len(again.Findings("")))
	}
	// The fingerprint index has to survive the reload, or a re-import after a
	// restart would duplicate every finding.
	dup := &model.Finding{EnclaveID: "CORE", AssetID: a.ID, Title: "x",
		Status: model.StatusOpen, Fingerprint: "fp1"}
	if _, isNew, _ := again.PutFinding(dup); isNew {
		t.Error("the fingerprint index did not survive a reload")
	}
}

func TestPlaceByAddressPrefersTheLongestPrefix(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "SITE", "10.20.0.0/16")
	seedEnclave(t, s, "MGMT", "10.20.9.0/24")

	for addr, want := range map[string]string{
		"10.20.4.11":  "SITE",
		"10.20.9.2":   "MGMT",
		"10.20.9.255": "MGMT",
	} {
		got, ok := s.PlaceByAddress(addr)
		if !ok || got.ID != want {
			t.Errorf("%s placed in %v, want %s", addr, got, want)
		}
	}
	if _, ok := s.PlaceByAddress("192.0.2.1"); ok {
		t.Error("an address outside every range should not be placed")
	}
	if _, ok := s.PlaceByAddress("not an address"); ok {
		t.Error("a malformed address should not be placed")
	}
}

func TestMatchAssetPrefersSerialThenNameThenAddress(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	bySerial := &model.Asset{EnclaveID: "CORE", Name: "one", Serial: "ABC123", IPs: []string{"10.0.0.1"}}
	byName := &model.Asset{EnclaveID: "CORE", Name: "two", IPs: []string{"10.0.0.2"}}
	for _, a := range []*model.Asset{bySerial, byName} {
		if err := s.PutAsset(a); err != nil {
			t.Fatal(err)
		}
	}
	// A serial wins even when the name points somewhere else.
	if got, ok := s.MatchAsset("CORE", "two", "abc123", nil); !ok || got.ID != bySerial.ID {
		t.Error("serial number should take precedence")
	}
	// A short hostname matches a fully qualified one.
	if got, ok := s.MatchAsset("CORE", "TWO.example.org", "", nil); !ok || got.ID != byName.ID {
		t.Error("hostname matching should ignore case and the domain suffix")
	}
	if got, ok := s.MatchAsset("CORE", "", "", []string{"10.0.0.2"}); !ok || got.ID != byName.ID {
		t.Error("address should match when nothing else does")
	}
	if _, ok := s.MatchAsset("CORE", "three", "", []string{"10.0.0.9"}); ok {
		t.Error("an unknown asset must not match")
	}
	// A placeholder serial must never join two machines together.
	if _, ok := s.MatchAsset("CORE", "nothing", "Unknown", nil); ok {
		t.Error("a placeholder serial matched an asset")
	}
}

func TestRepeatImportKeepsFirstSeenAndDecisions(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	a := &model.Asset{EnclaveID: "CORE", Name: "srv"}
	if err := s.PutAsset(a); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -120).UTC()
	first := &model.Finding{
		EnclaveID: "CORE", AssetID: a.ID, Title: "old", Fingerprint: "fp",
		Status: model.StatusOpen, FirstSeen: old, LastSeen: old,
	}
	stored, _, err := s.PutFinding(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisposition(stored.ID, model.DispositionRiskAccepted,
		"compensating control in place", "D. Rennick", nil); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	again := &model.Finding{
		EnclaveID: "CORE", AssetID: a.ID, Title: "old", Fingerprint: "fp",
		Status: model.StatusOpen, FirstSeen: now, LastSeen: now,
	}
	merged, isNew, err := s.PutFinding(again)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("the same rule against the same asset should merge, not duplicate")
	}
	if !merged.FirstSeen.Equal(old) {
		t.Error("first seen must not move forward, or finding age becomes meaningless")
	}
	if !merged.LastSeen.Equal(now) {
		t.Error("last seen should advance")
	}
	if merged.Disposition != model.DispositionRiskAccepted {
		t.Error("a re-import must not overwrite a human decision")
	}
}

func TestScannerClosingAFindingClosesItUnlessSomebodyDecidedOtherwise(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	a := &model.Asset{EnclaveID: "CORE", Name: "srv"}
	_ = s.PutAsset(a)

	untouched, _, _ := s.PutFinding(&model.Finding{
		EnclaveID: "CORE", AssetID: a.ID, Title: "a", Fingerprint: "fp-a", Status: model.StatusOpen})
	decided, _, _ := s.PutFinding(&model.Finding{
		EnclaveID: "CORE", AssetID: a.ID, Title: "b", Fingerprint: "fp-b", Status: model.StatusOpen})
	_ = s.SetDisposition(decided.ID, model.DispositionRiskAccepted, "accepted", "someone", nil)

	for _, fp := range []string{"fp-a", "fp-b"} {
		_, _, _ = s.PutFinding(&model.Finding{
			EnclaveID: "CORE", AssetID: a.ID, Title: "x", Fingerprint: fp,
			Status: model.StatusNotAFinding})
	}
	got, _ := s.Finding(untouched.ID)
	if got.Disposition != model.DispositionRemediated {
		t.Errorf("an untouched finding the scanner now passes should close, got %q", got.Disposition)
	}
	got, _ = s.Finding(decided.ID)
	if got.Disposition != model.DispositionRiskAccepted {
		t.Error("a recorded decision must survive the scanner changing its mind")
	}
}

func TestDeleteScanRemovesOnlyItsFindings(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	a := &model.Asset{EnclaveID: "CORE", Name: "srv"}
	_ = s.PutAsset(a)
	keep := &model.Scan{EnclaveID: "CORE", Title: "keep"}
	drop := &model.Scan{EnclaveID: "CORE", Title: "drop"}
	_ = s.PutScan(keep)
	_ = s.PutScan(drop)
	_, _, _ = s.PutFinding(&model.Finding{EnclaveID: "CORE", AssetID: a.ID, ScanID: keep.ID, Title: "k", Fingerprint: "k"})
	_, _, _ = s.PutFinding(&model.Finding{EnclaveID: "CORE", AssetID: a.ID, ScanID: drop.ID, Title: "d", Fingerprint: "d"})

	if err := s.DeleteScan(drop.ID); err != nil {
		t.Fatal(err)
	}
	rest := s.Findings("CORE")
	if len(rest) != 1 || rest[0].ScanID != keep.ID {
		t.Fatalf("expected only the kept scan's finding to remain, got %d", len(rest))
	}
	if len(s.AllAssets()) != 1 {
		t.Error("deleting an import should not delete the asset")
	}
}

func TestDeleteEnclaveCascades(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	seedEnclave(t, s, "LAB")
	for _, id := range []string{"CORE", "LAB"} {
		a := &model.Asset{EnclaveID: id, Name: "srv-" + id}
		_ = s.PutAsset(a)
		_, _, _ = s.PutFinding(&model.Finding{EnclaveID: id, AssetID: a.ID, Title: "f", Fingerprint: "fp-" + id})
		_ = s.PutRisk(&model.RiskEntry{EnclaveID: id, Title: "r"})
		_ = s.PutAssessment(&model.Assessment{EnclaveID: id, CatalogID: "c", ControlID: "AC-1"})
	}
	if err := s.DeleteEnclave("CORE"); err != nil {
		t.Fatal(err)
	}
	if len(s.Enclaves()) != 1 || len(s.AllAssets()) != 1 || len(s.Findings("")) != 1 ||
		len(s.Risks("")) != 1 || len(s.Assessments("LAB")) != 1 {
		t.Error("deleting an enclave should take its records with it and leave the others alone")
	}
	if len(s.Assessments("CORE")) != 0 {
		t.Error("assessments for the deleted enclave remain")
	}
}

func TestMovingAnAssetBetweenEnclavesReindexes(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	seedEnclave(t, s, "LAB")
	a := &model.Asset{EnclaveID: "CORE", Name: "srv"}
	_ = s.PutAsset(a)
	a.EnclaveID = "LAB"
	if err := s.PutAsset(a); err != nil {
		t.Fatal(err)
	}
	if len(s.Assets("CORE")) != 0 {
		t.Error("the asset is still listed under its old enclave")
	}
	if len(s.Assets("LAB")) != 1 {
		t.Error("the asset is not listed under its new enclave")
	}
}

func TestCountsSummarisesTheStore(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	a := &model.Asset{EnclaveID: "CORE", Name: "srv"}
	_ = s.PutAsset(a)
	_, _, _ = s.PutFinding(&model.Finding{EnclaveID: "CORE", AssetID: a.ID, Title: "open", Fingerprint: "1", Status: model.StatusOpen})
	_, _, _ = s.PutFinding(&model.Finding{EnclaveID: "CORE", AssetID: a.ID, Title: "closed", Fingerprint: "2", Status: model.StatusNotAFinding})
	c := s.Counts()
	if c.Enclaves != 1 || c.Assets != 1 || c.Findings != 2 || c.OpenFindings != 1 {
		t.Errorf("got %+v", c)
	}
}
