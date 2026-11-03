package store

import (
	"os"
	"path/filepath"
	"strings"
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

func TestUnplacedFindsAssetsNoPageWouldShow(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE", "10.20.0.0/16")
	seedEnclave(t, s, "MGMT", "10.20.9.0/24")

	fine := &model.Asset{EnclaveID: "CORE", Name: "in-range", IPs: []string{"10.20.4.1"}}
	// A nested range is not a misfiling: 10.20.9.x is inside MGMT's /24 and
	// also inside CORE's /16, and either enclave is a defensible home.
	nested := &model.Asset{EnclaveID: "CORE", Name: "nested", IPs: []string{"10.20.9.5"}}
	noAddress := &model.Asset{EnclaveID: "CORE", Name: "no-address"}
	// Genuinely outside every range CORE claims. An address inside a nested,
	// more specific enclave would still be inside CORE's own range, and being
	// in a range your enclave claims is not a misfiling.
	outside := &model.Asset{EnclaveID: "CORE", Name: "elsewhere", IPs: []string{"10.44.1.5"}}
	stray := &model.Asset{EnclaveID: "GONE", Name: "dangling", IPs: []string{"10.20.4.2"}}
	for _, a := range []*model.Asset{fine, nested, noAddress, outside, stray} {
		if err := s.PutAsset(a); err != nil {
			t.Fatal(err)
		}
	}
	// An asset with no enclave at all, which the form will not create but
	// restored or hand-edited data can contain.
	nowhere := &model.Asset{ID: "loose", Name: "nowhere", IPs: []string{"192.0.2.9"}}
	s.assets[nowhere.ID] = nowhere

	got := map[string]Placement{}
	for _, p := range s.UnplacedAssets() {
		got[p.Asset.Name] = p
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 problems, got %d: %v", len(got), keysOf(got))
	}
	if _, ok := got["in-range"]; ok {
		t.Error("an asset inside its enclave's range is not a problem")
	}
	if _, ok := got["nested"]; ok {
		t.Error("an asset in a nested range is inside its enclave's range, so it is not misfiled")
	}
	if _, ok := got["no-address"]; ok {
		t.Error("an asset with no address cannot be checked, so it is not reported as misplaced")
	}
	if got["dangling"].Problem != MissingEnclave {
		t.Errorf("dangling = %q", got["dangling"].Problem)
	}
	if got["nowhere"].Problem != NoEnclave {
		t.Errorf("nowhere = %q", got["nowhere"].Problem)
	}
	if got["elsewhere"].Problem != OutsideRanges {
		t.Errorf("elsewhere = %q", got["elsewhere"].Problem)
	}
	// The suggestion is the enclave whose range actually contains it.
	if got["elsewhere"].Suggested != nil {
		t.Error("no enclave claims that address, so nothing should be suggested")
	}
	if s := got["dangling"].Suggested; s == nil || s.ID != "CORE" {
		t.Errorf("dangling should be suggested for CORE, got %v", s)
	}
	if got["nowhere"].Suggested != nil {
		t.Error("an address in nobody's range should suggest nothing")
	}
	// Orphans are the ones no page would show, and they sort first.
	if s.OrphanCount() != 2 {
		t.Errorf("orphan count = %d, want 2", s.OrphanCount())
	}
	list := s.UnplacedAssets()
	if !list[0].Problem.Orphaned() || !list[1].Problem.Orphaned() {
		t.Error("assets nobody can see should be listed first")
	}
}

func TestEnclaveWithNoRangesPlacesNothingAndBlamesNobody(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE")
	a := &model.Asset{EnclaveID: "CORE", Name: "srv", IPs: []string{"10.1.1.1"}}
	if err := s.PutAsset(a); err != nil {
		t.Fatal(err)
	}
	if got := s.UnplacedAssets(); len(got) != 0 {
		t.Errorf("an enclave that declares no ranges cannot misplace anything, got %v", got)
	}
}

func TestMoveAssetsTakesFindingsAlong(t *testing.T) {
	s := open(t)
	seedEnclave(t, s, "CORE", "10.20.0.0/16")
	seedEnclave(t, s, "MGMT", "10.20.9.0/24")
	a := &model.Asset{EnclaveID: "CORE", Name: "switch", IPs: []string{"10.20.9.2"}}
	if err := s.PutAsset(a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutFinding(&model.Finding{
		EnclaveID: "CORE", AssetID: a.ID, Title: "f", Fingerprint: "fp", Status: model.StatusOpen,
	}); err != nil {
		t.Fatal(err)
	}

	moved, err := s.MoveAssets([]string{a.ID}, "MGMT")
	if err != nil || moved != 1 {
		t.Fatalf("moved %d: %v", moved, err)
	}
	if len(s.Assets("CORE")) != 0 || len(s.Assets("MGMT")) != 1 {
		t.Error("the asset did not change enclave")
	}
	if len(s.Findings("CORE")) != 0 || len(s.Findings("MGMT")) != 1 {
		t.Error("the findings were left counting towards the enclave the asset left")
	}
	// And it is no longer reported as misplaced.
	if got := s.UnplacedAssets(); len(got) != 0 {
		t.Errorf("still reported after being moved: %v", got)
	}
	if _, err := s.MoveAssets([]string{a.ID}, "NOPE"); err == nil {
		t.Error("moving into an enclave that does not exist should be refused")
	}
}

func keysOf(m map[string]Placement) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A data directory the process cannot write to is the single most common way
// a containerised deployment fails: the directory on the host is owned by
// somebody else, the container exits, and with a restart policy it does that
// on a loop. What it must not do is fail later with the name of whichever
// temporary file happened to be written first, which says nothing about the
// ownership that actually needs fixing.
func TestUnwritableDataDirectoryIsExplained(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write anywhere, so there is nothing to refuse")
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir)
	if err == nil {
		t.Fatal("opening a directory that cannot be written should fail")
	}
	msg := err.Error()
	for _, want := range []string{
		dir,            // which directory
		"not writable", // what is wrong
		"chown",        // what to do about it
		"user:",        // and the other way to resolve it
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error should mention %q, got:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, ".json.tmp") {
		t.Error("the error should not name a temporary file; that is what made it unhelpful")
	}
}
