package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
)

func fixture(t *testing.T) (*Importer, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cats, err := catalog.NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	maps, err := mapping.NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(st, cats, maps), st
}

func enclave(t *testing.T, st *store.Store, id string, cidrs ...string) {
	t.Helper()
	e := &model.Enclave{
		ID: id, Name: id, Confidentiality: model.ImpactModerate,
		Baselines: []model.BaselineRef{{CatalogID: "nist-800-53r5", ProfileID: "moderate"}},
	}
	for _, c := range cidrs {
		e.Networks = append(e.Networks, model.Network{CIDR: c})
	}
	if err := st.PutEnclave(e); err != nil {
		t.Fatal(err)
	}
}

func parse(t *testing.T, name string) *ingest.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ingest.Parse(b, name, ingest.CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestApplyCreatesAssetsAndMapsControls(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")

	sum, err := im.Apply(parse(t, "sample.ckl"), Options{EnclaveID: "CORE", CreateAssets: true})
	if err != nil {
		t.Fatal(err)
	}
	if sum.AssetsCreated != 1 || sum.FindingsAdded != 3 {
		t.Fatalf("got %+v", sum)
	}
	a := st.Assets("CORE")[0]
	if a.Name != "APP-SRV-01" || a.LastSeen == nil {
		t.Errorf("asset record is incomplete: %+v", a)
	}
	// The CCI on the first rule has to reach a control.
	var mapped int
	for _, f := range st.Findings("CORE") {
		if len(f.Controls("nist-800-53r5")) > 0 {
			mapped++
		}
	}
	if mapped == 0 {
		t.Error("no finding reached a control, so the seed mapping is not being applied")
	}
}

func TestApplyMatchesAnExistingAssetAcrossTools(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	if _, err := im.Apply(parse(t, "sample.ckl"), Options{EnclaveID: "CORE", CreateAssets: true}); err != nil {
		t.Fatal(err)
	}
	sum, err := im.Apply(parse(t, "sample.nessus"), Options{EnclaveID: "CORE", CreateAssets: true})
	if err != nil {
		t.Fatal(err)
	}
	// The checklist called it APP-SRV-01; Nessus reports 10.20.4.11 with a
	// NetBIOS name. They are the same machine.
	if sum.AssetsMatched != 1 {
		t.Errorf("the Nessus host should match the checklist's asset, got %+v", sum)
	}
	if got := len(st.Assets("CORE")); got != 2 {
		t.Errorf("expected the server plus the router, got %d assets", got)
	}
}

func TestApplyRespectsCreateAssetsOff(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	sum, err := im.Apply(parse(t, "sample.ckl"), Options{EnclaveID: "CORE", CreateAssets: false})
	if err != nil {
		t.Fatal(err)
	}
	if sum.AssetsCreated != 0 || sum.FindingsAdded != 0 {
		t.Errorf("nothing should have been written: %+v", sum)
	}
	if len(sum.Warnings) != 1 || !strings.Contains(sum.Warnings[0], "APP-SRV-01") {
		t.Errorf("the skipped host should be named in a warning, got %v", sum.Warnings)
	}
}

func TestPlaceByAddressRoutesToTheMatchingEnclave(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	enclave(t, st, "MGMT", "10.20.9.0/24")

	sum, err := im.Apply(parse(t, "sample.nessus"), Options{
		EnclaveID: "CORE", CreateAssets: true, PlaceByAddress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Placed["MGMT"] != 1 || sum.Placed["CORE"] != 1 {
		t.Errorf("the management VLAN host should land in MGMT: %v", sum.Placed)
	}
	if len(st.Assets("MGMT")) != 1 {
		t.Error("the router was not filed under the management enclave")
	}
	for _, f := range st.Findings("MGMT") {
		if f.EnclaveID != "MGMT" {
			t.Error("a finding was left pointing at the wrong enclave")
		}
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	opts := Options{EnclaveID: "CORE", CreateAssets: true}
	if _, err := im.Apply(parse(t, "sample.ckl"), opts); err != nil {
		t.Fatal(err)
	}
	before := len(st.Findings("CORE"))
	sum, err := im.Apply(parse(t, "sample.ckl"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if sum.FindingsAdded != 0 || sum.FindingsUpdated != before {
		t.Errorf("a repeat import should update, not add: %+v", sum)
	}
	if got := len(st.Findings("CORE")); got != before {
		t.Errorf("finding count changed from %d to %d", before, got)
	}
	if got := len(st.Assets("CORE")); got != 1 {
		t.Errorf("a repeat import created a duplicate asset: %d", got)
	}
}

func TestApplyRefusesWithoutAnEnclave(t *testing.T) {
	im, _ := fixture(t)
	if _, err := im.Apply(parse(t, "sample.ckl"), Options{}); err == nil {
		t.Error("an import with no enclave should be refused")
	}
	if _, err := im.Apply(parse(t, "sample.ckl"), Options{EnclaveID: "nope"}); err == nil {
		t.Error("an import into an unknown enclave should be refused")
	}
}

func TestImportDoesNotOverwriteCuratedAssetDetail(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	curated := &model.Asset{
		EnclaveID: "CORE", Name: "APP-SRV-01", Owner: "Platform team",
		Criticality: model.CritMission, Role: "Payment processing",
		Type: model.AssetServer, Location: "Rack B12",
	}
	if err := st.PutAsset(curated); err != nil {
		t.Fatal(err)
	}
	if _, err := im.Apply(parse(t, "sample.ckl"), Options{EnclaveID: "CORE", CreateAssets: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Asset(curated.ID)
	if got.Owner != "Platform team" || got.Criticality != model.CritMission ||
		got.Role != "Payment processing" || got.Location != "Rack B12" {
		t.Errorf("the import overwrote details a person had set: %+v", got)
	}
	// The scan is authoritative about addresses and when the asset was seen.
	if len(got.IPs) == 0 || got.LastSeen == nil {
		t.Error("the import should still contribute addresses and a last-seen date")
	}
}

func TestReannotateAfterLoadingAMapping(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	if _, err := im.Apply(parse(t, "sample-xccdf.xml"), Options{EnclaveID: "CORE", CreateAssets: true}); err != nil {
		t.Fatal(err)
	}
	// CCI-000381 is in the seed table; remove the seed's reach by targeting a
	// framework nothing maps to yet, then add the table and re-check.
	own, err := catalog.ParseText(strings.NewReader(
		"@id acme\n@name ACME\n@family HD = Hardening\nHD-2 | Unused services removed |\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := im.Catalogs.Add(own, []byte("@id acme\n@name ACME\nHD-2 | Unused services removed |\n"), "acme.catalog"); err != nil {
		t.Fatal(err)
	}
	before := 0
	for _, f := range st.Findings("CORE") {
		before += len(f.Controls("acme"))
	}
	if before != 0 {
		t.Fatal("nothing should map to the new framework yet")
	}
	if err := im.Mappings.Add(&mapping.Set{
		ID: "x", Name: "x", Scheme: mapping.SchemeCCI, Target: "acme",
		Entries: map[string][]string{"CCI-000381": {"HD-2"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := im.Reannotate("CORE"); err != nil {
		t.Fatal(err)
	}
	after := 0
	for _, f := range st.Findings("CORE") {
		after += len(f.Controls("acme"))
	}
	if after == 0 {
		t.Error("loading a mapping should surface evidence without re-importing anything")
	}
	// Re-annotation must not disturb finding history or decisions.
	for _, f := range st.Findings("CORE") {
		if f.FirstSeen.IsZero() || f.Disposition == "" {
			t.Errorf("re-annotation damaged a finding: %+v", f)
		}
	}
}

func TestScanRecordsWhatItProduced(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	sum, err := im.Apply(parse(t, "sample.nessus"), Options{
		EnclaveID: "CORE", CreateAssets: true, ImportedBy: "P. Kittelson",
		Notes: "weekly credentialed scan",
	})
	if err != nil {
		t.Fatal(err)
	}
	sc, ok := st.Scan(sum.ScanID)
	if !ok {
		t.Fatal("the scan was not recorded")
	}
	if sc.ImportedBy != "P. Kittelson" || sc.Notes != "weekly credentialed scan" {
		t.Errorf("provenance was lost: %+v", sc)
	}
	if len(sc.AssetIDs) != 2 {
		t.Errorf("the scan should list both hosts, got %v", sc.AssetIDs)
	}
	if sc.Counts["open"] == 0 {
		t.Error("the scan should record how many results were open")
	}
	if sc.ImportedAt.IsZero() || time.Since(sc.ImportedAt) > time.Minute {
		t.Error("the import timestamp is wrong")
	}
	// Deleting the import undoes it completely.
	if err := st.DeleteScan(sc.ID); err != nil {
		t.Fatal(err)
	}
	if len(st.Findings("CORE")) != 0 {
		t.Error("deleting an import should remove the findings it produced")
	}
}

func TestPinningAnImportToOneAsset(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	// The inventory knows this machine by a name the checklist does not use,
	// which is the case that makes matching fail and duplicates appear.
	curated := &model.Asset{
		EnclaveID: "CORE", Name: "PAY-APP-PROD-01", Owner: "Platform team",
		Criticality: model.CritMission, Role: "Payment processing",
		Type: model.AssetServer,
	}
	if err := st.PutAsset(curated); err != nil {
		t.Fatal(err)
	}

	sum, err := im.Apply(parse(t, "sample.ckl"), Options{
		EnclaveID: "CORE", CreateAssets: true, AssetID: curated.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sum.AssetsCreated != 0 || sum.AssetsMatched != 1 {
		t.Fatalf("pinning should attach to the existing asset, not create one: %+v", sum)
	}
	if sum.Attached != "PAY-APP-PROD-01" {
		t.Errorf("the summary should name what it attached to, got %q", sum.Attached)
	}
	if got := len(st.Assets("CORE")); got != 1 {
		t.Fatalf("a second asset was created despite pinning: %d", got)
	}
	got, _ := st.Asset(curated.ID)
	if got.Name != "PAY-APP-PROD-01" {
		t.Errorf("the checklist renamed the asset to %q", got.Name)
	}
	if got.Owner != "Platform team" || got.Criticality != model.CritMission {
		t.Errorf("curated detail was lost: %+v", got)
	}
	// The scan still contributes what it legitimately knows.
	if got.OS == "" || got.LastSeen == nil {
		t.Error("the import should still fill in the platform and last-seen date")
	}
	for _, f := range st.Findings("CORE") {
		if f.AssetID != curated.ID {
			t.Error("a finding was filed against something other than the pinned asset")
		}
	}
}

func TestPinningOverridesPlacementByAddress(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	enclave(t, st, "MGMT", "10.20.9.0/24")
	target := &model.Asset{EnclaveID: "MGMT", Name: "core-switch-01", Type: model.AssetNetwork}
	if err := st.PutAsset(target); err != nil {
		t.Fatal(err)
	}
	// sample.nessus describes two hosts, one of which would be placed in CORE.
	sum, err := im.Apply(parse(t, "sample.nessus"), Options{
		EnclaveID: "CORE", CreateAssets: true, PlaceByAddress: true, AssetID: target.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Assets("CORE")) != 0 {
		t.Error("pinning should stop placement by address scattering results")
	}
	if len(st.Findings("MGMT")) == 0 {
		t.Error("nothing reached the pinned asset")
	}
	// A file describing several targets pinned to one asset is worth saying out
	// loud rather than doing quietly.
	if len(sum.Warnings) == 0 {
		t.Error("pinning a multi-target file to one asset should warn")
	}
}

func TestPinningToAnUnknownAssetIsRefused(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	if _, err := im.Apply(parse(t, "sample.ckl"), Options{
		EnclaveID: "CORE", CreateAssets: true, AssetID: "no-such-asset",
	}); err == nil {
		t.Error("pinning to an asset that does not exist should be refused")
	}
}

func TestPinnedReimportUpdatesRatherThanDuplicating(t *testing.T) {
	im, st := fixture(t)
	enclave(t, st, "CORE", "10.20.0.0/16")
	a := &model.Asset{EnclaveID: "CORE", Name: "PAY-APP-PROD-01", Type: model.AssetServer}
	if err := st.PutAsset(a); err != nil {
		t.Fatal(err)
	}
	opts := Options{EnclaveID: "CORE", CreateAssets: true, AssetID: a.ID}
	if _, err := im.Apply(parse(t, "sample.ckl"), opts); err != nil {
		t.Fatal(err)
	}
	before := len(st.Findings("CORE"))
	sum, err := im.Apply(parse(t, "sample.ckl"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if sum.FindingsAdded != 0 || sum.FindingsUpdated != before {
		t.Errorf("a second pinned import should update: %+v", sum)
	}
}
