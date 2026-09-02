package backup

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
)

// seed builds a data directory with a little of everything in it.
func seed(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &model.Enclave{ID: "CORE", Name: "Core Operations", Owner: "D. Rennick",
		Confidentiality: model.ImpactModerate}
	if err := s.PutEnclave(e); err != nil {
		t.Fatal(err)
	}
	a := &model.Asset{EnclaveID: "CORE", Name: "APP-SRV-01", Type: model.AssetServer,
		Criticality: model.CritMission, IPs: []string{"10.20.4.11"}}
	if err := s.PutAsset(a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutFinding(&model.Finding{
		EnclaveID: "CORE", AssetID: a.ID, Title: "Guest account enabled",
		Severity: model.SeverityMedium, Status: model.StatusOpen, Fingerprint: "fp1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAssessment(&model.Assessment{
		EnclaveID: "CORE", CatalogID: "nist-800-53r5", ControlID: "AC-2",
		Status: model.ImplImplemented, Narrative: "Accounts are provisioned through the joiner process.",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRisk(&model.RiskEntry{EnclaveID: "CORE", Title: "Legacy authentication",
		Likelihood: 3, Impact: 4, Status: "open"}); err != nil {
		t.Fatal(err)
	}
	// An imported catalogue and mapping, which live in subdirectories and are
	// exactly the sort of thing a naive backup forgets.
	for _, f := range []struct{ path, body string }{
		{"catalogs/acme.catalog", "@id acme\n@name ACME Standard\nHD-1 | Approved base image |\n"},
		{"mappings/local.csv", "#name,Local\n#scheme,cci\n#target,nist-800-53r5\nkey,controls\nCCI-000015,AC-2(1)\n"},
	} {
		full := filepath.Join(dir, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, s
}

func writeBundle(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	man, err := Write(dir, &buf, "test")
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if man.Format != Format || man.Schema != store.SchemaVersion {
		t.Fatalf("manifest is wrong: %+v", man)
	}
	return buf.Bytes()
}

func TestBundleCarriesEverything(t *testing.T) {
	dir, _ := seed(t)
	body := writeBundle(t, dir)

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range zr.File {
		got[f.Name] = true
	}
	for _, want := range []string{
		manifestName,
		"data/enclaves.json", "data/assets.json", "data/findings.json",
		"data/assessments.json", "data/risks.json", "data/schema.json",
		"data/catalogs/acme.catalog", "data/mappings/local.csv",
	} {
		if !got[want] {
			t.Errorf("the bundle is missing %s", want)
		}
	}
	// The manifest is the first entry, so reading it never means scanning the
	// whole archive.
	if zr.File[0].Name != manifestName {
		t.Errorf("the manifest should come first, got %s", zr.File[0].Name)
	}
}

func TestManifestSummarises(t *testing.T) {
	dir, _ := seed(t)
	body := writeBundle(t, dir)
	man, err := Inspect(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if man.Counts["enclaves"] != 1 || man.Counts["assets"] != 1 || man.Counts["findings"] != 1 {
		t.Errorf("counts are wrong: %v", man.Counts)
	}
	if !strings.Contains(man.Describe(), "1 enclaves") {
		t.Errorf("Describe = %q", man.Describe())
	}
	if man.CreatedBy != "test" {
		t.Errorf("created by = %q", man.CreatedBy)
	}
}

func TestRestoreIntoAFreshDirectory(t *testing.T) {
	source, _ := seed(t)
	body := writeBundle(t, source)

	// This is the upgrade: a new build, a new folder, nothing in it.
	fresh := t.TempDir()
	res, err := Restore(fresh, bytes.NewReader(body), int64(len(body)), "test")
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Replaced != "" {
		t.Error("there was nothing to replace, so nothing should have been saved aside")
	}

	s, err := store.Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Counts()
	if c.Enclaves != 1 || c.Assets != 1 || c.Findings != 1 || c.Risks != 1 {
		t.Fatalf("records did not survive the round trip: %+v", c)
	}
	e, ok := s.Enclave("CORE")
	if !ok || e.Owner != "D. Rennick" {
		t.Errorf("enclave detail was lost: %+v", e)
	}
	a := s.Assets("CORE")[0]
	if a.Name != "APP-SRV-01" || a.Criticality != model.CritMission {
		t.Errorf("asset detail was lost: %+v", a)
	}
	if len(s.Assessments("CORE")) != 1 {
		t.Error("assessments were lost, which is the part nobody can recreate from a scan")
	}
	// The imported catalogue and mapping came too.
	for _, p := range []string{"catalogs/acme.catalog", "mappings/local.csv"} {
		if _, err := os.Stat(filepath.Join(fresh, filepath.FromSlash(p))); err != nil {
			t.Errorf("%s did not come across: %v", p, err)
		}
	}
}

func TestRestoreSavesWhatItReplaces(t *testing.T) {
	source, _ := seed(t)
	body := writeBundle(t, source)

	// A directory that already has different data in it.
	target, s := seed(t)
	if err := s.PutEnclave(&model.Enclave{ID: "OTHER", Name: "Somewhere else"}); err != nil {
		t.Fatal(err)
	}
	res, err := Restore(target, bytes.NewReader(body), int64(len(body)), "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced == "" {
		t.Fatal("the data that was replaced should have been saved")
	}
	if _, err := os.Stat(res.Replaced); err != nil {
		t.Fatalf("the saved copy is not there: %v", err)
	}
	// The restore really did replace rather than merge.
	after, err := store.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Enclave("OTHER"); ok {
		t.Error("a restore is a replacement, so the enclave that was not in the bundle should be gone")
	}
	// And what was replaced is recoverable from the copy.
	saved, err := os.ReadFile(res.Replaced)
	if err != nil {
		t.Fatal(err)
	}
	recovered := t.TempDir()
	if _, err := Restore(recovered, bytes.NewReader(saved), int64(len(saved)), "test"); err != nil {
		t.Fatalf("the saved copy did not restore: %v", err)
	}
	back, _ := store.Open(recovered)
	if _, ok := back.Enclave("OTHER"); !ok {
		t.Error("the saved copy did not actually contain what was replaced")
	}
}

func TestBackupsFolderIsNotBackedUp(t *testing.T) {
	dir, _ := seed(t)
	if _, err := SaveCurrent(dir, "test"); err != nil {
		t.Fatal(err)
	}
	if len(List(dir)) != 1 {
		t.Fatalf("expected one saved bundle, got %v", List(dir))
	}
	body := writeBundle(t, dir)
	zr, _ := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	for _, f := range zr.File {
		if strings.Contains(f.Name, BackupsDir+"/") {
			t.Errorf("a bundle contains the backups folder (%s), which nests without limit", f.Name)
		}
	}
}

func TestRefusesWhatIsNotABundle(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, body, wantMsg string
	}{
		{"not a zip", "hello", "not a readable backup"},
	} {
		_, err := Restore(dir, strings.NewReader(tc.body), int64(len(tc.body)), "test")
		if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
			t.Errorf("%s: got %v, want a message containing %q", tc.name, err, tc.wantMsg)
		}
	}

	// A valid zip with no manifest.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("data/enclaves.json")
	_, _ = f.Write([]byte("[]"))
	_ = zw.Close()
	if _, err := Restore(dir, bytes.NewReader(buf.Bytes()), int64(buf.Len()), "test"); err == nil ||
		!strings.Contains(err.Error(), "not produced by ENCLAVE") {
		t.Errorf("a zip with no manifest should be refused, got %v", err)
	}
}

func TestRefusesABundleFromANewerBuild(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(manifestName)
	_, _ = f.Write([]byte(`{"format":"enclave-backup","schema":9999,"created_by":"v99"}`))
	_ = zw.Close()

	dir, _ := seed(t)
	_, err := Restore(dir, bytes.NewReader(buf.Bytes()), int64(buf.Len()), "test")
	if err == nil {
		t.Fatal("a bundle from a newer schema should be refused")
	}
	if !strings.Contains(err.Error(), "upgrade ENCLAVE") {
		t.Errorf("the message should tell somebody what to do about it, got %q", err)
	}
	// Refusing must not have disturbed what was there.
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Counts().Enclaves != 1 {
		t.Error("a refused restore changed the data anyway")
	}
}

func TestRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{
		"data/../../escape.json", "data/../outside.json", "/etc/passwd",
		"data/../../../etc/passwd", "escape.json", "data/.hidden/x.json",
	} {
		if _, ok := safeRelative(name); ok {
			t.Errorf("safeRelative accepted %q", name)
		}
	}
	for _, name := range []string{
		"data/enclaves.json", "data/catalogs/acme.catalog", "data/mappings/local.csv",
	} {
		if _, ok := safeRelative(name); !ok {
			t.Errorf("safeRelative rejected the legitimate path %q", name)
		}
	}
}

func TestACorruptBundleLeavesTheDataAlone(t *testing.T) {
	dir, _ := seed(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	m, _ := zw.Create(manifestName)
	_, _ = m.Write([]byte(`{"format":"enclave-backup","schema":1}`))
	bad, _ := zw.Create("data/enclaves.json")
	_, _ = bad.Write([]byte("{ this is not json"))
	_ = zw.Close()

	if _, err := Restore(dir, bytes.NewReader(buf.Bytes()), int64(buf.Len()), "test"); err == nil {
		t.Fatal("a bundle whose data does not parse should be refused")
	}
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("the original data no longer loads: %v", err)
	}
	if s.Counts().Enclaves != 1 {
		t.Error("a failed restore damaged the data it was supposed to leave alone")
	}
}

func TestEmptyDirectoryHasNothingToBackUp(t *testing.T) {
	if _, err := Write(t.TempDir(), &bytes.Buffer{}, "test"); err == nil {
		t.Error("backing up an empty directory should say there is nothing there")
	}
}

func TestSuggestedFilename(t *testing.T) {
	got := SuggestedFilename(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	if got != "enclave-backup-20260304-050607.zip" {
		t.Errorf("got %q", got)
	}
}

func TestFreshDirectoryIsNotPreservedForNoReason(t *testing.T) {
	source, _ := seed(t)
	body := writeBundle(t, source)

	// A brand new install: the directory exists and has been stamped by the
	// store, but holds no records. Restoring into it should not leave a bundle
	// of nothing behind.
	fresh := t.TempDir()
	if _, err := store.Open(fresh); err != nil {
		t.Fatal(err)
	}
	res, err := Restore(fresh, bytes.NewReader(body), int64(len(body)), "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced != "" {
		t.Errorf("a stamped but empty directory has nothing to preserve, got %q", res.Replaced)
	}
	if got := List(fresh); len(got) != 0 {
		t.Errorf("a needless bundle was written: %v", got)
	}
}

func TestBackingUpAStampedButEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := store.Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, &bytes.Buffer{}, "test"); err == nil {
		t.Error("a directory holding only a version stamp has nothing to back up")
	}
}

func TestSavedBundlesAreNewestFirst(t *testing.T) {
	dir, _ := seed(t)
	for i := 0; i < 2; i++ {
		if _, err := SaveCurrent(dir, "test"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond) // the names carry a whole-second timestamp
	}
	got := List(dir)
	if len(got) != 2 {
		t.Fatalf("expected two bundles, got %v", got)
	}
	if got[0] < got[1] {
		t.Errorf("bundles should be listed newest first, got %v", got)
	}
}
