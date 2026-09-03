package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gaterunner341/enclave/internal/backup"
	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/importer"
	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
)

type harness struct {
	*Server
	t *testing.T
}

// newHarnessEmpty builds a server with nothing in it, which is what a freshly
// installed build looks like.
func newHarnessEmpty(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cats, err := catalog.NewRegistry(filepath.Join(st.Dir(), "catalogs"))
	if err != nil {
		t.Fatal(err)
	}
	maps, err := mapping.NewRegistry(filepath.Join(st.Dir(), "mappings"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cats, maps, "test")
	if err != nil {
		t.Fatal(err)
	}
	return &harness{Server: srv, t: t}
}

// newHarness builds a server over a temporary store seeded with one enclave,
// one real STIG checklist and one real Nessus export, so that every page has
// something to render.
func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Catalogues and mappings sit inside the data directory, as they do in a
	// real install, so that a backup taken in a test carries them.
	cats, err := catalog.NewRegistry(filepath.Join(st.Dir(), "catalogs"))
	if err != nil {
		t.Fatal(err)
	}
	maps, err := mapping.NewRegistry(filepath.Join(st.Dir(), "mappings"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, cats, maps, "test")
	if err != nil {
		t.Fatal(err)
	}
	e := &model.Enclave{
		ID: "CORE", Name: "Core Operations", Owner: "D. Rennick",
		Environment: "Production", Status: "Active",
		Confidentiality: model.ImpactModerate, Integrity: model.ImpactModerate,
		Availability: model.ImpactHigh,
		Networks:     []model.Network{{CIDR: "10.20.0.0/16", Label: "Core"}, {CIDR: "10.20.9.0/24", Label: "Management"}},
		Baselines: []model.BaselineRef{
			{CatalogID: "nist-800-53r5", ProfileID: "moderate"},
			{CatalogID: "cis-controls-v8", ProfileID: "ig2"},
		},
	}
	if err := st.PutEnclave(e); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnclave(&model.Enclave{ID: "LAB", Name: "Lab"}); err != nil {
		t.Fatal(err)
	}
	im := importer.New(st, cats, maps)
	for _, name := range []string{"sample.ckl", "sample.nessus", "sample-xccdf.xml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ingest.Parse(b, name, ingest.CSVOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := im.Apply(res, importer.Options{EnclaveID: "CORE", CreateAssets: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutRisk(&model.RiskEntry{
		EnclaveID: "CORE", Title: "Administrative account separation not enforced",
		Likelihood: 4, Impact: 4, Status: "open", Owner: "Windows engineering",
	}); err != nil {
		t.Fatal(err)
	}
	return &harness{Server: srv, t: t}
}

func (h *harness) get(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	return rec
}

func (h *harness) post(path string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	return rec
}

func (h *harness) upload(path, field, filename string, body []byte, fields map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	part, err := w.CreateFormFile(field, filename)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := part.Write(body); err != nil {
		h.t.Fatal(err)
	}
	_ = w.Close()
	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	return rec
}

// firstIDs pulls real identifiers out of the seeded store so the tests do not
// hard-code any.
func (h *harness) firstIDs() (assetID, findingID, scanID string) {
	assetID = h.Store.AllAssets()[0].ID
	findingID = h.Store.Findings("CORE")[0].ID
	scanID = h.Store.Scans("CORE")[0].ID
	return
}

func TestEveryPageRenders(t *testing.T) {
	h := newHarness(t)
	a, f, s := h.firstIDs()
	paths := []string{
		"/", "/enclaves", "/enclaves/CORE", "/enclaves/CORE/assets",
		"/enclaves/CORE/findings", "/enclaves/CORE/baseline",
		"/enclaves/CORE/baseline?catalog=cis-controls-v8",
		"/enclaves/CORE/baseline?state=failing", "/enclaves/CORE/baseline?family=AC",
		"/enclaves/CORE/baseline/nist-800-53r5/AC-6(10)",
		"/enclaves/CORE/baseline/cis-controls-v8/5.4",
		"/enclaves/CORE/risk", "/enclaves/CORE/risk/new", "/enclaves/CORE/scans",
		"/enclaves/CORE/edit", "/enclaves/CORE/assets/new",
		"/enclaves/LAB/baseline", "/enclaves/LAB/assets",
		"/enclaves/new",
		"/assets/" + a, "/assets/" + a + "/edit",
		"/findings/" + f, "/scans/" + s,
		"/catalogs", "/catalogs/nist-800-53r5", "/catalogs/nist-800-53r5?profile=low",
		"/catalogs/cis-controls-v8", "/catalogs/nist-csf-2.0",
		"/mappings", "/mappings/seed-cci-800-53r5",
		"/reports", "/reports?catalog=cis-controls-v8", "/import", "/healthz",
	}
	for _, p := range paths {
		rec := h.get(p)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d\n%s", p, rec.Code, truncateBody(rec.Body.String()))
			continue
		}
		// A template that fails mid-render still returns 200 with the error in
		// the body, so the body has to be checked too.
		if strings.Contains(rec.Body.String(), "could not be rendered") {
			t.Errorf("GET %s rendered an error: %s", p, truncateBody(rec.Body.String()))
		}
	}
}

func truncateBody(s string) string {
	if len(s) > 400 {
		return s[:400]
	}
	return s
}

func TestUnknownPathsAreNotFound(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/nope", "/enclaves/NOPE", "/assets/nope", "/findings/nope",
		"/scans/nope", "/catalogs/nope", "/mappings/nope",
		"/enclaves/CORE/baseline/nist-800-53r5/ZZ-9"} {
		if code := h.get(p).Code; code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
}

func TestCreateAndEditAnEnclave(t *testing.T) {
	h := newHarness(t)
	rec := h.post("/enclaves/new", url.Values{
		"name": {"New Site"}, "id": {"SITE-A"}, "owner": {"S. Ortiz"},
		"confidentiality": {"low"}, "integrity": {"moderate"}, "availability": {"high"},
		"networks":    {"10.30.0.0/16 Site A\n10.31.0.0/16 Overflow"},
		"environment": {"Production"}, "status": {"Active"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	e, ok := h.Store.Enclave("SITE-A")
	if !ok {
		t.Fatal("the enclave was not created under the identifier that was typed")
	}
	if len(e.Networks) != 2 || e.Networks[0].Label != "Site A" {
		t.Errorf("networks were not parsed: %+v", e.Networks)
	}
	if e.Categorization() != model.ImpactHigh {
		t.Errorf("categorisation = %q", e.Categorization())
	}

	// A bad range comes back on the form rather than being saved.
	rec = h.post("/enclaves/SITE-A/edit", url.Values{
		"name": {"New Site"}, "networks": {"not-a-range"},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not-a-range") {
		t.Errorf("a bad range should be reported on the form, got %d", rec.Code)
	}
}

func TestDeletingAnEnclaveNeedsItsNameTyped(t *testing.T) {
	h := newHarness(t)
	if rec := h.post("/enclaves/CORE/delete", url.Values{"confirm": {"wrong"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d", rec.Code)
	}
	if _, ok := h.Store.Enclave("CORE"); !ok {
		t.Fatal("the enclave was deleted without the name being typed correctly")
	}
	if rec := h.post("/enclaves/CORE/delete", url.Values{"confirm": {"Core Operations"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d", rec.Code)
	}
	if _, ok := h.Store.Enclave("CORE"); ok {
		t.Fatal("the enclave was not deleted")
	}
	if len(h.Store.AllAssets()) != 0 || len(h.Store.Findings("")) != 0 {
		t.Error("deleting an enclave should take its records with it")
	}
}

func TestAssessmentDrivesTheGapState(t *testing.T) {
	h := newHarness(t)
	// AC-6(10) has a failing STIG rule against it in the fixture.
	rec := h.post("/enclaves/CORE/baseline/nist-800-53r5/AC-6(10)", url.Values{
		"status": {"implemented"}, "assessed_by": {"P. Kittelson"},
		"narrative":   {"Separate accounts are issued through the privileged access process."},
		"responsible": {"Windows engineering"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d: %s", rec.Code, rec.Body.String())
	}
	a, ok := h.Store.Assessment("CORE", "nist-800-53r5", "AC-6(10)")
	if !ok || a.Status != model.ImplImplemented || a.AssessedAt == nil {
		t.Fatalf("assessment not stored properly: %+v", a)
	}
	body := h.get("/enclaves/CORE/baseline/nist-800-53r5/AC-6(10)").Body.String()
	if !strings.Contains(body, "Contradicted by scans") {
		t.Error("a control claimed implemented with failing scans should read as contradicted")
	}
	if !strings.Contains(h.get("/enclaves/CORE/baseline").Body.String(), "Contradicted by scans") {
		t.Error("the gap page should surface the contradiction")
	}
}

func TestDispositionNeedsANameAndAReason(t *testing.T) {
	h := newHarness(t)
	_, f, _ := h.firstIDs()
	rec := h.post("/findings/"+f+"/disposition", url.Values{"disposition": {"risk_accepted"}})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("accepting a risk with no reason should be refused, redirected to %q", loc)
	}
	got, _ := h.Store.Finding(f)
	if got.Disposition == model.DispositionRiskAccepted {
		t.Error("the disposition was recorded despite being refused")
	}

	rec = h.post("/findings/"+f+"/disposition", url.Values{
		"disposition": {"risk_accepted"}, "by": {"D. Rennick"},
		"note": {"Compensating control in place until the next image."},
	})
	if strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("a complete decision should be accepted: %s", rec.Header().Get("Location"))
	}
	got, _ = h.Store.Finding(f)
	if got.Disposition != model.DispositionRiskAccepted || got.DispositionBy != "D. Rennick" {
		t.Errorf("decision not recorded: %+v", got)
	}
	// In-progress and remediated need no justification, because they claim
	// nothing about accepting risk.
	rec = h.post("/findings/"+f+"/disposition", url.Values{"disposition": {"in_progress"}})
	if strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("marking work in progress should not require a justification")
	}
}

func TestBaselineAssignmentPairsCatalogAndProfile(t *testing.T) {
	h := newHarness(t)
	if rec := h.post("/enclaves/LAB/baselines", url.Values{"baseline": {"cis-controls-v8|ig1"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d", rec.Code)
	}
	e, _ := h.Store.Enclave("LAB")
	if len(e.Baselines) != 1 || e.Baselines[0].ProfileID != "ig1" {
		t.Fatalf("baseline not assigned: %+v", e.Baselines)
	}
	// A profile that belongs to another catalogue is refused.
	rec := h.post("/enclaves/LAB/baselines", url.Values{"baseline": {"nist-800-53r5|ig1"}})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a profile the catalogue does not define should be refused")
	}
	// Removal.
	if rec := h.post("/enclaves/LAB/baselines", url.Values{
		"action": {"remove"}, "catalog_id": {"cis-controls-v8"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d", rec.Code)
	}
	e, _ = h.Store.Enclave("LAB")
	if len(e.Baselines) != 0 {
		t.Error("the baseline was not removed")
	}
}

func TestCSVUploadStopsAtTheMappingScreen(t *testing.T) {
	h := newHarness(t)
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample-vulns.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rec := h.upload("/import", "file", "sample-vulns.csv", body, map[string]string{
		"enclave_id": "CORE", "create_assets": "on",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, truncateBody(rec.Body.String()))
	}
	page := rec.Body.String()
	if !strings.Contains(page, "Map the columns") {
		t.Fatal("a spreadsheet should stop at the mapping screen")
	}
	// Nothing may have been written yet.
	if n := len(h.Store.Findings("CORE")); n != countSeeded(h) {
		t.Errorf("the mapping screen wrote findings before being confirmed: %d", n)
	}
	for _, want := range []string{"Vulnerability Title", "Asset IP Address", "First Discovered"} {
		if !strings.Contains(page, want) {
			t.Errorf("the preview does not mention the column %q", want)
		}
	}
}

func countSeeded(h *harness) int { return len(h.Store.Findings("CORE")) }

func TestStructuredUploadAppliesImmediately(t *testing.T) {
	h := newHarness(t)
	before := len(h.Store.Findings("CORE"))
	body := []byte(`{"title":"Second server","target_data":{"host_name":"APP-SRV-02","ip_address":"10.20.4.12"},
	 "stigs":[{"display_name":"RHEL 9 STIG","stig_id":"RHEL_9","rules":[
	 {"group_id":"V-1","rule_id":"SV-1","rule_title":"Something","severity":"high","status":"open","ccis":["CCI-000366"]}]}]}`)
	rec := h.upload("/import", "file", "second.cklb", body, map[string]string{
		"enclave_id": "CORE", "create_assets": "on", "imported_by": "P. Kittelson",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Import complete") {
		t.Fatalf("got %d: %s", rec.Code, truncateBody(rec.Body.String()))
	}
	if len(h.Store.Findings("CORE")) != before+1 {
		t.Error("the checklist was not applied")
	}
}

func TestUnreadableUploadIsReportedNotSwallowed(t *testing.T) {
	h := newHarness(t)
	rec := h.upload("/import", "file", "junk.ckl", []byte("<CHECKLIST>this is not"), map[string]string{
		"enclave_id": "CORE", "create_assets": "on",
	})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("a broken file should report an error, redirected to %q", loc)
	}
}

func TestCatalogAndMappingImport(t *testing.T) {
	h := newHarness(t)
	cat := []byte("@id acme\n@name ACME Standard\n@family HD = Hardening\nHD-1 | Approved base image |\nHD-2 | Unused services removed |\n")
	if rec := h.upload("/catalogs/import", "file", "acme.catalog", cat, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("catalog import = %d: %s", rec.Code, truncateBody(rec.Body.String()))
	}
	if _, ok := h.Catalogs.Get("acme"); !ok {
		t.Fatal("the catalogue was not loaded")
	}

	xwalk := []byte("#name,To ACME\n#id,acme-xwalk\n#scheme,control\n#target,acme\nkey,controls\nCM-7,HD-2\nCM-6,HD-1\n")
	if rec := h.upload("/mappings/import", "file", "acme-xwalk.csv", xwalk, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("mapping import = %d", rec.Code)
	}
	// Assign the framework and confirm the crosswalk carried evidence across.
	if rec := h.post("/enclaves/CORE/baselines", url.Values{"baseline": {"acme|"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("assign = %d", rec.Code)
	}
	body := h.get("/enclaves/CORE/baseline?catalog=acme").Body.String()
	if strings.Contains(body, "could not be rendered") {
		t.Fatalf("gap page failed: %s", truncateBody(body))
	}
	reached := false
	for _, f := range h.Store.Findings("CORE") {
		if len(f.Controls("acme")) > 0 {
			reached = true
		}
	}
	if !reached {
		t.Error("the crosswalk did not carry any finding into the organisation's own framework")
	}
	// A built-in catalogue cannot be deleted.
	if rec := h.post("/catalogs/nist-800-53r5/delete", nil); !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a built-in catalogue should not be removable")
	}
}

func TestReadOnlyBlocksEveryWrite(t *testing.T) {
	h := newHarness(t)
	h.ReadOnly = true
	for _, p := range []string{
		"/enclaves/new", "/enclaves/CORE/edit", "/enclaves/CORE/delete",
		"/enclaves/CORE/baselines", "/enclaves/CORE/assets/new",
		"/import", "/import/confirm", "/catalogs/import", "/mappings/import",
		"/mappings/reannotate", "/enclaves/CORE/risk/new",
	} {
		if code := h.post(p, url.Values{"name": {"x"}}).Code; code != http.StatusForbidden {
			t.Errorf("POST %s = %d in read-only mode, want 403", p, code)
		}
	}
	// Reading still works.
	if code := h.get("/enclaves/CORE/baseline").Code; code != http.StatusOK {
		t.Errorf("read-only mode broke a read: %d", code)
	}
}

func TestCSVExports(t *testing.T) {
	h := newHarness(t)
	for _, kind := range []string{"assets", "findings", "baseline", "risks"} {
		rec := h.get("/export/" + kind + "?enclave=CORE")
		if rec.Code != http.StatusOK {
			t.Errorf("export %s = %d", kind, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Errorf("export %s content type = %q", kind, ct)
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
			t.Errorf("export %s is not offered as a download", kind)
		}
		lines := strings.Count(strings.TrimSpace(rec.Body.String()), "\n")
		if lines < 1 {
			t.Errorf("export %s produced only a header", kind)
		}
	}
	if code := h.get("/export/nonsense").Code; code != http.StatusNotFound {
		t.Errorf("an unknown export should be 404, got %d", code)
	}
}

func TestJSONAPI(t *testing.T) {
	h := newHarness(t)
	for _, kind := range []string{"enclaves", "assets", "findings", "risks", "scans", "catalogs", "summary"} {
		rec := h.get("/api/" + kind)
		if rec.Code != http.StatusOK {
			t.Errorf("api %s = %d", kind, rec.Code)
		}
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("api %s content type = %q", kind, rec.Header().Get("Content-Type"))
		}
		if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[") {
			t.Errorf("api %s did not return a list", kind)
		}
	}
	if code := h.get("/api/nonsense").Code; code != http.StatusNotFound {
		t.Errorf("an unknown collection should be 404, got %d", code)
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	h := newHarness(t)
	rec := h.get("/")
	for header, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := rec.Header().Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", header, got, want)
		}
	}
}

func TestFindingFiltersNarrowTheList(t *testing.T) {
	h := newHarness(t)
	all := h.get("/enclaves/CORE/findings").Body.String()
	high := h.get("/enclaves/CORE/findings?severity=critical").Body.String()
	if len(high) >= len(all) {
		t.Error("filtering by severity did not narrow the page")
	}
	if strings.Contains(high, "could not be rendered") {
		t.Fatal(truncateBody(high))
	}
	for _, q := range []string{"?unmapped=1", "?overdue=1", "?show=all", "?show=closed",
		"?q=windows", "?disposition=open", "?control=AC-6(10)&catalog=nist-800-53r5"} {
		rec := h.get("/enclaves/CORE/findings" + q)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "could not be rendered") {
			t.Errorf("findings%s failed: %d", q, rec.Code)
		}
	}
}

func TestUploadCapIsEnforced(t *testing.T) {
	h := newHarness(t)
	h.MaxUpload = 64
	rec := h.upload("/import", "file", "big.ckl", bytes.Repeat([]byte("x"), 4096), map[string]string{
		"enclave_id": "CORE",
	})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("an oversized upload should be refused with a message")
	}
}

func TestImportIsReachableFromTheAssetPages(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]

	// The asset page has to offer an import pinned to that host, or the only
	// way to add compliance for a machine is to guess that the top-level
	// Import page will match it by name.
	page := h.get("/assets/" + a.ID).Body.String()
	want := "/import?enclave=" + a.EnclaveID + "&amp;asset=" + a.ID
	if !strings.Contains(page, want) {
		t.Errorf("the asset page does not link to a pinned import (%s)", want)
	}
	if !strings.Contains(page, "Import results for this host") {
		t.Error("the asset page does not say it can import results for the host")
	}

	list := h.get("/enclaves/" + a.EnclaveID + "/assets").Body.String()
	if !strings.Contains(list, "/import?enclave="+a.EnclaveID) {
		t.Error("the assets list does not offer an import")
	}
	if !strings.Contains(list, want) {
		t.Error("the assets list does not offer a per-row pinned import")
	}
}

func TestImportFormOffersAndPreselectsTheAsset(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]

	plain := h.get("/import").Body.String()
	if !strings.Contains(plain, `name="asset_id"`) {
		t.Fatal("the import form has no way to attach results to a known host")
	}
	if !strings.Contains(plain, "STIG checklist") {
		t.Error("the import form never mentions STIG checklists, so nobody will know it reads them")
	}
	if !strings.Contains(plain, a.DisplayName()) {
		t.Error("the asset picker does not list the inventory")
	}

	// Arriving from an asset page preselects that host and its enclave.
	pinned := h.get("/import?enclave=" + a.EnclaveID + "&asset=" + a.ID).Body.String()
	if !strings.Contains(pinned, `value="`+a.ID+`" selected`) {
		t.Error("the asset picker did not preselect the host the link came from")
	}
	if !strings.Contains(pinned, `value="`+a.EnclaveID+`" selected`) {
		t.Error("the enclave was not preselected from the asset")
	}
}

func TestUploadingAChecklistPinnedToAHost(t *testing.T) {
	h := newHarness(t)
	// A host the inventory knows by a name no checklist will carry.
	curated := &model.Asset{
		EnclaveID: "CORE", Name: "PAY-APP-PROD-01", Type: model.AssetServer,
		Criticality: model.CritMission, Owner: "Platform team",
	}
	if err := h.Store.PutAsset(curated); err != nil {
		t.Fatal(err)
	}
	before := len(h.Store.Assets("CORE"))

	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample.ckl"))
	if err != nil {
		t.Fatal(err)
	}
	rec := h.upload("/import", "file", "sample.ckl", body, map[string]string{
		"enclave_id": "CORE", "asset_id": curated.ID, "create_assets": "on",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Import complete") {
		t.Fatalf("got %d: %s", rec.Code, truncateBody(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "attached to PAY-APP-PROD-01") {
		t.Error("the summary should say which host the results were attached to")
	}
	if got := len(h.Store.Assets("CORE")); got != before {
		t.Errorf("pinning still created a host: %d, was %d", got, before)
	}
	got, _ := h.Store.Asset(curated.ID)
	if got.Name != "PAY-APP-PROD-01" || got.Criticality != model.CritMission {
		t.Errorf("the checklist overwrote the inventory record: %+v", got)
	}
	if len(h.Store.AssetFindings(curated.ID)) == 0 {
		t.Error("no findings were attached to the pinned host")
	}
	// The compliance now shows on that host's page.
	page := h.get("/assets/" + curated.ID).Body.String()
	if !strings.Contains(page, "administrative privileges") {
		t.Error("the host page does not show the checklist results")
	}
}

func TestPinnedCSVImportCarriesTheAssetThroughTheMappingScreen(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample-vulns.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rec := h.upload("/import", "file", "sample-vulns.csv", body, map[string]string{
		"enclave_id": "CORE", "asset_id": a.ID, "create_assets": "on",
	})
	if !strings.Contains(rec.Body.String(), `name="asset_id" value="`+a.ID+`"`) {
		t.Error("the mapping screen dropped the pinned host, so confirming would scatter the rows")
	}
}

func TestDataPageExplainsTheUpgradePath(t *testing.T) {
	h := newHarness(t)
	rec := h.get("/data")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "could not be rendered") {
		t.Fatal(truncateBody(body))
	}
	for _, want := range []string{
		"Download a backup", "Restore from a backup", h.Store.Dir(),
		"Upgrading to a new version",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the data page never mentions %q", want)
		}
	}
	// It is linked from somewhere a person will find it.
	if !strings.Contains(h.get("/").Body.String(), `href="/data"`) {
		t.Error("nothing links to the data page")
	}
}

func TestBackupDownloadsAndRestores(t *testing.T) {
	h := newHarness(t)
	before := h.Store.Counts()

	rec := h.get("/data/backup")
	if rec.Code != http.StatusOK {
		t.Fatalf("backup = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("content type = %q", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "enclave-backup-") {
		t.Errorf("content disposition = %q", cd)
	}
	bundle := rec.Body.Bytes()
	if len(bundle) == 0 {
		t.Fatal("the backup is empty")
	}

	// This is the upgrade: a different install, nothing in it, restore the file.
	fresh := newHarnessEmpty(t)
	if fresh.Store.Counts().Enclaves != 0 {
		t.Fatal("the second instance should start empty")
	}
	rec = fresh.upload("/data/restore", "file", "enclave-backup.zip", bundle,
		map[string]string{"confirm": "REPLACE"})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("restore = %d: %s", rec.Code, truncateBody(rec.Body.String()))
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
		t.Fatalf("restore reported an error: %s", loc)
	}

	after := fresh.Store.Counts()
	if after.Enclaves != before.Enclaves || after.Assets != before.Assets ||
		after.Findings != before.Findings {
		t.Fatalf("records did not come across: got %+v, want %+v", after, before)
	}
	// The restore took effect in the running server without a restart.
	if body := fresh.get("/enclaves").Body.String(); !strings.Contains(body, "Core Operations") {
		t.Error("the pages are still serving what was there before the restore")
	}
	// And the gap analysis works against the restored data, which needs the
	// catalogues and mappings to have come back too.
	if body := fresh.get("/enclaves/CORE/baseline").Body.String(); strings.Contains(body, "could not be rendered") {
		t.Fatalf("the baseline page failed after a restore: %s", truncateBody(body))
	}
}

func TestRestoreNeedsConfirmationAndAValidFile(t *testing.T) {
	h := newHarness(t)
	bundle := h.get("/data/backup").Body.Bytes()
	before := h.Store.Counts()

	// No confirmation.
	rec := h.upload("/data/restore", "file", "b.zip", bundle, nil)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a restore without confirmation should be refused")
	}
	// Wrong word.
	rec = h.upload("/data/restore", "file", "b.zip", bundle, map[string]string{"confirm": "yes"})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a restore confirmed with the wrong word should be refused")
	}
	// Not a bundle.
	rec = h.upload("/data/restore", "file", "b.zip", []byte("not a zip"),
		map[string]string{"confirm": "REPLACE"})
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "err=") || !strings.Contains(loc, "Nothing+was+changed") {
		t.Errorf("a bad file should be refused and say nothing changed, got %q", loc)
	}
	if h.Store.Counts() != before {
		t.Error("a refused restore changed the data")
	}
}

func TestSnapshotAndSavedBundleDownload(t *testing.T) {
	h := newHarness(t)
	if rec := h.post("/data/snapshot", nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("snapshot = %d", rec.Code)
	}
	page := h.get("/data").Body.String()
	if !strings.Contains(page, "before-restore-") && !strings.Contains(page, ".zip") {
		t.Error("the saved copy is not listed on the data page")
	}
	names := backup.List(h.Store.Dir())
	if len(names) != 1 {
		t.Fatalf("expected one saved bundle, got %v", names)
	}
	rec := h.get("/data/backups/" + names[0])
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/zip" {
		t.Errorf("downloading a saved bundle = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	// A name that tries to escape the backups folder is refused.
	for _, bad := range []string{"..%2f..%2fetc%2fpasswd", "not-a-zip.txt"} {
		if code := h.get("/data/backups/" + bad).Code; code == http.StatusOK {
			t.Errorf("serving %q should not have worked", bad)
		}
	}
}

func TestReadOnlyAllowsBackupButNotRestore(t *testing.T) {
	h := newHarness(t)
	bundle := h.get("/data/backup").Body.Bytes()
	h.ReadOnly = true

	// Taking a copy changes nothing, so it stays available.
	if code := h.get("/data/backup").Code; code != http.StatusOK {
		t.Errorf("read-only mode blocked taking a backup: %d", code)
	}
	if code := h.get("/data").Code; code != http.StatusOK {
		t.Errorf("read-only mode blocked the data page: %d", code)
	}
	// Replacing everything does not.
	rec := h.upload("/data/restore", "file", "b.zip", bundle, map[string]string{"confirm": "REPLACE"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("restore in read-only mode = %d, want 403", rec.Code)
	}
	if code := h.post("/data/snapshot", nil).Code; code != http.StatusForbidden {
		t.Errorf("snapshot in read-only mode = %d, want 403", code)
	}
}

func TestRestoreCarriesImportedCatalogsAndMappings(t *testing.T) {
	h := newHarness(t)
	// Load an organisation's own framework and a crosswalk into it, which are
	// exactly the things that are not recoverable from a scan.
	cat := []byte("@id acme\n@name ACME Standard\n@family HD = Hardening\nHD-1 | Approved base image |\n")
	if rec := h.upload("/catalogs/import", "file", "acme.catalog", cat, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("catalog import = %d", rec.Code)
	}
	xwalk := []byte("#name,To ACME\n#id,acme-xwalk\n#scheme,control\n#target,acme\nkey,controls\nCM-6,HD-1\n")
	if rec := h.upload("/mappings/import", "file", "acme-xwalk.csv", xwalk, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("mapping import = %d", rec.Code)
	}

	bundle := h.get("/data/backup").Body.Bytes()
	fresh := newHarnessEmpty(t)
	rec := fresh.upload("/data/restore", "file", "b.zip", bundle, map[string]string{"confirm": "REPLACE"})
	if strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("restore failed: %s", rec.Header().Get("Location"))
	}

	if _, ok := fresh.Catalogs.Get("acme"); !ok {
		t.Error("the imported catalogue did not survive the move to a new install")
	}
	if _, ok := fresh.Mappings.Get("acme-xwalk"); !ok {
		t.Error("the imported mapping did not survive the move to a new install")
	}
	// And they are live, not merely on disk.
	if body := fresh.get("/catalogs").Body.String(); !strings.Contains(body, "ACME Standard") {
		t.Error("the restored catalogue is not being served")
	}
}

func TestVulnerabilitiesAreReachableAndListed(t *testing.T) {
	h := newHarness(t)
	if !strings.Contains(h.get("/").Body.String(), `href="/vulnerabilities"`) {
		t.Error("nothing links to the vulnerabilities view")
	}
	rec := h.get("/vulnerabilities")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "could not be rendered") {
		t.Fatal(truncateBody(body))
	}
	// The fixture imports a Nessus export carrying two CVEs.
	for _, cve := range []string{"CVE-2025-21001", "CVE-2023-20198"} {
		if !strings.Contains(body, cve) {
			t.Errorf("the CVE list does not show %s", cve)
		}
	}
	for _, q := range []string{"?severity=critical", "?show=all", "?show=overdue", "?show=closed",
		"?q=CVE-2023", "?enclave=CORE"} {
		r := h.get("/vulnerabilities" + q)
		if r.Code != http.StatusOK || strings.Contains(r.Body.String(), "could not be rendered") {
			t.Errorf("vulnerabilities%s failed: %d", q, r.Code)
		}
	}
}

func TestVulnerabilityDetailShowsEveryHost(t *testing.T) {
	h := newHarness(t)
	rec := h.get("/vulnerabilities/CVE-2023-20198")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, truncateBody(rec.Body.String()))
	}
	body := rec.Body.String()
	if strings.Contains(body, "could not be rendered") {
		t.Fatal(truncateBody(body))
	}
	if !strings.Contains(body, "10.20.9.2") {
		t.Error("the CVE page does not name the host it was found on")
	}
	// An unpatched CVE is evidence about flaw remediation, so it should reach
	// the baseline rather than being only a patch.
	if !strings.Contains(body, "SI-2") && !strings.Contains(body, "RA-5") {
		t.Error("the CVE page shows no controls, so the seed mapping is not reaching it")
	}
	// Lookup is case-insensitive; nonsense is a 404.
	if code := h.get("/vulnerabilities/cve-2023-20198").Code; code != http.StatusOK {
		t.Errorf("lowercase lookup = %d", code)
	}
	for _, bad := range []string{"/vulnerabilities/nonsense", "/vulnerabilities/CVE-2099-0001"} {
		if code := h.get(bad).Code; code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", bad, code)
		}
	}
}

func TestRecordACVEByHand(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]

	// It is offered from the host page, which is where somebody would look.
	page := h.get("/assets/" + a.ID).Body.String()
	if !strings.Contains(page, "/assets/"+a.ID+"/findings/new") {
		t.Error("the host page does not offer recording a finding")
	}
	if h.get("/assets/"+a.ID+"/findings/new").Code != http.StatusOK {
		t.Fatal("the form does not render")
	}

	before := len(h.Store.AssetFindings(a.ID))
	rec := h.post("/assets/"+a.ID+"/findings/new", url.Values{
		"cves": {"CVE-2024-1086"}, "cvss": {"7.8"},
		"description": {"Local privilege escalation in the netfilter subsystem."},
		"fix":         {"Update the kernel package and reboot."},
		"recorded_by": {"P. Kittelson"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d: %s", rec.Code, truncateBody(rec.Body.String()))
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
		t.Fatalf("save reported an error: %s", loc)
	}
	after := h.Store.AssetFindings(a.ID)
	if len(after) != before+1 {
		t.Fatalf("finding count went from %d to %d", before, len(after))
	}

	var got *model.Finding
	for _, f := range after {
		for _, c := range f.CVEs {
			if c == "CVE-2024-1086" {
				got = f
			}
		}
	}
	if got == nil {
		t.Fatal("the recorded CVE is not on the host")
	}
	// A CVSS score sets the severity without anybody choosing one.
	if got.Severity != model.SeverityHigh {
		t.Errorf("CVSS 7.8 should be high, got %q", got.Severity)
	}
	// The title falls back to the identifier, which is a complete thought.
	if got.Title != "CVE-2024-1086" {
		t.Errorf("title = %q", got.Title)
	}
	// It reaches the same controls an imported one would.
	if len(got.Controls("nist-800-53r5")) == 0 {
		t.Error("a hand-entered CVE reached no control, so it is invisible to the gap analysis")
	}
	// And it shows up in the CVE view alongside the imported ones.
	if !strings.Contains(h.get("/vulnerabilities").Body.String(), "CVE-2024-1086") {
		t.Error("the recorded CVE is missing from the vulnerabilities list")
	}
	// It is traceable to an import, like everything else.
	sc, ok := h.Store.Scan(got.ScanID)
	if !ok || sc.Format != "manual" {
		t.Errorf("the finding is not filed under a traceable import: %+v", sc)
	}
}

func TestRecordingTheSameCVETwiceUpdates(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]
	form := url.Values{"cves": {"CVE-2024-1086"}, "cvss": {"7.8"}}
	if rec := h.post("/assets/"+a.ID+"/findings/new", form); rec.Code != http.StatusSeeOther {
		t.Fatal(rec.Code)
	}
	before := len(h.Store.AssetFindings(a.ID))
	if rec := h.post("/assets/"+a.ID+"/findings/new", form); rec.Code != http.StatusSeeOther {
		t.Fatal(rec.Code)
	}
	if got := len(h.Store.AssetFindings(a.ID)); got != before {
		t.Errorf("recording the same CVE twice duplicated it: %d then %d", before, got)
	}
	// Only one scan record is created for hand entry, not one per finding.
	manual := 0
	for _, sc := range h.Store.Scans("CORE") {
		if sc.Format == "manual" {
			manual++
		}
	}
	if manual != 1 {
		t.Errorf("expected one hand-entry import record, got %d", manual)
	}
}

func TestRecordedFindingValidation(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]
	for _, tc := range []struct {
		name string
		form url.Values
		want string
	}{
		{"nothing at all", url.Values{}, "title"},
		{"a CVE that is not one", url.Values{"cves": {"CVE-24-1"}}, "Not+a+CVE"},
		{"CCI mistaken for a CVE", url.Values{"cves": {"CCI-000366"}}, "Not+a+CVE"},
		{"CVSS out of range", url.Values{"cves": {"CVE-2024-1086"}, "cvss": {"14"}}, "between+0+and+10"},
		{"CVSS that is not a number", url.Values{"cves": {"CVE-2024-1086"}, "cvss": {"high"}}, "between+0+and+10"},
	} {
		rec := h.post("/assets/"+a.ID+"/findings/new", tc.form)
		loc := rec.Header().Get("Location")
		if !strings.Contains(loc, "err=") || !strings.Contains(loc, tc.want) {
			t.Errorf("%s: redirected to %q, expected an error mentioning %q", tc.name, loc, tc.want)
		}
	}
}

func TestRecordAFindingFromTheEnclaveWithAChosenHost(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]
	if code := h.get("/enclaves/CORE/findings/new").Code; code != http.StatusOK {
		t.Fatalf("the enclave-level form = %d", code)
	}
	rec := h.post("/enclaves/CORE/findings/new", url.Values{
		"asset_id": {a.ID}, "title": {"Unsupported operating system in production"},
		"severity": {"high"},
	})
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("save = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// Choosing no host is refused rather than filed somewhere arbitrary.
	rec = h.post("/enclaves/CORE/findings/new", url.Values{"title": {"x"}})
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Error("a finding with no host should be refused")
	}
}

func TestVulnerabilityExportAndAPI(t *testing.T) {
	h := newHarness(t)
	rec := h.get("/export/vulnerabilities")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "CVE-2023-20198") || !strings.Contains(body, "Affected hosts") {
		t.Errorf("the CVE export is missing content:\n%s", truncateBody(body))
	}
	rec = h.get("/api/vulnerabilities")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "CVE-2023-20198") {
		t.Errorf("api = %d", rec.Code)
	}
}

func TestRecordingIsBlockedInReadOnlyMode(t *testing.T) {
	h := newHarness(t)
	a := h.Store.AllAssets()[0]
	h.ReadOnly = true
	for _, p := range []string{
		"/assets/" + a.ID + "/findings/new", "/enclaves/CORE/findings/new",
	} {
		if code := h.post(p, url.Values{"cves": {"CVE-2024-1086"}}).Code; code != http.StatusForbidden {
			t.Errorf("POST %s = %d in read-only mode, want 403", p, code)
		}
	}
	// Reading the CVE views still works.
	if code := h.get("/vulnerabilities").Code; code != http.StatusOK {
		t.Errorf("read-only mode broke the vulnerabilities list: %d", code)
	}
}
