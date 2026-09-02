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

// newHarness builds a server over a temporary store seeded with one enclave,
// one real STIG checklist and one real Nessus export, so that every page has
// something to render.
func newHarness(t *testing.T) *harness {
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
