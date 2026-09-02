package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pkittelson/enclave/internal/coverage"
	"github.com/pkittelson/enclave/internal/model"
	"github.com/pkittelson/enclave/internal/resolve"
	"github.com/pkittelson/enclave/internal/store"
)

// harness is a whole application over a throwaway data directory.
type harness struct {
	t      *testing.T
	store  *store.Store
	engine *Engine
	mux    http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(st, resolve.DefaultConfig(), coverage.DefaultControls())
	if err := engine.Rebuild(); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(engine, st)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, store: st, engine: engine, mux: srv.Routes()}
}

func (h *harness) get(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func (h *harness) post(path string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	return w
}

// upload posts a CSV to the first half of the import and returns the rendered
// mapping screen.
func (h *harness) upload(filename, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := part.Write([]byte(body)); err != nil {
		h.t.Fatal(err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/import/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	return w
}

var stageRE = regexp.MustCompile(`name="stage" value="([0-9a-f]+)"`)

func TestEveryPageRendersOnAnEmptyInstall(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/", "/hosts", "/unassigned", "/conflicts", "/import", "/enclaves"} {
		w := h.get(path)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d", path, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), "</html>") {
			t.Errorf("GET %s did not render a complete page", path)
		}
	}
}

func TestImportPlacesHostsAndSurfacesConflicts(t *testing.T) {
	h := newHarness(t)

	if err := h.store.PutEnclave(&model.Enclave{
		ID: "CORP-CORE", Name: "Core Enterprise Services", Owner: "D. Rennick",
		CIDRs: []string{"10.12.0.0/16"}, Impact: "Moderate", Framework: "cis",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.engine.Rebuild(); err != nil {
		t.Fatal(err)
	}

	recent := time.Now().Add(-48 * time.Hour).Format("2006-01-02")
	edr := "Computer Name,IP Address,Operating System,Sensor Status,BitLocker,Last Scan\n" +
		"WKS-014,10.12.1.20,Windows 11 Pro,Normal,Yes," + recent + "\n" +
		"SRV-DB-02,10.12.9.5,Windows Server 2022,Normal,Yes," + recent + "\n" +
		"LAB-77,192.168.5.5,Windows 10 Pro,Unknown,No,\n"

	page := h.upload("falcon-prod.csv", edr)
	if page.Code != http.StatusOK {
		t.Fatalf("upload = %d, body %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	if !strings.Contains(body, "Map columns") {
		t.Fatal("upload did not reach the mapping screen")
	}
	// The mapping arrives pre-filled from the headers.
	if !strings.Contains(body, `<option value="Computer Name" selected>`) {
		t.Error("the host name column was not guessed")
	}

	m := stageRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no staging identifier on the mapping screen")
	}

	commit := url.Values{
		"stage":                {m[1]},
		"source_id":            {"falcon-prod"},
		"source_kind":          {"edr"},
		"col_id:hostname":      {"Computer Name"},
		"col_f:ip":             {"IP Address"},
		"col_f:os":             {"Operating System"},
		"col_f:edr_status":     {"Sensor Status"},
		"col_f:disk_encrypted": {"BitLocker"},
		"col_f:last_vuln_scan": {"Last Scan"},
		"save_as":              {"CrowdStrike monthly export"},
	}
	if w := h.post("/import/commit", commit); w.Code != http.StatusSeeOther {
		t.Fatalf("commit = %d, body %s", w.Code, w.Body.String())
	}

	if got := h.engine.Live(); got != 3 {
		t.Fatalf("live hosts = %d, want 3", got)
	}
	if got := len(h.engine.Unassigned()); got != 1 {
		t.Errorf("unassigned = %d, want 1: only the 192.168 host is outside the range", got)
	}

	// A second feed disagreeing about the operating system.
	cmdb := "Asset Name,Serial,IP,OS,Assigned To\n" +
		"WKS-014,5CG8241LM,10.12.1.20,Windows 10 Pro,D. Rennick\n"
	page = h.upload("servicenow.csv", cmdb)
	m = stageRE.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("no staging identifier on the second mapping screen")
	}
	commit = url.Values{
		"stage":           {m[1]},
		"source_id":       {"servicenow"},
		"source_kind":     {"cmdb"},
		"col_id:hostname": {"Asset Name"},
		"col_id:serial":   {"Serial"},
		"col_f:ip":        {"IP"},
		"col_f:os":        {"OS"},
		"col_f:owner":     {"Assigned To"},
	}
	if w := h.post("/import/commit", commit); w.Code != http.StatusSeeOther {
		t.Fatalf("second commit = %d", w.Code)
	}

	if got := h.engine.Live(); got != 3 {
		t.Errorf("live hosts = %d, want 3: the second feed describes a known machine", got)
	}
	conflicts := h.engine.Conflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1", len(conflicts))
	}
	if got := conflicts[0].Field(model.FieldOS); got != "Windows 11 Pro" {
		t.Errorf("winning OS = %q, want the agent's value", got)
	}

	if page := h.get("/conflicts"); !strings.Contains(page.Body.String(), "Windows 10 Pro") {
		t.Error("the conflicts page does not show the rejected value")
	}
	if page := h.get("/"); !strings.Contains(page.Body.String(), "CORP-CORE") {
		t.Error("the overview does not show the enclave")
	}
	if page := h.get("/import"); !strings.Contains(page.Body.String(), "CrowdStrike monthly export") {
		t.Error("the saved mapping is not listed")
	}
}

func TestAssigningAHostByHandSticks(t *testing.T) {
	h := newHarness(t)
	if err := h.store.PutEnclave(&model.Enclave{ID: "DMZ", CIDRs: []string{"172.16.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	csv := "Computer Name,IP Address\nEDGE-01,192.168.9.9\n"
	page := h.upload("edge.csv", csv)
	m := stageRE.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("no staging identifier")
	}
	h.post("/import/commit", url.Values{
		"stage": {m[1]}, "source_id": {"ipam"}, "source_kind": {"ipam"},
		"col_id:hostname": {"Computer Name"}, "col_f:ip": {"IP Address"},
	})

	hosts := h.engine.Hosts("")
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts", len(hosts))
	}
	if w := h.post("/assign", url.Values{"host": {hosts[0].ID}, "enclave": {"DMZ"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("assign = %d", w.Code)
	}
	if got := h.engine.Host(hosts[0].ID).EnclaveID; got != "DMZ" {
		t.Errorf("enclave after assignment = %q, want DMZ", got)
	}
	if got := len(h.engine.Unassigned()); got != 0 {
		t.Errorf("unassigned = %d, want 0", got)
	}
}

func TestDeletingAnEnclaveThatStillHoldsHostsIsRefused(t *testing.T) {
	h := newHarness(t)
	if err := h.store.PutEnclave(&model.Enclave{ID: "CORP-CORE", CIDRs: []string{"10.12.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	csv := "Computer Name,IP Address\nWKS-014,10.12.1.20\n"
	page := h.upload("f.csv", csv)
	m := stageRE.FindStringSubmatch(page.Body.String())
	h.post("/import/commit", url.Values{
		"stage": {m[1]}, "source_id": {"falcon"}, "source_kind": {"edr"},
		"col_id:hostname": {"Computer Name"}, "col_f:ip": {"IP Address"},
	})

	h.post("/enclaves/delete", url.Values{"id": {"CORP-CORE"}})
	if h.store.Enclave("CORP-CORE") == nil {
		t.Error("an enclave still holding hosts must not be deleted")
	}
}

func TestBadAddressRangeIsRejected(t *testing.T) {
	h := newHarness(t)
	w := h.post("/enclaves/save", url.Values{
		"id": {"CORP-CORE"}, "cidrs": {"10.12.0.0/33"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save = %d", w.Code)
	}
	if h.store.Enclave("CORP-CORE") != nil {
		t.Error("an enclave with an unparseable range must not be saved")
	}
}
