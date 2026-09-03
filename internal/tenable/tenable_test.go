package tenable

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/importer"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
)

// fakeSC stands in for a Security Center. Every test runs against it, because
// pointing tests at a real console would make them untrustworthy and slow.
type fakeSC struct {
	*httptest.Server
	requests  []*http.Request
	headers   []http.Header
	nessus    []byte
	bareXML   bool
	failWith  string
	errorCode int
}

func newFakeSC(t *testing.T) *fakeSC {
	t.Helper()
	f := &fakeSC{nessus: []byte(`<?xml version="1.0"?><NessusClientData_v2>
<Report name="Weekly credentialed">
  <ReportHost name="10.20.4.11">
    <HostProperties>
      <tag name="host-ip">10.20.4.11</tag>
      <tag name="netbios-name">APP-SRV-01</tag>
      <tag name="operating-system">Microsoft Windows Server 2022</tag>
    </HostProperties>
    <ReportItem port="0" svc_name="general" protocol="tcp" severity="4" pluginID="200001"
                pluginName="Missing critical update" pluginFamily="Windows">
      <description>The host is missing a security update.</description>
      <solution>Apply the vendor update.</solution>
      <risk_factor>Critical</risk_factor>
      <cve>CVE-2025-21001</cve>
      <cvss3_base_score>9.8</cvss3_base_score>
    </ReportItem>
  </ReportHost>
</Report></NessusClientData_v2>`)}

	mux := http.NewServeMux()
	record := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.requests = append(f.requests, r)
			f.headers = append(f.headers, r.Header.Clone())
			if f.failWith != "" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error_code": f.errorCode, "error_msg": f.failWith, "response": nil,
				})
				return
			}
			h(w, r)
		}
	}
	reply := func(w http.ResponseWriter, payload any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "regular", "error_code": 0, "error_msg": "", "response": payload,
		})
	}

	mux.HandleFunc("/rest/token", record(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "TNS_SESSIONID", Value: "session-abc"})
		reply(w, map[string]any{"token": 12345})
	}))
	mux.HandleFunc("/rest/system", record(func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"version": "6.4.0", "buildID": "1"})
	}))
	mux.HandleFunc("/rest/scanResult", record(func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{
			"usable": []map[string]any{
				{"id": "101", "name": "Weekly credentialed", "status": "Completed",
					"finishTime": "1756800000", "startTime": "1756790000", "scannedIPs": "42",
					"repository": map[string]any{"name": "Production"},
					"owner":      map[string]any{"username": "scanner"}},
				{"id": "102", "name": "Still running", "status": "Running",
					"finishTime": "0", "startTime": "1756880000", "scannedIPs": "0",
					"repository": map[string]any{"name": "Production"},
					"owner":      map[string]any{"username": "scanner"}},
			},
			"manageable": []map[string]any{
				{"id": "103", "name": "Lab sweep", "status": "Completed",
					"finishTime": "1756700000", "startTime": "1756690000", "scannedIPs": "9",
					"repository": map[string]any{"name": "Lab"},
					"owner":      map[string]any{"username": "scanner"}},
				// The same result appearing in both lists must not be counted twice.
				{"id": "101", "name": "Weekly credentialed", "status": "Completed",
					"finishTime": "1756800000", "repository": map[string]any{"name": "Production"}},
			},
		})
	}))
	mux.HandleFunc("/rest/scanResult/", record(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/download") {
			http.NotFound(w, r)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["downloadType"] != "v2" {
			http.Error(w, "unexpected download type "+body["downloadType"], http.StatusBadRequest)
			return
		}
		if f.bareXML {
			_, _ = w.Write(f.nessus)
			return
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		fh, _ := zw.Create("scan-result.nessus")
		_, _ = fh.Write(f.nessus)
		_ = zw.Close()
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(buf.Bytes())
	}))

	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

// config points at the fake, trusting its throwaway certificate the way an
// operator would trust an appliance certificate they had accepted.
func (f *fakeSC) config() *Connector {
	return &Connector{
		ID: "fake-sc", Name: "Fake Security Center", Kind: KindSecurityCenter,
		Enabled: true, URL: f.URL, EnclaveID: "CORE",
		CreateAssets: true, InsecureSkipVerify: true,
	}
}

func keyClient(t *testing.T, f *fakeSC) *Client {
	t.Helper()
	c, err := New(f.config(), Credentials{AccessKey: "AK", SecretKey: "SK"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAPIKeysAreSentInTheDocumentedHeader(t *testing.T) {
	f := newFakeSC(t)
	c := keyClient(t, f)
	if _, err := c.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.headers) == 0 {
		t.Fatal("no request reached the server")
	}
	got := f.headers[0].Get("X-APIKey")
	if got != "accessKey=AK; secretKey=SK" {
		t.Errorf("X-APIKey = %q, want the documented accessKey/secretKey form", got)
	}
	// With keys there is no login round trip to make.
	for _, r := range f.requests {
		if strings.HasSuffix(r.URL.Path, "/token") {
			t.Error("API key authentication should not call the token endpoint")
		}
	}
}

func TestPasswordLoginUsesTokenAndSession(t *testing.T) {
	f := newFakeSC(t)
	c, err := New(f.config(), Credentials{Username: "svc", Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) < 2 || !strings.HasSuffix(f.requests[0].URL.Path, "/token") {
		t.Fatal("a password login should call the token endpoint first")
	}
	h := f.headers[1]
	if h.Get("X-SecurityCenter") != "12345" {
		t.Errorf("X-SecurityCenter = %q", h.Get("X-SecurityCenter"))
	}
	if !strings.Contains(h.Get("Cookie"), "TNS_SESSIONID=session-abc") {
		t.Errorf("the session cookie was not carried: %q", h.Get("Cookie"))
	}
	// The token is reused rather than logging in for every request.
	before := len(f.requests)
	if _, err := c.ScanResults(context.Background(), time.Time{}); err != nil {
		t.Fatal(err)
	}
	logins := 0
	for _, r := range f.requests[before:] {
		if strings.HasSuffix(r.URL.Path, "/token") {
			logins++
		}
	}
	if logins != 0 {
		t.Errorf("logged in again %d times for a second request", logins)
	}
}

func TestScanResultsAreListedNewestFirstWithoutDuplicates(t *testing.T) {
	f := newFakeSC(t)
	got, err := keyClient(t, f).ScanResults(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3 (the repeated one counted once)", len(got))
	}
	if got[0].ID != "101" {
		t.Errorf("first result = %s, want the most recently finished", got[0].ID)
	}
	if got[0].ScannedIPs != 42 || got[0].Repository != "Production" || got[0].Owner != "scanner" {
		t.Errorf("detail was not read: %+v", got[0])
	}
	if got[0].Finished.IsZero() {
		t.Error("the finish time was not converted from its epoch string")
	}
	// A scan still running has nothing finished to take.
	for _, r := range got {
		if r.ID == "102" && r.Complete() {
			t.Error("a running scan should not be reported as complete")
		}
	}
	// The request asks only for the fields that are used.
	if q := f.requests[0].URL.Query().Get("fields"); !strings.Contains(q, "finishTime") {
		t.Errorf("fields = %q", q)
	}
}

func TestRepositoryFilter(t *testing.T) {
	f := newFakeSC(t)
	cfg := f.config()
	cfg.Repositories = []string{"production"}
	c, err := New(cfg, Credentials{AccessKey: "AK", SecretKey: "SK"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ScanResults(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if !strings.EqualFold(r.Repository, "Production") {
			t.Errorf("%s came from %q, which the filter excludes", r.ID, r.Repository)
		}
	}
	if len(got) == 0 {
		t.Error("the filter excluded everything, including what it should match")
	}
}

func TestDownloadUnwrapsTheArchive(t *testing.T) {
	f := newFakeSC(t)
	body, name, err := keyClient(t, f).Download(context.Background(), "101")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, ".nessus") {
		t.Errorf("filename = %q", name)
	}
	if !bytes.Contains(body, []byte("NessusClientData_v2")) {
		t.Error("what came out of the archive is not a Nessus file")
	}
}

func TestDownloadAcceptsABareNessusFile(t *testing.T) {
	f := newFakeSC(t)
	f.bareXML = true
	body, _, err := keyClient(t, f).Download(context.Background(), "101")
	if err != nil {
		t.Fatalf("some releases answer with the file rather than an archive: %v", err)
	}
	if !bytes.Contains(body, []byte("NessusClientData_v2")) {
		t.Error("the file was not returned")
	}
}

func TestServerErrorsAreReportedNotSwallowed(t *testing.T) {
	f := newFakeSC(t)
	f.failWith = "Unable to authenticate"
	f.errorCode = 74
	_, err := keyClient(t, f).Test(context.Background())
	if err == nil {
		t.Fatal("an error envelope should be an error")
	}
	if !strings.Contains(err.Error(), "Unable to authenticate") || !strings.Contains(err.Error(), "74") {
		t.Errorf("the message loses what the server said: %v", err)
	}
}

func TestUntrustedCertificateSaysWhatToDo(t *testing.T) {
	f := newFakeSC(t)
	cfg := f.config()
	cfg.InsecureSkipVerify = false // the fake's certificate is not in any pool
	c, err := New(cfg, Credentials{AccessKey: "AK", SecretKey: "SK"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Test(context.Background())
	if err == nil {
		t.Fatal("an untrusted certificate should not be accepted silently")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("the message does not mention the certificate: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate authority") {
		t.Errorf("the message does not say what to do about it: %v", err)
	}
}

func TestConfigurationIsRefusedWhenItCannotWork(t *testing.T) {
	base := func() *Connector {
		return &Connector{ID: "sc", Name: "SC", Kind: KindSecurityCenter,
			URL: "https://sc.example.org", EnclaveID: "CORE"}
	}
	cases := map[string]func(*Connector){
		"no name":      func(c *Connector) { c.Name = "" },
		"no id":        func(c *Connector) { c.ID = "" },
		"no address":   func(c *Connector) { c.URL = "" },
		"no enclave":   func(c *Connector) { c.EnclaveID = "" },
		"plain http":   func(c *Connector) { c.URL = "http://sc.example.org" },
		"missing cert": func(c *Connector) { c.CACertFile = "/no/such/file.pem" },
	}
	for name, breakIt := range cases {
		c := base()
		breakIt(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s should be refused", name)
		}
	}
	if err := base().Validate(); err != nil {
		t.Errorf("a complete connector should be accepted: %v", err)
	}
	// Settings are checked even while switched off, because settings saved now
	// are settings used later.
	off := base()
	off.URL = "http://sc.example.org"
	err := off.Validate()
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain http should be refused by name, got %v", err)
	}
}

func TestClientNeedsCredentials(t *testing.T) {
	f := newFakeSC(t)
	_, err := New(f.config(), Credentials{})
	if err == nil {
		t.Fatal("a client with no credentials should not be built")
	}
	// The message names the connector and the variable that belongs to it,
	// which is what somebody with two consoles needs to be told.
	envA, _, _, _ := EnvNames(f.config().ID)
	if !strings.Contains(err.Error(), envA) {
		t.Errorf("the message should name this connector's variable: %v", err)
	}
	if !strings.Contains(err.Error(), "Fake Security Center") {
		t.Errorf("the message should say which connector: %v", err)
	}
}

func TestCredentialsPreferTheEnvironmentOverTheFile(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCredentials(dir, "sc-one", Credentials{AccessKey: "from-file", SecretKey: "file-secret"}); err != nil {
		t.Fatal(err)
	}
	// The stored file is owner-only, because it holds a secret.
	info, err := os.Stat(filepath.Join(dir, CredentialsStore))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credentials file mode = %o, want 600", perm)
	}
	if !CredentialsOnDisk(dir, "sc-one") {
		t.Error("the page needs to be able to say that secrets are on disk")
	}

	got, err := LoadCredentials(dir, "sc-one")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKey != "from-file" {
		t.Errorf("stored credentials were not read: %+v", got)
	}

	t.Setenv(EnvAccessKey, "from-env")
	t.Setenv(EnvSecretKey, "env-secret")
	got, err = LoadCredentials(dir, "sc-one")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKey != "from-env" || got.SecretKey != "env-secret" {
		t.Errorf("the environment should win, got %+v", got)
	}

	if err := ForgetCredentials(dir, "sc-one"); err != nil {
		t.Fatal(err)
	}
	if CredentialsOnDisk(dir, "sc-one") {
		t.Error("forgetting the credentials left them behind")
	}
	// Forgetting again is not an error.
	if err := ForgetCredentials(dir, "sc-one"); err != nil {
		t.Errorf("removing what is already gone should be fine: %v", err)
	}
}

func TestTwoConnectorsKeepSeparateCredentials(t *testing.T) {
	dir := t.TempDir()
	for id, key := range map[string]string{"prod": "prod-key", "lab": "lab-key"} {
		if err := SaveCredentials(dir, id, Credentials{AccessKey: key, SecretKey: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	for id, want := range map[string]string{"prod": "prod-key", "lab": "lab-key"} {
		got, err := LoadCredentials(dir, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.AccessKey != want {
			t.Errorf("%s got %q, want %q", id, got.AccessKey, want)
		}
	}
	// Removing one leaves the other alone.
	if err := ForgetCredentials(dir, "prod"); err != nil {
		t.Fatal(err)
	}
	if CredentialsOnDisk(dir, "prod") {
		t.Error("prod credentials survived being forgotten")
	}
	if !CredentialsOnDisk(dir, "lab") {
		t.Error("forgetting one connector's credentials removed another's")
	}
	// A variable named for the connector beats the plain one, so two consoles
	// can hold different keys.
	envA, _, _, _ := EnvNames("lab")
	t.Setenv(EnvAccessKey, "generic")
	t.Setenv(envA, "lab-specific")
	got, _ := LoadCredentials(dir, "lab")
	if got.AccessKey != "lab-specific" {
		t.Errorf("the connector's own variable should win, got %q", got.AccessKey)
	}
	other, _ := LoadCredentials(dir, "prod")
	if other.AccessKey != "generic" {
		t.Errorf("the plain variable should still apply elsewhere, got %q", other.AccessKey)
	}
}

func TestConnectorsAreAListThatCanBeAddedToAndRemovedFrom(t *testing.T) {
	dir := t.TempDir()
	all, err := LoadConnectors(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Fatal("a fresh directory has no connectors")
	}
	if on, _ := AnyEnabled(dir); on {
		t.Fatal("with no connectors nothing should be reaching the network")
	}

	prod := &Connector{ID: "prod", Name: "Production", Kind: KindSecurityCenter,
		Enabled: true, URL: "https://prod.example.org/", EnclaveID: "CORE", TimeoutSeconds: 90}
	lab := &Connector{ID: "lab", Name: "Lab", Kind: KindSecurityCenter,
		URL: "https://lab.example.org", EnclaveID: "LAB"}
	for _, c := range []*Connector{prod, lab} {
		if err := SaveConnector(dir, c); err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
	}

	all, err = LoadConnectors(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d connectors, want 2", len(all))
	}
	// The one that is on sorts first, because it is the one that matters.
	if all[0].ID != "prod" {
		t.Errorf("switched-on connectors should come first, got %s", all[0].ID)
	}
	got, err := GetConnector(dir, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if got.Timeout() != 90*time.Second || got.Base() != "https://prod.example.org/rest" ||
		got.Host() != "prod.example.org" {
		t.Errorf("round trip lost detail: %+v", got)
	}

	// Only the enabled one counts as reaching the network.
	on, live := AnyEnabled(dir)
	if !on || len(live) != 1 || live[0].ID != "prod" {
		t.Errorf("enabled set = %v", live)
	}

	// Editing one leaves the other alone and keeps its history.
	RecordSync(dir, "prod")
	got, _ = GetConnector(dir, "prod")
	if got.LastSync == nil {
		t.Fatal("the sync time was not recorded")
	}
	got.Name = "Production console"
	if err := SaveConnector(dir, got); err != nil {
		t.Fatal(err)
	}
	got, _ = GetConnector(dir, "prod")
	if got.Name != "Production console" || got.LastSync == nil {
		t.Errorf("an edit lost history: %+v", got)
	}
	if _, err := GetConnector(dir, "lab"); err != nil {
		t.Errorf("editing one connector disturbed another: %v", err)
	}

	// Removing one takes its credentials with it and leaves the rest.
	if err := SaveCredentials(dir, "prod", Credentials{AccessKey: "A", SecretKey: "S"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteConnector(dir, "prod"); err != nil {
		t.Fatal(err)
	}
	if _, err := GetConnector(dir, "prod"); err == nil {
		t.Error("the connector was not removed")
	}
	if CredentialsOnDisk(dir, "prod") {
		t.Error("a secret was left on disk for a connector that no longer exists")
	}
	if _, err := GetConnector(dir, "lab"); err != nil {
		t.Errorf("removing one connector removed another: %v", err)
	}
	if err := DeleteConnector(dir, "prod"); err == nil {
		t.Error("removing what is already gone should say so")
	}
}

// ---------- pulling results all the way into the store ----------

func syncer(t *testing.T, f *fakeSC) (*Syncer, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnclave(&model.Enclave{
		ID: "CORE", Name: "Core Operations", Confidentiality: model.ImpactModerate,
		Networks: []model.Network{{CIDR: "10.20.0.0/16"}},
	}); err != nil {
		t.Fatal(err)
	}
	cats, err := catalog.NewRegistry(filepath.Join(dir, "catalogs"))
	if err != nil {
		t.Fatal(err)
	}
	maps, err := mapping.NewRegistry(filepath.Join(dir, "mappings"))
	if err != nil {
		t.Fatal(err)
	}
	return &Syncer{
		Store: st, Importer: importer.New(st, cats, maps),
		Client: keyClient(t, f), Config: f.config(),
	}, st
}

func TestPulledResultsGoThroughTheSameReaderAsAnUpload(t *testing.T) {
	f := newFakeSC(t)
	s, st := syncer(t, f)

	results, err := s.Available(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var weekly ScanResult
	for _, r := range results {
		if r.ID == "101" {
			weekly = r
		}
	}
	if weekly.ID == "" {
		t.Fatal("the completed scan was not listed")
	}
	if weekly.Imported {
		t.Fatal("nothing has been imported yet")
	}

	out, err := s.Import(context.Background(), weekly, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped != "" {
		t.Fatalf("skipped: %s", out.Skipped)
	}
	if out.Summary.FindingsAdded != 1 || out.Summary.AssetsCreated != 1 {
		t.Fatalf("summary = %+v", out.Summary)
	}
	// The asset and the finding are indistinguishable from an uploaded file's.
	assets := st.Assets("CORE")
	if len(assets) != 1 || assets[0].Name != "APP-SRV-01" {
		t.Fatalf("assets = %v", assets)
	}
	findings := st.Findings("CORE")
	if len(findings) != 1 || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("findings = %v", findings)
	}
	if len(findings[0].CVEs) != 1 || findings[0].CVEs[0] != "CVE-2025-21001" {
		t.Errorf("CVEs = %v", findings[0].CVEs)
	}
	// It reaches the controls, like any other vulnerability finding.
	if len(findings[0].Controls("nist-800-53r5")) == 0 {
		t.Error("a pulled finding reached no control")
	}

	// The import records where it came from.
	scans := st.Scans("CORE")
	if len(scans) != 1 {
		t.Fatalf("scans = %d", len(scans))
	}
	sc := scans[0]
	if sc.SourceRef != SourceRef("101") {
		t.Errorf("source ref = %q", sc.SourceRef)
	}
	if !FromScan(sc) {
		t.Error("the import is not recognisable as having come from the connector")
	}
	if sc.Title != "Weekly credentialed" || !strings.Contains(sc.Notes, "repository Production") {
		t.Errorf("provenance is thin: %+v", sc)
	}
	if sc.ScanDate.IsZero() {
		t.Error("the scan date should come from the console's finish time")
	}
}

func TestTheSameResultIsNotImportedTwice(t *testing.T) {
	f := newFakeSC(t)
	s, st := syncer(t, f)
	results, _ := s.Available(context.Background(), time.Time{})
	var weekly ScanResult
	for _, r := range results {
		if r.ID == "101" {
			weekly = r
		}
	}
	if _, err := s.Import(context.Background(), weekly, false); err != nil {
		t.Fatal(err)
	}

	// Listing again marks it as taken.
	again, err := s.Available(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range again {
		if r.ID == "101" && !r.Imported {
			t.Error("an imported result should be marked as such")
		}
	}
	out, err := s.Import(context.Background(), weekly, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped == "" {
		t.Error("importing the same result again should be skipped, not repeated")
	}
	if len(st.Scans("CORE")) != 1 {
		t.Errorf("a second import record was created: %d", len(st.Scans("CORE")))
	}

	// Forcing it re-reads the file, which still merges rather than duplicating.
	out, err = s.Import(context.Background(), weekly, true)
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped != "" {
		t.Errorf("forcing should not skip: %s", out.Skipped)
	}
	if got := len(st.Findings("CORE")); got != 1 {
		t.Errorf("forcing duplicated findings: %d", got)
	}
}

func TestSyncAllTakesWhatIsOutstandingAndKeepsGoing(t *testing.T) {
	f := newFakeSC(t)
	s, st := syncer(t, f)
	rep, err := s.SyncAll(context.Background(), time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Two completed results, one still running.
	if rep.Imported != 2 {
		t.Errorf("imported %d, want the two completed results", rep.Imported)
	}
	if rep.Skipped != 1 {
		t.Errorf("skipped %d, want the running scan", rep.Skipped)
	}
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %v", rep.Errors)
	}
	if len(st.Scans("CORE")) != 2 {
		t.Errorf("scans on file = %d", len(st.Scans("CORE")))
	}

	// A second run takes nothing, because there is nothing new.
	rep, err = s.SyncAll(context.Background(), time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 0 {
		t.Errorf("a second sync imported %d results", rep.Imported)
	}
}

func TestARunningScanIsNotDownloaded(t *testing.T) {
	f := newFakeSC(t)
	s, _ := syncer(t, f)
	out, err := s.Import(context.Background(), ScanResult{ID: "102", Status: "Running"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Skipped == "" {
		t.Error("a scan that has not finished has nothing to take")
	}
	for _, r := range f.requests {
		if strings.HasSuffix(r.URL.Path, "/download") {
			t.Error("a running scan should not have been downloaded")
		}
	}
}
