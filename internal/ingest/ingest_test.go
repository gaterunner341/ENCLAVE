package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gaterunner341/enclave/internal/model"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return b
}

func TestDetectIdentifiesEachFormat(t *testing.T) {
	for name, want := range map[string]Format{
		"sample.ckl":       FormatCKL,
		"sample.nessus":    FormatNessus,
		"sample-xccdf.xml": FormatXCCDF,
		"sample-vulns.csv": FormatCSV,
	} {
		if got := Detect(read(t, name), name); got != want {
			t.Errorf("Detect(%s) = %q, want %q", name, got, want)
		}
	}
	// The content wins over a misleading extension.
	if got := Detect(read(t, "sample.ckl"), "results.csv"); got != FormatCKL {
		t.Errorf("a checklist named .csv should still be read as a checklist, got %q", got)
	}
	if got := Detect([]byte("{\"stigs\":[]}"), "x.json"); got != FormatCKLB {
		t.Errorf("JSON should be read as a v3 checklist, got %q", got)
	}
	if got := Detect([]byte("\xef\xbb\xbf{\"stigs\":[]}"), "x"); got != FormatCKLB {
		t.Errorf("a byte order mark should not defeat detection, got %q", got)
	}
}

func TestParseCKL(t *testing.T) {
	res, err := Parse(read(t, "sample.ckl"), "sample.ckl", CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("a checklist describes one target, got %d", len(res.Hosts))
	}
	h := res.Hosts[0]
	if h.Name != "APP-SRV-01" || h.FQDN != "app-srv-01.example.org" {
		t.Errorf("target identity wrong: %+v", h)
	}
	if len(h.IPs) != 1 || h.IPs[0] != "10.20.4.11" {
		t.Errorf("addresses = %v", h.IPs)
	}
	if len(h.Findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(h.Findings))
	}
	first := h.Findings[0]
	if first.GroupID != "V-254238" || first.RuleID != "SV-254238r958472_rule" {
		t.Errorf("identifiers = %q / %q", first.GroupID, first.RuleID)
	}
	if first.Severity != model.SeverityHigh || first.Status != model.StatusOpen {
		t.Errorf("severity/status = %q / %q", first.Severity, first.Status)
	}
	if len(first.CCIs) != 1 || first.CCIs[0] != "CCI-002235" {
		t.Errorf("CCIs = %v", first.CCIs)
	}
	if !strings.Contains(first.FindingDetails, "daily-driver") {
		t.Error("the reviewer's own finding details were dropped")
	}
	if h.Findings[1].Status != model.StatusNotAFinding {
		t.Error("a NotAFinding status should not read as open")
	}
	if res.Scan.BenchmarkID != "Windows_Server_2022_STIG" {
		t.Errorf("benchmark = %q", res.Scan.BenchmarkID)
	}
	if res.Scan.Kind != "stig" {
		t.Errorf("kind = %q", res.Scan.Kind)
	}
}

func TestParseCKLB(t *testing.T) {
	in := `{"title":"App server review","target_data":{"host_name":"APP-SRV-02","ip_address":"10.20.4.12",
	 "fqdn":"app-srv-02.example.org","target_type":"Computing"},
	 "stigs":[{"display_name":"RHEL 9 STIG","stig_id":"RHEL_9_STIG","version":"1","release_info":"Release: 5",
	 "rules":[{"group_id":"V-257777","rule_id":"SV-257777r991589_rule","rule_title":"Single-user mode requires authentication",
	 "severity":"medium","status":"open","ccis":["CCI-000213"],"discussion":"d","check_content":"c","fix_text":"f",
	 "overrides":{"severity":{"severity":"high","reason":"internet facing"}}}]}]}`
	res, err := Parse([]byte(in), "x.cklb", CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Hosts[0].Findings[0]
	if f.Severity != model.SeverityHigh {
		t.Errorf("a severity override should win, got %q", f.Severity)
	}
	if res.Hosts[0].Name != "APP-SRV-02" {
		t.Errorf("host = %q", res.Hosts[0].Name)
	}
	if f.CCIs[0] != "CCI-000213" {
		t.Errorf("CCIs = %v", f.CCIs)
	}
	// A JSON file that is not a checklist has to say so clearly.
	if _, err := Parse([]byte(`{"hello":"world"}`), "x.json", CSVOptions{}); err == nil {
		t.Error("a JSON file with no stigs section should be rejected")
	}
}

func TestParseXCCDF(t *testing.T) {
	res, err := Parse(read(t, "sample-xccdf.xml"), "sample-xccdf.xml", CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := res.Hosts[0]
	if h.Name != "db-srv-04.example.org" {
		t.Errorf("target = %q", h.Name)
	}
	if len(h.IPs) != 1 || h.IPs[0] != "10.20.4.40" {
		t.Errorf("addresses = %v", h.IPs)
	}
	if len(h.Findings) != 2 {
		t.Fatalf("got %d results", len(h.Findings))
	}
	var fail, pass *model.Finding
	for _, f := range h.Findings {
		if f.Status == model.StatusOpen {
			fail = f
		} else {
			pass = f
		}
	}
	if fail == nil || pass == nil {
		t.Fatal("expected one failing and one passing result")
	}
	// The rule definition has to be joined to the result, or the finding has a
	// bare identifier and no text.
	if !strings.Contains(fail.Title, "single-user mode") {
		t.Errorf("rule title was not joined to the result: %q", fail.Title)
	}
	if fail.FixText == "" {
		t.Error("fix text was not joined to the result")
	}
	if fail.RuleID != "SV-257777r991589_rule" {
		t.Errorf("the xccdf_ prefix chain was not stripped: %q", fail.RuleID)
	}
	if len(fail.CCIs) != 1 {
		t.Errorf("CCIs = %v", fail.CCIs)
	}
	if res.Scan.ScanDate.IsZero() {
		t.Error("the test result start time should become the scan date")
	}
	// A benchmark with no results is a different problem from a broken file.
	only := strings.SplitN(string(read(t, "sample-xccdf.xml")), "<TestResult", 2)[0] + "</Benchmark>"
	if _, err := Parse([]byte(only), "b.xml", CSVOptions{}); err == nil ||
		!strings.Contains(err.Error(), "benchmark definition") {
		t.Errorf("expected a clear message about a definition file, got %v", err)
	}
}

func TestParseNessus(t *testing.T) {
	res, err := Parse(read(t, "sample.nessus"), "sample.nessus", CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(res.Hosts))
	}
	host := res.Hosts[0]
	if host.Name != "APP-SRV-01" {
		t.Errorf("the NetBIOS name should replace the bare address, got %q", host.Name)
	}
	if !strings.Contains(host.OS, "Windows Server 2022") {
		t.Errorf("operating system = %q", host.OS)
	}
	var critical, info *model.Finding
	for _, f := range host.Findings {
		switch f.RuleID {
		case "200001":
			critical = f
		case "19506":
			info = f
		}
	}
	if critical == nil || critical.Severity != model.SeverityCritical {
		t.Errorf("a CVSS 9.8 plugin should be critical, got %+v", critical)
	}
	if critical.CVSS != 9.8 || !strings.HasPrefix(critical.CVSSVector, "CVSS:3.1") {
		t.Errorf("CVSS was not read: %v %q", critical.CVSS, critical.CVSSVector)
	}
	if len(critical.CVEs) != 1 {
		t.Errorf("CVEs = %v", critical.CVEs)
	}
	if info == nil || info.Status.Counts() {
		t.Error("an informational plugin must not count as an open finding")
	}
	// A STIG severity on a plugin overrides the CVSS band.
	router := res.Hosts[1]
	if router.Type != model.AssetNetwork {
		t.Errorf("a Cisco IOS XE target should be classed as network gear, got %q", router.Type)
	}
	if router.Findings[0].Severity != model.SeverityHigh {
		t.Errorf("stig_severity CAT I should map to high, got %q", router.Findings[0].Severity)
	}
	if res.Scan.ScanDate.IsZero() {
		t.Error("HOST_START should become the scan date")
	}
}

func TestParseNessusCompliance(t *testing.T) {
	in := `<?xml version="1.0"?><NessusClientData_v2><Report name="audit">
	<ReportHost name="10.0.0.1"><HostProperties><tag name="host-ip">10.0.0.1</tag></HostProperties>
	<ReportItem port="0" severity="3" pluginID="21157" pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance">
	  <compliance>true</compliance>
	  <compliance-check-name>2.2.1 Ensure xinetd is not installed</compliance-check-name>
	  <compliance-check-id>abc123</compliance-check-id>
	  <compliance-result>FAILED</compliance-result>
	  <compliance-actual-value>xinetd is installed</compliance-actual-value>
	  <compliance-severity>MEDIUM</compliance-severity>
	  <compliance-solution>Remove the xinetd package.</compliance-solution>
	</ReportItem></ReportHost></Report></NessusClientData_v2>`
	res, err := Parse([]byte(in), "audit.nessus", CSVOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Hosts[0].Findings[0]
	if f.Title != "2.2.1 Ensure xinetd is not installed" {
		t.Errorf("the compliance check name should be the title, got %q", f.Title)
	}
	if f.Status != model.StatusOpen {
		t.Errorf("a FAILED compliance result is open, got %q", f.Status)
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("the compliance severity should win, got %q", f.Severity)
	}
	if f.FindingDetails != "xinetd is installed" {
		t.Errorf("the observed value was dropped: %q", f.FindingDetails)
	}
}

func TestCSVColumnDetection(t *testing.T) {
	p, err := PreviewCSV(read(t, "sample-vulns.csv"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 3 {
		t.Errorf("rows = %d", p.Total)
	}
	want := map[Field]string{
		FAssetName: "Asset Names", FIP: "Asset IP Address", FOS: "Asset OS Name",
		FTitle: "Vulnerability Title", FCVE: "Vulnerability CVE IDs",
		FSeverity: "Vulnerability Severity Level", FCVSS: "Vulnerability CVSSv3 Score",
		FFix: "Vulnerability Solution", FFirstSeen: "First Discovered",
	}
	for field, col := range want {
		if p.Mapping[field] != col {
			t.Errorf("%s mapped to %q, want %q", field, p.Mapping[field], col)
		}
	}
}

func TestCSVImportGroupsRowsByAsset(t *testing.T) {
	data := read(t, "sample-vulns.csv")
	p, _ := PreviewCSV(data, 1)
	res, err := Parse(data, "sample-vulns.csv", CSVOptions{Mapping: p.Mapping})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("three rows across two machines should give 2 hosts, got %d", len(res.Hosts))
	}
	if len(res.Hosts[0].Findings) != 2 {
		t.Errorf("the first host should carry 2 findings, got %d", len(res.Hosts[0].Findings))
	}
	var critical *model.Finding
	for _, f := range res.Hosts[0].Findings {
		if f.Severity == model.SeverityCritical {
			critical = f
		}
	}
	if critical == nil {
		t.Fatal("the critical row was not read")
	}
	if critical.CVSS != 9.8 {
		t.Errorf("CVSS = %v", critical.CVSS)
	}
	if critical.FirstSeen.IsZero() {
		t.Error("the first-discovered date was not read")
	}
}

func TestCSVNeedsATitleColumn(t *testing.T) {
	_, err := Parse([]byte("a,b\n1,2\n"), "x.csv", CSVOptions{Mapping: map[Field]string{FAssetName: "a"}})
	if err == nil || !strings.Contains(err.Error(), "title column") {
		t.Errorf("expected a clear message about the title column, got %v", err)
	}
}

func TestCSVSniffsDelimiterAndByteOrderMark(t *testing.T) {
	in := "\xef\xbb\xbfHost;Finding;Severity\nsrv-1;Something wrong;High\n"
	p, err := PreviewCSV([]byte(in), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Delim != ';' {
		t.Errorf("delimiter = %q", p.Delim)
	}
	if p.Header[0] != "Host" {
		t.Errorf("the byte order mark was left on the first heading: %q", p.Header[0])
	}
	if p.Mapping[FTitle] != "Finding" {
		t.Errorf("title mapped to %q", p.Mapping[FTitle])
	}
}

func TestFingerprintIsStableAndSpecific(t *testing.T) {
	a := Fingerprint("asset-1", "SV-1", "V-1", "title")
	if a != Fingerprint("asset-1", "SV-1", "V-9", "different title") {
		t.Error("the rule identifier alone should decide identity when it is present")
	}
	if a == Fingerprint("asset-2", "SV-1", "V-1", "title") {
		t.Error("the same rule on a different asset is a different finding")
	}
	if Fingerprint("a", "", "", "Some title") != Fingerprint("a", "", "", "  some TITLE  ") {
		t.Error("with no identifiers, the title should decide, ignoring case and spacing")
	}
}

func TestAssetTypeGuessing(t *testing.T) {
	for _, tc := range []struct {
		role, os string
		want     model.AssetType
	}{
		{"", "Cisco IOS XE Software", model.AssetNetwork},
		{"", "Palo Alto PAN-OS 11", model.AssetSecurity},
		{"", "VMware ESXi 8.0", model.AssetVirtual},
		{"", "Microsoft Windows 11 Enterprise", model.AssetWorkstation},
		{"", "Red Hat Enterprise Linux 9", model.AssetServer},
		{"", "something else entirely", model.AssetOther},
	} {
		if got := assetTypeFor(tc.role, tc.os, ""); got != tc.want {
			t.Errorf("assetTypeFor(%q) = %q, want %q", tc.os, got, tc.want)
		}
	}
}
