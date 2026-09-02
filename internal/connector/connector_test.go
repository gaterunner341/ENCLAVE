package connector

import (
	"strings"
	"testing"

	"github.com/pkittelson/enclave/internal/model"
)

const sample = "\ufeffComputer Name,IP Address,Operating System,Sensor Status,BitLocker,Last Scan\r\n" +
	"WKS-014,10.12.1.20,Windows 11 Pro,Normal,Yes,2026-08-20\r\n" +
	",,,,,\r\n" +
	"SRV-DB-02,10.12.9.5,Windows Server 2022,Normal,No,20/13/2026\r\n"

func testMap() ColumnMap {
	return ColumnMap{
		Identifiers: map[string]string{model.IDHostname: "Computer Name"},
		Fields: map[string]string{
			model.FieldIP:            "IP Address",
			model.FieldOS:            "Operating System",
			model.FieldEDRStatus:     "Sensor Status",
			model.FieldDiskEncrypted: "BitLocker",
			model.FieldLastVulnScan:  "Last Scan",
		},
	}
}

func TestParseReadsAnExcelExport(t *testing.T) {
	c := &CSV{SourceID: "falcon-prod", SourceKind: "edr", Map: testMap()}
	obs, err := c.Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	// The blank row carries no identifier, so there is nothing to attach it to.
	if len(obs) != 2 {
		t.Fatalf("got %d observations, want 2", len(obs))
	}

	first := obs[0]
	if first.Identifiers[0].Value != "WKS-014" {
		t.Errorf("identifier = %q", first.Identifiers[0].Value)
	}
	if !first.BoolFields[model.FieldDiskEncrypted] {
		t.Error("BitLocker=Yes should read as encrypted")
	}
	if got := first.Fields[model.FieldLastVulnScan]; got != "2026-08-20" {
		t.Errorf("scan date = %q, want 2026-08-20", got)
	}
	if _, ok := first.TimeFields[model.FieldLastVulnScan]; !ok {
		t.Error("a readable date should be kept as a timestamp")
	}
}

func TestParseKeepsAnUnreadableDateAsText(t *testing.T) {
	c := &CSV{SourceID: "falcon-prod", SourceKind: "edr", Map: testMap()}
	obs, err := c.Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	second := obs[1]
	if got := second.Fields[model.FieldLastVulnScan]; got != "20/13/2026" {
		t.Errorf("unparseable date = %q, want it kept verbatim", got)
	}
	if _, ok := second.TimeFields[model.FieldLastVulnScan]; ok {
		t.Error("an unparseable date must not become a timestamp")
	}
	if second.BoolFields[model.FieldDiskEncrypted] {
		t.Error("BitLocker=No should not read as encrypted")
	}
}

func TestNormHeaderIgnoresPunctuationAndCase(t *testing.T) {
	for _, s := range []string{"Host Name", "host_name", "HOSTNAME", " Host-Name "} {
		if got := normHeader(s); got != "hostname" {
			t.Errorf("normHeader(%q) = %q", s, got)
		}
	}
}
