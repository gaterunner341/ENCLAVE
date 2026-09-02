package mapping

import (
	"strings"
	"testing"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/model"
)

func registries(t *testing.T) (*Registry, *catalog.Registry) {
	t.Helper()
	m, err := NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := catalog.NewRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return m, c
}

func TestSeedCCIResolvesAStigFinding(t *testing.T) {
	m, c := registries(t)
	cat, _ := c.Get("nist-800-53r5")
	f := &model.Finding{Title: "separate admin accounts", CCIs: []string{"CCI-002235"}}
	ids, why := m.Resolve(f, cat)
	if len(ids) != 1 || ids[0] != "AC-6(10)" {
		t.Fatalf("got %v", ids)
	}
	if !strings.Contains(why[0], "CCI-002235") {
		t.Errorf("the reason should name the CCI, got %q", why[0])
	}
}

func TestCVEWildcardReachesFlawRemediation(t *testing.T) {
	m, c := registries(t)
	cat, _ := c.Get("nist-800-53r5")
	f := &model.Finding{Title: "missing patch", CVEs: []string{"CVE-2025-0001"}}
	ids, _ := m.Resolve(f, cat)
	got := strings.Join(ids, " ")
	if !strings.Contains(got, "SI-2") || !strings.Contains(got, "RA-5") {
		t.Errorf("a finding naming a CVE should reach flaw remediation, got %v", ids)
	}
	// A finding with no CVE must not.
	plain := &model.Finding{Title: "a configuration item"}
	if ids, _ := m.Resolve(plain, cat); len(ids) != 0 {
		t.Errorf("a finding with no identifiers should reach nothing, got %v", ids)
	}
}

func TestUnknownCCIStaysUnmapped(t *testing.T) {
	m, c := registries(t)
	cat, _ := c.Get("nist-800-53r5")
	f := &model.Finding{Title: "x", CCIs: []string{"CCI-999999"}}
	if ids, _ := m.Resolve(f, cat); len(ids) != 0 {
		t.Errorf("an unknown CCI must not be guessed at, got %v", ids)
	}
}

func TestEnhancementFallsBackToItsBaseControl(t *testing.T) {
	m, c := registries(t)
	// A catalogue that has AC-2 but not AC-2(1).
	cat, err := catalog.ParseText(strings.NewReader("@id tiny\n@name Tiny\nAC-2 | Account Management |\n"))
	if err != nil {
		t.Fatal(err)
	}
	set := &Set{ID: "t", Name: "t", Scheme: SchemeCCI, Target: "tiny",
		Entries: map[string][]string{"CCI-000015": {"AC-2(1)"}}}
	if err := m.Add(set); err != nil {
		t.Fatal(err)
	}
	_ = c
	f := &model.Finding{Title: "x", CCIs: []string{"CCI-000015"}}
	ids, _ := m.Resolve(f, cat)
	if len(ids) != 1 || ids[0] != "AC-2" {
		t.Fatalf("evidence about an unselected enhancement should land on its base control, got %v", ids)
	}
}

func TestCrosswalkCarriesEvidenceBetweenFrameworks(t *testing.T) {
	m, c := registries(t)
	nist, _ := c.Get("nist-800-53r5")
	own, err := catalog.ParseText(strings.NewReader(
		"@id acme\n@name ACME\n@family AM = Accounts\nAM-1 | Separate admin accounts |\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Add(&Set{
		ID: "acme-xwalk", Name: "800-53 to ACME", Scheme: SchemeControl, Target: "acme",
		Entries: map[string][]string{"AC-6(10)": {"AM-1"}},
	}); err != nil {
		t.Fatal(err)
	}
	f := &model.Finding{Title: "x", CCIs: []string{"CCI-002235"}}
	// Annotating against 800-53 first is what gives the crosswalk something to
	// carry across, which is why Annotate takes the catalogues in order.
	m.Annotate(f, []*catalog.Catalog{nist, own})
	if got := f.Controls("nist-800-53r5"); len(got) != 1 || got[0] != "AC-6(10)" {
		t.Fatalf("800-53 refs = %v", got)
	}
	if got := f.Controls("acme"); len(got) != 1 || got[0] != "AM-1" {
		t.Fatalf("the crosswalk did not reach the organisation's own framework: %v", got)
	}
}

func TestParseCCIList(t *testing.T) {
	in := `<?xml version="1.0"?><cci_list><cci_items>
	<cci_item id="CCI-000366"><references>
	  <reference creator="NIST" title="NIST SP 800-53" version="4" index="CM-6 b"/>
	  <reference creator="NIST" title="NIST SP 800-53 Revision 5" version="5" index="CM-6 b"/>
	</references></cci_item>
	<cci_item id="CCI-000015"><references>
	  <reference creator="NIST" title="NIST SP 800-53 Revision 5" version="5" index="AC-2 (1)"/>
	</references></cci_item>
	<cci_item id="CCI-NOREF"><references></references></cci_item>
	</cci_items></cci_list>`
	set, err := ParseCCIList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Lookup("CCI-000366"); len(got) != 1 || got[0] != "CM-6" {
		t.Errorf("a statement item suffix should be dropped, got %v", got)
	}
	if got := set.Lookup("CCI-000015"); len(got) != 1 || got[0] != "AC-2(1)" {
		t.Errorf("an enhancement should be kept, got %v", got)
	}
	if len(set.Lookup("CCI-NOREF")) != 0 {
		t.Error("a CCI with no usable reference should be left out")
	}
	if _, err := ParseCCIList(strings.NewReader("<x/>")); err == nil {
		t.Error("a file with no CCI items should be rejected")
	}
}

func TestParseCSVWithDirectives(t *testing.T) {
	in := "#name,Local crosswalk\n#scheme,control\n#target,acme\nkey,controls\nAC-2,\"AM-1,AM-2\"\nCM-6,HD-1\n"
	set, err := ParseCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if set.Name != "Local crosswalk" || set.Scheme != SchemeControl || set.Target != "acme" {
		t.Errorf("directives were not read: %+v", set)
	}
	if got := set.Lookup("ac-2"); len(got) != 2 {
		t.Errorf("lookup should ignore case, got %v", got)
	}
	if _, err := ParseCSV(strings.NewReader("key,controls\n")); err == nil {
		t.Error("a file with a header row and no entries should be rejected")
	}
	// A file with no header row at all still works, because every key carries a
	// digit and a heading does not.
	headerless, err := ParseCSV(strings.NewReader("CCI-000366,CM-6\n"))
	if err != nil {
		t.Fatalf("a headerless file should still parse: %v", err)
	}
	if len(headerless.Lookup("CCI-000366")) != 1 {
		t.Error("the first row was mistaken for a heading")
	}
}

func TestSeedTablesCannotBeRemoved(t *testing.T) {
	m, _ := registries(t)
	for _, s := range m.Sets() {
		if !s.BuiltIn {
			continue
		}
		if err := m.Remove(s.ID); err == nil {
			t.Errorf("%s is built in and should not be removable", s.ID)
		}
	}
}

func TestImportedTableRoundTripsThroughDisk(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewRegistry(dir)
	set := &Set{ID: "local", Name: "Local", Scheme: SchemeCCI, Target: "nist-800-53r5",
		Entries: map[string][]string{"CCI-000001": {"AC-1", "PL-1"}}}
	if err := m.Add(set); err != nil {
		t.Fatal(err)
	}
	again, err := NewRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := again.Get("local")
	if !ok {
		t.Fatal("the imported table did not survive a restart")
	}
	if len(got.Lookup("CCI-000001")) != 2 || got.Scheme != SchemeCCI || got.Target != "nist-800-53r5" {
		t.Errorf("round trip lost detail: %+v", got)
	}
}

func TestSeedCCIEntriesAllResolveInTheBuiltInCatalog(t *testing.T) {
	_, c := registries(t)
	cat, _ := c.Get("nist-800-53r5")
	for _, s := range seedSets() {
		if s.Scheme != SchemeCCI || s.Target != "nist-800-53r5" {
			continue
		}
		for key, ids := range s.Entries {
			for _, id := range ids {
				if !cat.Has(id) && !cat.Has(catalog.BaseID(id)) {
					t.Errorf("%s maps to %s, which is not in the built-in 800-53 catalog", key, id)
				}
			}
		}
	}
}
