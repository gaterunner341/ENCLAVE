package catalog

import (
	"strings"
	"testing"
)

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := NewRegistry(t.TempDir())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestBuiltinCatalogsLoad(t *testing.T) {
	r := testRegistry(t)
	for _, id := range []string{"nist-800-53r5", "cis-controls-v8", "nist-csf-2.0"} {
		c, ok := r.Get(id)
		if !ok {
			t.Fatalf("built-in catalog %s missing", id)
		}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", id, err)
		}
		if len(c.Families) == 0 {
			t.Errorf("%s declares no families", id)
		}
	}
}

func TestNISTBaselinesAreNested(t *testing.T) {
	c, _ := testRegistry(t).Get("nist-800-53r5")
	low, mod, high := c.Count("low"), c.Count("moderate"), c.Count("high")
	if !(low < mod && mod < high) {
		t.Fatalf("baselines should grow low < moderate < high, got %d %d %d", low, mod, high)
	}
	// Every low control has to appear in moderate, and every moderate one in
	// high; a baseline that is not a superset would silently drop requirements.
	for _, ctl := range c.Selected("low") {
		if !ctl.InProfile("moderate") {
			t.Errorf("%s is in low but not moderate", ctl.ID)
		}
	}
	for _, ctl := range c.Selected("moderate") {
		if !ctl.InProfile("high") {
			t.Errorf("%s is in moderate but not high", ctl.ID)
		}
	}
}

func TestCISImplementationGroupsAreNested(t *testing.T) {
	c, _ := testRegistry(t).Get("cis-controls-v8")
	if got := len(c.Controls); got != 153 {
		t.Errorf("CIS v8 should have 153 safeguards, got %d", got)
	}
	for _, ctl := range c.Selected("ig1") {
		if !ctl.InProfile("ig2") || !ctl.InProfile("ig3") {
			t.Errorf("%s is in IG1 but not the groups above it", ctl.ID)
		}
	}
	for _, ctl := range c.Selected("ig2") {
		if !ctl.InProfile("ig3") {
			t.Errorf("%s is in IG2 but not IG3", ctl.ID)
		}
	}
}

func TestControlLookupToleratesSpelling(t *testing.T) {
	c, _ := testRegistry(t).Get("nist-800-53r5")
	for _, id := range []string{"AC-2(1)", "ac-2(1)", "AC-2 (1)", " AC-2(1) "} {
		if _, ok := c.Control(id); !ok {
			t.Errorf("did not resolve %q", id)
		}
	}
	if _, ok := c.Control("ZZ-9"); ok {
		t.Error("resolved a control that does not exist")
	}
}

func TestEnhancementsGetParents(t *testing.T) {
	c, _ := testRegistry(t).Get("nist-800-53r5")
	ctl, ok := c.Control("AC-2(1)")
	if !ok {
		t.Fatal("AC-2(1) missing")
	}
	if ctl.Parent != "AC-2" {
		t.Errorf("parent = %q, want AC-2", ctl.Parent)
	}
	if ctl.FamilyID != "AC" {
		t.Errorf("family = %q, want AC", ctl.FamilyID)
	}
	if !ctl.IsEnhancement() {
		t.Error("AC-2(1) should be an enhancement")
	}
}

func TestCSFFunctionsBecomeFamilies(t *testing.T) {
	c, _ := testRegistry(t).Get("nist-csf-2.0")
	ctl, ok := c.Control("PR.AA-01")
	if !ok {
		t.Fatal("PR.AA-01 missing")
	}
	if ctl.FamilyID != "PR" {
		t.Errorf("family = %q, want PR", ctl.FamilyID)
	}
}

func TestParseTextRejectsDuplicates(t *testing.T) {
	_, err := ParseText(strings.NewReader("@id x\n@name X\nA-1 | One |\nA-1 | One again |\n"))
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("expected a duplicate error, got %v", err)
	}
}

func TestParseCSVCustomFramework(t *testing.T) {
	in := "Control ID,Title,Family,Profiles\nSEC-1,Do the thing,Security,core\nSEC-1(1),Do it twice,Security,core;extended\n"
	c, err := ParseCSV(strings.NewReader(in), "acme", "ACME Standard")
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(c.Controls) != 2 {
		t.Fatalf("got %d controls", len(c.Controls))
	}
	if c.Count("extended") != 1 {
		t.Errorf("extended profile should hold 1 control, got %d", c.Count("extended"))
	}
	ctl, _ := c.Control("SEC-1(1)")
	if ctl.Parent != "SEC-1" {
		t.Errorf("parent = %q", ctl.Parent)
	}
}

func TestParseOSCAL(t *testing.T) {
	in := `{"catalog":{"metadata":{"title":"Tiny Catalog","version":"1.0"},
	 "groups":[{"id":"ac","title":"Access Control","controls":[
	   {"id":"ac-1","title":"Policy","parts":[{"name":"statement","prose":"Do policy."}],
	    "controls":[{"id":"ac-1.1","title":"Automated"}]}]}]}}`
	c, err := ParseOSCAL(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseOSCAL: %v", err)
	}
	if _, ok := c.Control("AC-1(1)"); !ok {
		t.Error("enhancement ac-1.1 should become AC-1(1)")
	}
	ctl, _ := c.Control("AC-1")
	if ctl.Statement != "Do policy." {
		t.Errorf("statement = %q", ctl.Statement)
	}
}

func TestRegistryImportShadowsBuiltIn(t *testing.T) {
	r := testRegistry(t)
	raw := []byte("@id nist-800-53r5\n@name Authoritative 800-53\nAC-1 | Policy | low\n")
	cat, err := Load(raw, "nist-800-53r5.catalog")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(cat, raw, "nist-800-53r5.catalog"); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("nist-800-53r5")
	if got.Name != "Authoritative 800-53" {
		t.Errorf("import did not shadow the built-in: %q", got.Name)
	}
	if err := r.Remove("nist-800-53r5"); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Get("nist-800-53r5")
	if !got.BuiltIn {
		t.Error("removing the import should restore the built-in catalog")
	}
}

func TestBaseID(t *testing.T) {
	for in, want := range map[string]string{
		"AC-2(1)": "AC-2", "AC-2": "AC-2", "AC-2 (12)": "AC-2", "3.10": "3.10",
	} {
		if got := BaseID(in); got != want {
			t.Errorf("BaseID(%q) = %q, want %q", in, got, want)
		}
	}
}
