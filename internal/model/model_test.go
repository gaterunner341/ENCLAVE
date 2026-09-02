package model

import "testing"

func TestIdentifierNormalize(t *testing.T) {
	cases := []struct {
		in   Identifier
		want string
	}{
		{Identifier{IDMAC, "AA:BB:CC:11:22:33"}, "aabbcc112233"},
		{Identifier{IDMAC, "aa-bb-cc-11-22-33"}, "aabbcc112233"},
		{Identifier{IDHostname, "WKS-014.corp.example.com"}, "wks-014"},
		{Identifier{IDFQDN, "WKS-014.corp.example.com."}, "wks-014.corp.example.com"},
		{Identifier{IDSerial, "  5cg-8241-lm "}, "5CG8241LM"},
	}
	for _, c := range cases {
		if got := c.in.Normalize().Value; got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in.Value, got, c.want)
		}
	}
}

func TestIdentifierValid(t *testing.T) {
	valid := []Identifier{
		{IDHostname, "wks-014"},
		{IDMAC, "aabbcc112233"},
		{IDSerial, "5CG8241LM"},
	}
	for _, id := range valid {
		if !id.Valid() {
			t.Errorf("%v should be valid", id)
		}
	}
	invalid := []Identifier{
		{IDHostname, ""},
		{IDSerial, "To Be Filled By O.E.M."},
		{IDMAC, "aabbcc"}, // half an address is not an address
		{IDUUID, "unknown"},
	}
	for _, id := range invalid {
		if id.Valid() {
			t.Errorf("%v should not be valid", id)
		}
	}
}

func TestDisplayNameFallsBackToHardware(t *testing.T) {
	h := &Host{Identifiers: []Identifier{{IDMAC, "aabbcc112233"}}}
	if h.Named() {
		t.Fatal("a host with only a MAC address is not named")
	}
	if got, want := h.DisplayName(), "MAC-AABBCC112233"; got != want {
		t.Errorf("DisplayName() = %q, want %q", got, want)
	}
}
