package resolve

import (
	"testing"
	"time"

	"github.com/pkittelson/enclave/internal/model"
)

func obs(source, kind string, at time.Time, ids []model.Identifier, fields map[string]string) model.Observation {
	return model.Observation{
		Identifiers: ids,
		Fields:      fields,
		SourceID:    source,
		SourceKind:  kind,
		CollectedAt: at,
	}
}

func TestMergesTransitivelyAcrossIdentifiers(t *testing.T) {
	now := time.Now()
	r := New(DefaultConfig())
	// The EDR knows the name and the serial.
	r.Add(obs("falcon", string(KindEDR), now, []model.Identifier{
		{Kind: model.IDHostname, Value: "WKS-014"},
		{Kind: model.IDSerial, Value: "5CG8241LM"},
	}, map[string]string{model.FieldOS: "Windows 11"}))
	// The asset database knows the serial and an asset tag, but not the name.
	r.Add(obs("snow", string(KindCMDB), now, []model.Identifier{
		{Kind: model.IDSerial, Value: "5cg-8241-lm"},
		{Kind: model.IDAssetTag, Value: "A-4471"},
	}, map[string]string{model.FieldOwner: "D. Rennick"}))
	// Address management knows only the asset tag.
	r.Add(obs("ipam", string(KindIPAM), now, []model.Identifier{
		{Kind: model.IDAssetTag, Value: "a4471"},
	}, map[string]string{model.FieldIP: "10.12.1.20"}))

	hosts := r.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 merged host", len(hosts))
	}
	h := hosts[0]
	if h.Field(model.FieldOwner) != "D. Rennick" || h.Field(model.FieldIP) != "10.12.1.20" {
		t.Errorf("fields did not merge: %+v", h.Fields)
	}
	if len(h.Sources) != 3 {
		t.Errorf("sources = %v, want all three", h.Sources)
	}
}

func TestMoreAuthoritativeFeedWinsAndLoserIsKept(t *testing.T) {
	now := time.Now()
	r := New(DefaultConfig())
	ids := []model.Identifier{{Kind: model.IDHostname, Value: "SRV-DB-02"}}
	// The CMDB is stale about the operating system.
	r.Add(obs("snow", string(KindCMDB), now, ids, map[string]string{model.FieldOS: "Windows Server 2016"}))
	// The agent on the box knows better, even though it reported first.
	r.Add(obs("falcon", string(KindEDR), now.Add(-time.Hour), ids, map[string]string{model.FieldOS: "Windows Server 2022"}))

	h := r.Hosts()[0]
	got := h.Fields[model.FieldOS]
	if got.Value != "Windows Server 2022" {
		t.Errorf("winner = %q, want the EDR's value", got.Value)
	}
	if got.Source != "falcon" {
		t.Errorf("attribution = %q, want falcon", got.Source)
	}
	if len(got.Conflicts) != 1 || got.Conflicts[0].Value != "Windows Server 2016" {
		t.Errorf("the rejected value must be kept, got %+v", got.Conflicts)
	}
}

func TestUnmergeableIdentifiersDoNotCollapseHosts(t *testing.T) {
	now := time.Now()
	r := New(DefaultConfig())
	for _, name := range []string{"To Be Filled By O.E.M.", "To Be Filled By O.E.M."} {
		r.Add(obs("bios-dump", string(KindCMDB), now, []model.Identifier{
			{Kind: model.IDSerial, Value: name},
		}, map[string]string{model.FieldOS: "Windows 10"}))
	}
	if got := len(r.Hosts()); got != 2 {
		t.Errorf("got %d hosts, want 2: a placeholder serial must not merge machines", got)
	}
}

func TestAgreementKeepsOneValue(t *testing.T) {
	now := time.Now()
	r := New(DefaultConfig())
	ids := []model.Identifier{{Kind: model.IDHostname, Value: "WKS-014"}}
	r.Add(obs("falcon", string(KindEDR), now, ids, map[string]string{model.FieldOS: "Windows 11"}))
	r.Add(obs("intune", string(KindEndpointMgmt), now, ids, map[string]string{model.FieldOS: "windows 11"}))

	if got := r.Hosts()[0].Fields[model.FieldOS]; len(got.Conflicts) != 0 {
		t.Errorf("case-only difference is agreement, got conflicts %+v", got.Conflicts)
	}
}
