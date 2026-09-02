// Package importer applies a parsed scan result to the store: it decides which
// asset each result belongs to, resolves the controls each finding is evidence
// about, and writes the lot down as one import that can be undone in one step.
package importer

import (
	"fmt"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/store"
)

// Options controls how a result is applied.
type Options struct {
	// EnclaveID is where assets are placed when their address does not fall in
	// any enclave's network ranges. It is also the default for every asset when
	// PlaceByAddress is off.
	EnclaveID string
	// PlaceByAddress routes each asset to the enclave whose network range
	// contains its address, falling back to EnclaveID.
	PlaceByAddress bool
	// AssetID attaches every result in the file to one named asset, whatever
	// the file says the target was called. A STIG checklist often records a
	// hostname that does not match the inventory, and without this the import
	// would create a second record for a machine that is already tracked.
	// It overrides both asset matching and placement by address.
	AssetID string
	// CreateAssets allows the import to add assets it has not seen before.
	// Turning it off makes an import strictly additive to a curated inventory.
	CreateAssets bool
	// ImportedBy is recorded on the scan.
	ImportedBy string
	// Notes is free text recorded on the scan.
	Notes string
	// DefaultCriticality is applied to assets the import creates.
	DefaultCriticality model.Criticality
}

// Summary is what the import screen reports back.
type Summary struct {
	ScanID        string
	AssetsCreated int
	AssetsMatched int
	// Attached names the asset every result was pinned to, when the import was
	// told to attach to one.
	Attached        string
	FindingsAdded   int
	FindingsUpdated int
	Unmapped        int
	Placed          map[string]int
	Warnings        []string
}

// Importer applies results. It holds the registries so that findings are
// annotated with control references at the moment they are written, rather
// than every time a page is rendered.
type Importer struct {
	Store    *store.Store
	Catalogs *catalog.Registry
	Mappings *mapping.Registry
}

// New builds an importer.
func New(s *store.Store, cats *catalog.Registry, maps *mapping.Registry) *Importer {
	return &Importer{Store: s, Catalogs: cats, Mappings: maps}
}

// Apply writes a parsed result into the store.
func (im *Importer) Apply(res *ingest.Result, opts Options) (*Summary, error) {
	if res == nil || len(res.Hosts) == 0 {
		return nil, fmt.Errorf("there is nothing in this file to import")
	}
	if opts.EnclaveID == "" {
		return nil, fmt.Errorf("choose which enclave these results belong to")
	}
	if _, ok := im.Store.Enclave(opts.EnclaveID); !ok {
		return nil, fmt.Errorf("no enclave %q", opts.EnclaveID)
	}
	now := time.Now().UTC()
	sum := &Summary{Placed: map[string]int{}}

	scan := res.Scan
	scan.EnclaveID = opts.EnclaveID
	scan.ImportedAt = now
	scan.ImportedBy = opts.ImportedBy
	scan.Notes = opts.Notes
	if scan.ScanDate.IsZero() {
		scan.ScanDate = now
	}
	if err := im.Store.PutScan(&scan); err != nil {
		return nil, err
	}
	sum.ScanID = scan.ID

	counts := map[string]int{}
	var allFindings []*model.Finding

	// An import pinned to one asset resolves it once, so that a file describing
	// several targets cannot silently scatter results across the inventory.
	var pinned *model.Asset
	if opts.AssetID != "" {
		a, ok := im.Store.Asset(opts.AssetID)
		if !ok {
			return nil, fmt.Errorf("no asset %q to attach these results to", opts.AssetID)
		}
		pinned = a
		sum.Attached = a.DisplayName()
		if len(res.Hosts) > 1 {
			sum.Warnings = append(sum.Warnings, fmt.Sprintf(
				"the file describes %d targets and every one of them was attached to %s, because the import was pinned to that asset",
				len(res.Hosts), a.DisplayName()))
		}
	}

	for _, h := range res.Hosts {
		enclaveID := opts.EnclaveID
		switch {
		case pinned != nil:
			enclaveID = pinned.EnclaveID
		case opts.PlaceByAddress:
			for _, ip := range h.IPs {
				if e, ok := im.Store.PlaceByAddress(ip); ok {
					enclaveID = e.ID
					break
				}
			}
		}
		sum.Placed[enclaveID]++

		asset, matched := pinned, pinned != nil
		if pinned == nil {
			asset, matched = im.Store.MatchAsset(enclaveID, h.Name, h.Serial, h.IPs)
		}
		if !matched {
			if !opts.CreateAssets {
				sum.Warnings = append(sum.Warnings, fmt.Sprintf(
					"%s is not in the inventory and new assets were not being created, so its %d results were skipped",
					displayName(h), len(h.Findings)))
				continue
			}
			asset = &model.Asset{
				EnclaveID:   enclaveID,
				Criticality: firstCriticality(opts.DefaultCriticality, model.CritModerate),
				Status:      "Active",
				FirstSeen:   scan.ScanDate,
			}
			sum.AssetsCreated++
		} else {
			sum.AssetsMatched++
		}

		if pinned != nil {
			// The inventory name is the one people know the machine by, so a
			// pinned import contributes platform detail and dates but never
			// renames the asset.
			h = withoutName(h)
		}
		applyHost(asset, h, enclaveID, scan.ScanDate)
		if err := im.Store.PutAsset(asset); err != nil {
			sum.Warnings = append(sum.Warnings, fmt.Sprintf("%s: %v", displayName(h), err))
			continue
		}
		scan.AssetIDs = append(scan.AssetIDs, asset.ID)

		cats := im.enclaveCatalogs(enclaveID)
		for _, f := range h.Findings {
			f.EnclaveID = enclaveID
			f.AssetID = asset.ID
			f.ScanID = scan.ID
			if f.FirstSeen.IsZero() {
				f.FirstSeen = scan.ScanDate
			}
			if f.LastSeen.IsZero() {
				f.LastSeen = scan.ScanDate
			}
			f.Fingerprint = ingest.Fingerprint(asset.ID, f.RuleID, f.GroupID, f.Title)
			spreadDirectControlRefs(f, cats)
			im.Mappings.Annotate(f, cats)
			if len(f.ControlRefs) == 0 && f.Status.Counts() {
				sum.Unmapped++
			}
			counts[string(f.Severity.Normalise())]++
			if f.Status.Counts() {
				counts["open"]++
			}
			allFindings = append(allFindings, f)
		}
	}

	added, updated, err := im.Store.PutFindings(allFindings)
	if err != nil {
		return nil, err
	}
	sum.FindingsAdded, sum.FindingsUpdated = added, updated

	scan.AssetIDs = model.Dedup(scan.AssetIDs)
	scan.Counts = counts
	if err := im.Store.PutScan(&scan); err != nil {
		return nil, err
	}
	return sum, nil
}

// applyHost merges what a scan observed onto an asset record. A value the scan
// supplies fills a blank field but never overwrites one a person has set, apart
// from the last-seen date and the address list, which the scan is authoritative
// about.
func applyHost(a *model.Asset, h *ingest.Host, enclaveID string, seen time.Time) {
	a.EnclaveID = enclaveID
	fill(&a.Name, h.Name)
	fill(&a.FQDN, h.FQDN)
	fill(&a.OS, h.OS)
	fill(&a.OSVersion, h.OSVersion)
	fill(&a.Vendor, h.Vendor)
	fill(&a.Model, h.Model)
	fill(&a.Role, h.Role)
	if !store.Placeholder(h.Serial) {
		fill(&a.Serial, h.Serial)
	}
	if a.Type == "" || a.Type == model.AssetOther {
		if h.Type != "" {
			a.Type = h.Type
		}
	}
	a.IPs = model.Dedup(append(a.IPs, h.IPs...))
	a.MACs = model.Dedup(append(a.MACs, h.MACs...))
	if a.LastSeen == nil || a.LastSeen.Before(seen) {
		t := seen
		a.LastSeen = &t
	}
	if a.FirstSeen.IsZero() || seen.Before(a.FirstSeen) {
		a.FirstSeen = seen
	}
}

func fill(dst *string, v string) {
	if strings.TrimSpace(*dst) == "" && strings.TrimSpace(v) != "" {
		*dst = strings.TrimSpace(v)
	}
}

// spreadDirectControlRefs takes the control identifiers a CSV import recorded
// under the reserved empty key and files them under every catalogue that
// actually contains them. A spreadsheet that says "AC-2" does not say which
// framework it means, so the answer is "whichever ones have an AC-2".
func spreadDirectControlRefs(f *model.Finding, cats []*catalog.Catalog) {
	direct, ok := f.ControlRefs[""]
	if !ok {
		return
	}
	delete(f.ControlRefs, "")
	for _, cat := range cats {
		var hits []string
		for _, id := range direct {
			if cat.Has(id) {
				hits = append(hits, id)
			} else if base := catalog.BaseID(id); cat.Has(base) {
				hits = append(hits, base)
			}
		}
		if len(hits) > 0 {
			f.ControlRefs[cat.ID] = model.Dedup(append(f.ControlRefs[cat.ID], hits...))
		}
	}
	if len(f.ControlRefs) == 0 {
		f.ControlRefs = nil
	}
}

// enclaveCatalogs is the set of catalogues an enclave is measured against. An
// enclave with no baseline assigned still gets its findings mapped against
// every loaded catalogue, so that assigning a baseline later shows results
// immediately instead of requiring a re-import.
func (im *Importer) enclaveCatalogs(enclaveID string) []*catalog.Catalog {
	e, ok := im.Store.Enclave(enclaveID)
	if !ok || len(e.Baselines) == 0 {
		return im.Catalogs.All()
	}
	out := make([]*catalog.Catalog, 0, len(e.Baselines))
	seen := map[string]bool{}
	for _, b := range e.Baselines {
		if seen[b.CatalogID] {
			continue
		}
		seen[b.CatalogID] = true
		if c, ok := im.Catalogs.Get(b.CatalogID); ok {
			out = append(out, c)
		}
	}
	return out
}

// Reannotate recomputes control references for every finding in an enclave. It
// is run after a mapping table or a baseline changes, so that evidence appears
// without anyone having to import the same file twice.
func (im *Importer) Reannotate(enclaveID string) (int, error) {
	findings := im.Store.Findings(enclaveID)
	cats := im.Catalogs.All()
	changed := 0
	for _, f := range findings {
		before := len(f.ControlRefs)
		f.ControlRefs = nil
		im.Mappings.Annotate(f, cats)
		if len(f.ControlRefs) != before {
			changed++
		}
	}
	if _, _, err := im.Store.PutFindings(findings); err != nil {
		return 0, err
	}
	return changed, nil
}

// withoutName copies a parsed host with its identifying fields cleared, so an
// import pinned to a chosen asset cannot overwrite the name that asset is known
// by in the inventory.
func withoutName(h *ingest.Host) *ingest.Host {
	cp := *h
	cp.Name, cp.FQDN = "", ""
	return &cp
}

func displayName(h *ingest.Host) string {
	if h.Name != "" {
		return h.Name
	}
	if len(h.IPs) > 0 {
		return h.IPs[0]
	}
	return "an unnamed target"
}

func firstCriticality(vals ...model.Criticality) model.Criticality {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return model.CritModerate
}
