package store

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// ---------- enclaves ----------

// Enclaves returns every enclave, ordered by name.
func (s *Store) Enclaves() []*model.Enclave {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Enclave, 0, len(s.enclaves))
	for _, e := range s.enclaves {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// Enclave looks one up by identifier.
func (s *Store) Enclave(id string) (*model.Enclave, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.enclaves[id]
	return e, ok
}

// PutEnclave creates or replaces an enclave.
func (s *Store) PutEnclave(e *model.Enclave) error {
	if err := e.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if prev, ok := s.enclaves[e.ID]; ok {
		e.Created = prev.Created
	} else if e.Created.IsZero() {
		e.Created = now
	}
	e.Updated = now
	s.enclaves[e.ID] = e
	s.dirty["enclaves"] = true
	return s.saveLocked()
}

// DeleteEnclave removes an enclave and everything recorded against it. It is
// the one destructive operation in the store, so it is explicit about scope.
func (s *Store) DeleteEnclave(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.enclaves[id]; !ok {
		return fmt.Errorf("no enclave %q", id)
	}
	delete(s.enclaves, id)
	for aid, a := range s.assets {
		if a.EnclaveID == id {
			delete(s.assets, aid)
		}
	}
	for fid, f := range s.findings {
		if f.EnclaveID == id {
			delete(s.fingerprints, f.Fingerprint)
			delete(s.findings, fid)
		}
	}
	for sid, sc := range s.scans {
		if sc.EnclaveID == id {
			delete(s.scans, sid)
		}
	}
	for k, a := range s.assessments {
		if a.EnclaveID == id {
			delete(s.assessments, k)
		}
	}
	for rid, r := range s.risks {
		if r.EnclaveID == id {
			delete(s.risks, rid)
		}
	}
	s.reindexLocked()
	for _, c := range []string{"enclaves", "assets", "scans", "findings", "assessments", "risks"} {
		s.dirty[c] = true
	}
	return s.saveLocked()
}

func (s *Store) reindexLocked() {
	s.findingsByAsset = map[string][]string{}
	s.findingsByEnclave = map[string][]string{}
	s.assetsByEnclave = map[string][]string{}
	s.assetEnclave = map[string]string{}
	for _, a := range s.assets {
		s.assetsByEnclave[a.EnclaveID] = append(s.assetsByEnclave[a.EnclaveID], a.ID)
		s.assetEnclave[a.ID] = a.EnclaveID
	}
	for _, f := range s.findings {
		s.indexFinding(f)
	}
}

// PlaceByAddress finds the enclave whose network range most specifically
// contains the address. Longest prefix wins, so a management VLAN carved out
// of a larger site range takes precedence over the site.
func (s *Store) PlaceByAddress(addr string) (*model.Enclave, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *model.Enclave
	bestBits := -1
	for _, e := range s.enclaves {
		for _, p := range e.Prefixes() {
			if p.Contains(ip) && p.Bits() > bestBits {
				best, bestBits = e, p.Bits()
			}
		}
	}
	return best, best != nil
}

// ---------- assets ----------

// Assets returns the assets of one enclave, ordered by name.
func (s *Store) Assets(enclaveID string) []*model.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.assetsByEnclave[enclaveID]
	out := make([]*model.Asset, 0, len(ids))
	for _, id := range ids {
		if a, ok := s.assets[id]; ok {
			out = append(out, a)
		}
	}
	sortAssets(out)
	return out
}

// AllAssets returns every asset in the store.
func (s *Store) AllAssets() []*model.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Asset, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, a)
	}
	sortAssets(out)
	return out
}

func sortAssets(out []*model.Asset) {
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].DisplayName()) < strings.ToLower(out[j].DisplayName())
	})
}

// Asset looks one up by identifier.
func (s *Store) Asset(id string) (*model.Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	return a, ok
}

// PutAsset creates or replaces an asset.
func (s *Store) PutAsset(a *model.Asset) error {
	if err := a.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putAssetLocked(a)
}

func (s *Store) putAssetLocked(a *model.Asset) error {
	now := time.Now().UTC()
	if a.ID == "" {
		a.ID = s.NextID("asset")
	}
	prev, existed := s.assets[a.ID]
	if existed {
		a.Created = prev.Created
		if a.FirstSeen.IsZero() {
			a.FirstSeen = prev.FirstSeen
		}
	} else {
		if a.Created.IsZero() {
			a.Created = now
		}
		if a.FirstSeen.IsZero() {
			a.FirstSeen = now
		}
	}
	a.Updated = now
	a.IPs = model.Dedup(a.IPs)
	a.MACs = model.Dedup(a.MACs)
	if filed, ok := s.assetEnclave[a.ID]; ok && filed != a.EnclaveID {
		s.assetsByEnclave[filed] = removeString(s.assetsByEnclave[filed], a.ID)
		delete(s.assetEnclave, a.ID)
	}
	_, indexed := s.assetEnclave[a.ID]
	s.assets[a.ID] = a
	if !indexed {
		s.assetsByEnclave[a.EnclaveID] = append(s.assetsByEnclave[a.EnclaveID], a.ID)
		s.assetEnclave[a.ID] = a.EnclaveID
	}
	s.dirty["assets"] = true
	return s.saveLocked()
}

// DeleteAsset removes an asset and the findings recorded against it.
func (s *Store) DeleteAsset(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok {
		return fmt.Errorf("no asset %q", id)
	}
	delete(s.assets, id)
	s.assetsByEnclave[a.EnclaveID] = removeString(s.assetsByEnclave[a.EnclaveID], id)
	delete(s.assetEnclave, id)
	for fid, f := range s.findings {
		if f.AssetID == id {
			delete(s.fingerprints, f.Fingerprint)
			delete(s.findings, fid)
		}
	}
	s.reindexLocked()
	s.dirty["assets"], s.dirty["findings"] = true, true
	return s.saveLocked()
}

// MatchAsset finds an existing asset that an incoming scan record refers to.
// Identity is established on serial number, then hostname, then address, in
// that order, because that is the order of how reliably each one identifies a
// machine across tools.
func (s *Store) MatchAsset(enclaveID, name, serial string, ips []string) (*model.Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidates := s.assetsByEnclave[enclaveID]
	norm := func(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
	serial, name = norm(serial), norm(strings.SplitN(name, ".", 2)[0])

	if serial != "" && !placeholder(serial) {
		for _, id := range candidates {
			if a := s.assets[id]; a != nil && norm(a.Serial) == serial {
				return a, true
			}
		}
	}
	if name != "" {
		for _, id := range candidates {
			a := s.assets[id]
			if a == nil {
				continue
			}
			if norm(strings.SplitN(a.Name, ".", 2)[0]) == name {
				return a, true
			}
		}
	}
	for _, ip := range ips {
		ip = norm(ip)
		if ip == "" {
			continue
		}
		for _, id := range candidates {
			a := s.assets[id]
			if a == nil {
				continue
			}
			for _, have := range a.IPs {
				if norm(have) == ip {
					return a, true
				}
			}
		}
	}
	return nil, false
}

// placeholder rejects the values tools write when they do not know an answer.
// Merging on one of these collapses an entire estate into a single asset.
var placeholders = map[string]bool{
	"unknown": true, "n/a": true, "na": true, "none": true, "null": true,
	"not specified": true, "to be filled by o.e.m.": true, "system serial number": true,
	"default string": true, "0": true, "000000": true, "-": true, "not available": true,
	"invalid": true, "chassis serial number": true, "empty": true,
}

func placeholder(v string) bool { return placeholders[strings.ToLower(strings.TrimSpace(v))] }

// Placeholder is the exported form, used by the ingest layer.
func Placeholder(v string) bool { return placeholder(v) }

// ---------- scans ----------

// Scans returns the scans of one enclave, most recently imported first. An
// empty enclave identifier returns every scan.
func (s *Store) Scans(enclaveID string) []*model.Scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Scan{}
	for _, sc := range s.scans {
		if enclaveID == "" || sc.EnclaveID == enclaveID {
			out = append(out, sc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ImportedAt.After(out[j].ImportedAt) })
	return out
}

// Scan looks one up by identifier.
func (s *Store) Scan(id string) (*model.Scan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.scans[id]
	return sc, ok
}

// DeleteScan removes a scan and every finding it produced, which is the
// correct way to undo a mistaken import.
func (s *Store) DeleteScan(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.scans[id]; !ok {
		return fmt.Errorf("no scan %q", id)
	}
	delete(s.scans, id)
	for fid, f := range s.findings {
		if f.ScanID == id {
			delete(s.fingerprints, f.Fingerprint)
			delete(s.findings, fid)
		}
	}
	s.reindexLocked()
	s.dirty["scans"], s.dirty["findings"] = true, true
	return s.saveLocked()
}

// ---------- findings ----------

// Findings returns every finding in an enclave. An empty identifier returns
// all of them.
func (s *Store) Findings(enclaveID string) []*model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*model.Finding
	if enclaveID == "" {
		out = make([]*model.Finding, 0, len(s.findings))
		for _, f := range s.findings {
			out = append(out, f)
		}
	} else {
		ids := s.findingsByEnclave[enclaveID]
		out = make([]*model.Finding, 0, len(ids))
		for _, id := range ids {
			if f, ok := s.findings[id]; ok {
				out = append(out, f)
			}
		}
	}
	sortFindings(out)
	return out
}

// AssetFindings returns the findings recorded against one asset.
func (s *Store) AssetFindings(assetID string) []*model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.findingsByAsset[assetID]
	out := make([]*model.Finding, 0, len(ids))
	for _, id := range ids {
		if f, ok := s.findings[id]; ok {
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// ScanFindings returns the findings one import produced.
func (s *Store) ScanFindings(scanID string) []*model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Finding{}
	for _, f := range s.findings {
		if f.ScanID == scanID {
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// sortFindings puts the worst live findings first, which is the order every
// page wants.
func sortFindings(out []*model.Finding) {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Live() != b.Live() {
			return a.Live()
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if !a.FirstSeen.Equal(b.FirstSeen) {
			return a.FirstSeen.Before(b.FirstSeen)
		}
		return a.ID < b.ID
	})
}

// Finding looks one up by identifier.
func (s *Store) Finding(id string) (*model.Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.findings[id]
	return f, ok
}

// PutFinding writes a finding, merging with any existing one that shares its
// fingerprint. A re-import updates last-seen, status and scanner text while
// leaving the first-seen date and every human decision untouched, which is what
// makes finding age meaningful across repeated scans.
func (s *Store) PutFinding(f *model.Finding) (*model.Finding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	merged, isNew := s.putFindingLocked(f)
	s.dirty["findings"] = true
	return merged, isNew, s.saveLocked()
}

// PutFindings writes many findings in one save, which matters when an import
// carries tens of thousands of rows.
func (s *Store) PutFindings(fs []*model.Finding) (added, updated int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range fs {
		if _, isNew := s.putFindingLocked(f); isNew {
			added++
		} else {
			updated++
		}
	}
	s.dirty["findings"] = true
	return added, updated, s.saveLocked()
}

func (s *Store) putFindingLocked(f *model.Finding) (*model.Finding, bool) {
	now := time.Now().UTC()
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = now
	}
	if f.Disposition == "" {
		f.Disposition = model.DispositionOpen
	}
	if existingID, ok := s.fingerprints[f.Fingerprint]; ok && f.Fingerprint != "" {
		if prev, ok := s.findings[existingID]; ok {
			if prev == f {
				// Re-annotation hands back the stored record itself. There is
				// nothing to merge, and the auto-close rule below must not fire.
				return prev, false
			}
			prev.LastSeen = f.LastSeen
			prev.ScanID = f.ScanID
			prev.Status = f.Status
			prev.Severity = f.Severity
			prev.RawSeverity = f.RawSeverity
			prev.Title = f.Title
			prev.Description = f.Description
			prev.CheckText = f.CheckText
			prev.FixText = f.FixText
			prev.FindingDetails = f.FindingDetails
			prev.CCIs = f.CCIs
			prev.CVEs = f.CVEs
			prev.References = f.References
			prev.ControlRefs = f.ControlRefs
			prev.CVSS = f.CVSS
			prev.CVSSVector = f.CVSSVector
			prev.Port, prev.Protocol, prev.Service = f.Port, f.Protocol, f.Service
			// A finding the scanner now reports as fixed closes automatically,
			// but only if nobody has recorded a different decision.
			if !f.Status.Counts() && prev.Disposition == model.DispositionOpen {
				prev.Disposition = model.DispositionRemediated
				prev.DispositionNote = "Closed automatically: the scanner no longer reports this."
				prev.DispositionAt = &now
			}
			return prev, false
		}
	}
	if f.ID == "" {
		f.ID = s.NextID("f")
	}
	s.findings[f.ID] = f
	s.indexFinding(f)
	return f, true
}

// SetDisposition records a human decision about a finding.
func (s *Store) SetDisposition(id string, d model.Disposition, note, by string, due *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.findings[id]
	if !ok {
		return fmt.Errorf("no finding %q", id)
	}
	now := time.Now().UTC()
	f.Disposition, f.DispositionNote, f.DispositionBy, f.DispositionAt = d, note, by, &now
	f.DueDate = due
	s.dirty["findings"] = true
	return s.saveLocked()
}

// ---------- assessments ----------

// Assessments returns every control assessment for an enclave, keyed by
// catalogue and control identifier.
func (s *Store) Assessments(enclaveID string) map[string]*model.Assessment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]*model.Assessment{}
	for _, a := range s.assessments {
		if a.EnclaveID == enclaveID {
			out[a.CatalogID+"|"+a.ControlID] = a
		}
	}
	return out
}

// Assessment looks one up.
func (s *Store) Assessment(enclaveID, catalogID, controlID string) (*model.Assessment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assessments[enclaveID+"|"+catalogID+"|"+controlID]
	return a, ok
}

// PutAssessment records a control assessment.
func (s *Store) PutAssessment(a *model.Assessment) error {
	if a.EnclaveID == "" || a.CatalogID == "" || a.ControlID == "" {
		return fmt.Errorf("an assessment needs an enclave, a catalog and a control")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == "" {
		a.ID = s.NextID("as")
	}
	a.Updated = time.Now().UTC()
	s.assessments[a.Key()] = a
	s.dirty["assessments"] = true
	return s.saveLocked()
}

// ---------- risk entries ----------

// Risks returns the risk register for an enclave, worst first. An empty
// identifier returns every entry.
func (s *Store) Risks(enclaveID string) []*model.RiskEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.RiskEntry{}
	for _, r := range s.risks {
		if enclaveID == "" || r.EnclaveID == enclaveID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Open() != b.Open() {
			return a.Open()
		}
		if a.Score() != b.Score() {
			return a.Score() > b.Score()
		}
		return a.Detected.Before(b.Detected)
	})
	return out
}

// Risk looks one up by identifier.
func (s *Store) Risk(id string) (*model.RiskEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.risks[id]
	return r, ok
}

// PutRisk creates or replaces a risk entry.
func (s *Store) PutRisk(r *model.RiskEntry) error {
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("a risk entry needs a title")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = s.NextID("risk")
	}
	if r.Detected.IsZero() {
		r.Detected = time.Now().UTC()
	}
	if r.Status == "" {
		r.Status = "open"
	}
	r.Updated = time.Now().UTC()
	s.risks[r.ID] = r
	s.dirty["risks"] = true
	return s.saveLocked()
}

// DeleteRisk removes a risk entry.
func (s *Store) DeleteRisk(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.risks[id]; !ok {
		return fmt.Errorf("no risk entry %q", id)
	}
	delete(s.risks, id)
	s.dirty["risks"] = true
	return s.saveLocked()
}

// ---------- scans, written last so they can count their findings ----------

// PutScan records an import.
func (s *Store) PutScan(sc *model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sc.ID == "" {
		sc.ID = s.NextID("scan")
	}
	if sc.ImportedAt.IsZero() {
		sc.ImportedAt = time.Now().UTC()
	}
	s.scans[sc.ID] = sc
	s.dirty["scans"] = true
	return s.saveLocked()
}

func removeString(in []string, v string) []string {
	out := in[:0]
	for _, s := range in {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

// Counts is a summary of the whole store, used on the dashboard.
type Counts struct {
	Enclaves, Assets, Findings, OpenFindings, Scans, Risks, OpenRisks int
}

// Counts summarises the store.
func (s *Store) Counts() Counts {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := Counts{
		Enclaves: len(s.enclaves), Assets: len(s.assets),
		Findings: len(s.findings), Scans: len(s.scans), Risks: len(s.risks),
	}
	for _, f := range s.findings {
		if f.Live() {
			c.OpenFindings++
		}
	}
	for _, r := range s.risks {
		if r.Open() {
			c.OpenRisks++
		}
	}
	return c
}
