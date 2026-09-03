package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/ingest"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

// handleVulnList answers the question a vulnerability manager asks, which is
// not "what is wrong with this host" but "where is this CVE and how bad is it
// for us". Findings are recorded per host; this is the other axis.
func (s *Server) handleVulnList(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	q := r.URL.Query()
	enclaveID := q.Get("enclave")
	rollups := risk.CVEs(s.Store.Findings(enclaveID), s.assetIndex(), now)

	text := strings.ToLower(strings.TrimSpace(q.Get("q")))
	severity := q.Get("severity")
	show := q.Get("show")
	if show == "" {
		show = "open"
	}
	filtered := make([]risk.CVERollup, 0, len(rollups))
	for _, c := range rollups {
		switch show {
		case "all":
		case "closed":
			if c.Live() {
				continue
			}
		case "overdue":
			if c.PastTarget == 0 {
				continue
			}
		default:
			if !c.Live() {
				continue
			}
		}
		if severity != "" && string(c.Severity.Normalise()) != severity {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(c.CVE+" "+c.Title), text) {
			continue
		}
		filtered = append(filtered, c)
	}

	const window = 500
	shown := filtered
	if len(shown) > window {
		shown = shown[:window]
	}
	s.render(w, r, "vulns.html", page{
		Title: "Vulnerabilities", Nav: "vulns",
		Data: map[string]any{
			"Rows": shown, "Total": len(filtered), "Truncated": len(filtered) > len(shown),
			"Window": window, "Summary": risk.Summarise(rollups),
			"Enclaves": s.Store.Enclaves(), "Enclave": enclaveID,
			"Query": q.Get("q"), "Severity": severity, "Show": show,
			"AssetIndex": s.assetIndex(), "EnclaveIndex": s.enclaveIndex(),
		},
	})
}

// handleVulnDetail shows every host one CVE was found on.
func (s *Server) handleVulnDetail(w http.ResponseWriter, r *http.Request) {
	cve := risk.NormaliseCVE(r.PathValue("cve"))
	if cve == "" {
		s.fail(w, r, http.StatusNotFound, "That is not a CVE identifier.")
		return
	}
	now := time.Now()
	assets := s.assetIndex()
	roll, ok := risk.FindCVE(s.Store.Findings(""), assets, cve, now)
	if !ok {
		s.fail(w, r, http.StatusNotFound, cve+" has not been recorded against anything here.")
		return
	}
	// Which controls the evidence reaches, so a CVE can be discussed in the
	// language of the baseline rather than only as a patch.
	type ref struct{ Catalog, Control, Title string }
	seen := map[string]bool{}
	refs := []ref{}
	for _, f := range roll.Findings {
		for _, catID := range sortedKeys(f.ControlRefs) {
			cat := s.Catalogs.MustGet(catID)
			for _, id := range f.ControlRefs[catID] {
				key := catID + "|" + id
				if seen[key] {
					continue
				}
				seen[key] = true
				ctl, _ := cat.Control(id)
				refs = append(refs, ref{Catalog: cat.Name, Control: id, Title: ctl.Title})
			}
		}
	}
	s.render(w, r, "vuln.html", page{
		Title: cve, Nav: "vulns",
		Data: map[string]any{
			"CVE": roll, "Refs": refs,
			"AssetIndex": assets, "EnclaveIndex": s.enclaveIndex(),
		},
	})
}

// ---------- recording a finding by hand ----------

// manualScanTitle names the import that hand-entered findings belong to, so
// they are traceable in exactly the same way scanner results are.
const manualScanTitle = "Recorded by hand"

func (s *Server) handleFindingForm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	var (
		e *model.Enclave
		a *model.Asset
	)
	if aid := r.PathValue("aid"); aid != "" {
		found, ok := s.Store.Asset(aid)
		if !ok {
			s.fail(w, r, http.StatusNotFound, "No asset with that identifier.")
			return
		}
		a = found
		e, _ = s.Store.Enclave(a.EnclaveID)
	} else {
		found, ok := s.Store.Enclave(r.PathValue("id"))
		if !ok {
			s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
			return
		}
		e = found
	}
	if e == nil {
		s.fail(w, r, http.StatusNotFound, "That asset is not in an enclave.")
		return
	}
	s.render(w, r, "finding_form.html", page{
		Title: "Record a finding", Nav: "enclaves", SubNav: "findings", Enclave: e,
		Data: map[string]any{
			"Asset": a, "Assets": s.Store.Assets(e.ID),
			"CVE": r.URL.Query().Get("cve"),
		},
	})
}

func (s *Server) handleFindingSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	enclaveID := r.PathValue("id")
	assetID := f.str("asset_id")
	if aid := r.PathValue("aid"); aid != "" {
		assetID = aid
	}
	asset, ok := s.Store.Asset(assetID)
	if !ok {
		redirect(w, r, "/enclaves/"+enclaveID+"/findings", "", "Choose which host this is about.")
		return
	}
	if enclaveID == "" {
		enclaveID = asset.EnclaveID
	}

	cves := []string{}
	var bad []string
	for _, raw := range f.csv("cves") {
		if id := risk.NormaliseCVE(raw); id != "" {
			cves = append(cves, id)
		} else {
			bad = append(bad, raw)
		}
	}
	if len(bad) > 0 {
		redirect(w, r, findingFormURL(asset), "",
			"Not a CVE identifier: "+strings.Join(bad, ", ")+". They look like CVE-2024-1086.")
		return
	}

	title := f.str("title")
	if title == "" && len(cves) > 0 {
		// A CVE on its own is a complete thought; the identifier is the title.
		title = strings.Join(cves, ", ")
	}
	if title == "" {
		redirect(w, r, findingFormURL(asset), "", "Give the finding a title, or at least one CVE.")
		return
	}

	cvss := 0.0
	if v := f.str("cvss"); v != "" {
		parsed, perr := strconv.ParseFloat(v, 64)
		if perr != nil || parsed < 0 || parsed > 10 {
			redirect(w, r, findingFormURL(asset), "", "A CVSS score is a number between 0 and 10.")
			return
		}
		cvss = parsed
	}

	severity := model.Severity(f.str("severity")).Normalise()
	if f.str("severity") == "" {
		if cvss > 0 {
			severity = model.SeverityFromCVSS(cvss)
		} else {
			severity = model.SeverityMedium
		}
	}

	now := time.Now().UTC()
	first := now
	if d := f.date("first_seen"); d != nil {
		first = *d
	}

	scan, err := s.manualScan(enclaveID, f.str("recorded_by"))
	if err != nil {
		redirect(w, r, findingFormURL(asset), "", err.Error())
		return
	}

	finding := &model.Finding{
		EnclaveID:   enclaveID,
		AssetID:     asset.ID,
		ScanID:      scan.ID,
		RuleID:      f.str("rule_id"),
		Title:       title,
		Severity:    severity,
		RawSeverity: f.str("severity"),
		Status:      model.StatusOpen,
		Description: f.str("description"),
		FixText:     f.str("fix"),
		Comments:    f.str("comments"),
		CVEs:        cves,
		CVSS:        cvss,
		CVSSVector:  f.str("cvss_vector"),
		Protocol:    f.str("protocol"),
		Port:        f.int("port", 0),
		Service:     f.str("service"),
		FirstSeen:   first,
		LastSeen:    now,
		DueDate:     f.date("due"),
		Disposition: model.DispositionOpen,
	}
	if v := f.str("status"); v != "" {
		finding.Status = model.FindingStatus(v).Normalise()
	}
	// A hand-entered finding is identified the same way a scanned one is, so
	// recording the same CVE for the same host twice updates rather than
	// duplicating, and a later scan that reports it merges with it.
	key := finding.RuleID
	if key == "" && len(cves) > 0 {
		key = cves[0]
	}
	finding.Fingerprint = ingest.Fingerprint(asset.ID, key, "", title)
	s.Mappings.Annotate(finding, s.Catalogs.All())

	stored, isNew, err := s.Store.PutFinding(finding)
	if err != nil {
		redirect(w, r, findingFormURL(asset), "", err.Error())
		return
	}
	// The asset has been reported on, so its last-seen date moves with it.
	if asset.LastSeen == nil || asset.LastSeen.Before(now) {
		t := now
		asset.LastSeen = &t
		_ = s.Store.PutAsset(asset)
	}
	msg := "Recorded against " + asset.DisplayName() + "."
	if !isNew {
		msg = "Updated the existing entry for this on " + asset.DisplayName() + "."
	}
	if len(stored.ControlRefs) == 0 {
		msg += " It reached no control, so it will not appear in the gap analysis."
	}
	redirect(w, r, "/findings/"+stored.ID, msg, "")
}

func findingFormURL(a *model.Asset) string { return "/assets/" + a.ID + "/findings/new" }

// manualScan finds or creates the import that hand-entered findings belong to.
// Everything in ENCLAVE hangs off an import, so that any finding can be traced
// to where it came from; typing one in is just another source.
func (s *Server) manualScan(enclaveID, by string) (*model.Scan, error) {
	for _, sc := range s.Store.Scans(enclaveID) {
		if sc.Format == "manual" {
			return sc, nil
		}
	}
	sc := &model.Scan{
		EnclaveID: enclaveID, Kind: "manual", Format: "manual",
		Title: manualScanTitle, Tool: "Entered in ENCLAVE",
		ImportedBy: by, ScanDate: time.Now().UTC(),
		Notes: "Findings typed in rather than imported from a scanner.",
	}
	if err := s.Store.PutScan(sc); err != nil {
		return nil, err
	}
	return sc, nil
}
