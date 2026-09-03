package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

func (s *Server) handleAssetList(w http.ResponseWriter, r *http.Request) {
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	now := time.Now()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	wantType := r.URL.Query().Get("type")
	wantCrit := r.URL.Query().Get("criticality")

	findings := map[string][]*model.Finding{}
	for _, f := range s.Store.Findings(e.ID) {
		findings[f.AssetID] = append(findings[f.AssetID], f)
	}

	type row struct {
		Asset *model.Asset
		// Open is work outstanding; Accepted is live but deliberately accepted.
		Open     int
		Accepted int
		Worst    model.Severity
		Score    float64
		Stale    bool
		LastSeen *time.Time
	}
	rows := []row{}
	byType := map[string]int{}
	for _, a := range s.Store.Assets(e.ID) {
		byType[a.Type.Label()]++
		if wantType != "" && string(a.Type) != wantType {
			continue
		}
		if wantCrit != "" && string(a.Criticality) != wantCrit {
			continue
		}
		if q != "" && !assetMatches(a, q) {
			continue
		}
		rw := row{Asset: a, Worst: model.SeverityInfo, Stale: a.Stale(now, risk.StaleAfter), LastSeen: a.LastSeen}
		for _, f := range findings[a.ID] {
			if !f.Live() {
				continue
			}
			if f.Accepted() {
				rw.Accepted++
			} else {
				rw.Open++
			}
			rw.Score += risk.FindingScore(f, a, now)
			if f.Severity.Rank() > rw.Worst.Rank() {
				rw.Worst = f.Severity.Normalise()
			}
		}
		rows = append(rows, rw)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return strings.ToLower(rows[i].Asset.DisplayName()) < strings.ToLower(rows[j].Asset.DisplayName())
	})

	s.render(w, r, "assets.html", page{
		Title: "Assets · " + e.Name, Nav: "enclaves", SubNav: "assets", Enclave: e,
		Data: map[string]any{
			"Rows": rows, "Query": r.URL.Query().Get("q"),
			"Type": wantType, "Criticality": wantCrit,
			"ByType": byType, "TypeOrder": sortedKeys(byType),
			"Total": len(rows),
		},
	})
}

func assetMatches(a *model.Asset, q string) bool {
	hay := strings.ToLower(strings.Join([]string{
		a.Name, a.FQDN, a.OS, a.OSVersion, a.Vendor, a.Model, a.Role,
		a.Owner, a.Location, a.Serial, strings.Join(a.IPs, " "),
		strings.Join(a.MACs, " "), strings.Join(a.Tags, " "),
	}, " "))
	for _, term := range strings.Fields(q) {
		if !strings.Contains(hay, term) {
			return false
		}
	}
	return true
}

func (s *Server) handleAssetDetail(w http.ResponseWriter, r *http.Request) {
	a, ok := s.Store.Asset(r.PathValue("aid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No asset with that identifier.")
		return
	}
	e, _ := s.Store.Enclave(a.EnclaveID)
	now := time.Now()
	findings := s.Store.AssetFindings(a.ID)

	counts := map[model.Severity]int{}
	score := 0.0
	outstanding, accepted := 0, 0
	for _, f := range findings {
		if !f.Live() {
			continue
		}
		counts[f.Severity.Normalise()]++
		score += risk.FindingScore(f, a, now)
		if f.Accepted() {
			accepted++
		} else {
			outstanding++
		}
	}

	// Which controls this asset's own findings speak to, per assigned baseline.
	type controlHit struct {
		Catalog string
		Control string
		Title   string
		Open    int
	}
	hits := []controlHit{}
	if e != nil {
		for _, b := range e.Baselines {
			cat := s.Catalogs.MustGet(b.CatalogID)
			tally := map[string]int{}
			for _, f := range findings {
				if !f.Live() {
					continue
				}
				for _, id := range f.Controls(cat.ID) {
					tally[id]++
				}
			}
			for _, id := range sortedKeys(tally) {
				ctl, _ := cat.Control(id)
				hits = append(hits, controlHit{Catalog: cat.Name, Control: id, Title: ctl.Title, Open: tally[id]})
			}
		}
	}

	scans := []*model.Scan{}
	for _, sc := range s.Store.Scans(a.EnclaveID) {
		for _, id := range sc.AssetIDs {
			if id == a.ID {
				scans = append(scans, sc)
				break
			}
		}
	}

	s.render(w, r, "asset.html", page{
		Title: a.DisplayName(), Nav: "enclaves", SubNav: "assets", Enclave: e,
		Data: map[string]any{
			"Asset": a, "Findings": findings, "Score": score,
			"Outstanding": outstanding, "Accepted": accepted,
			"Severity": donut(countsBySeverity(counts), severityOrder, severityClasses),
			"Counts":   counts, "Controls": hits, "Scans": firstN(scans, 10),
			"Stale": a.Stale(now, risk.StaleAfter),
		},
	})
}

func (s *Server) handleAssetForm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	var (
		a *model.Asset
		e *model.Enclave
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
		a = &model.Asset{EnclaveID: e.ID, Type: model.AssetServer, Criticality: model.CritModerate, Status: "Active"}
	}
	title := "New asset"
	if a.ID != "" {
		title = "Edit " + a.DisplayName()
	}
	s.render(w, r, "asset_form.html", page{
		Title: title, Nav: "enclaves", SubNav: "assets", Enclave: e,
		Data: map[string]any{"Asset": a, "IsNew": a.ID == "", "Enclaves": s.Store.Enclaves()},
	})
}

func (s *Server) handleAssetSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	a := &model.Asset{}
	if aid := r.PathValue("aid"); aid != "" {
		prev, ok := s.Store.Asset(aid)
		if !ok {
			s.fail(w, r, http.StatusNotFound, "No asset with that identifier.")
			return
		}
		cp := *prev
		a = &cp
	} else {
		a.EnclaveID = r.PathValue("id")
	}
	if v := f.str("enclave_id"); v != "" {
		a.EnclaveID = v
	}
	// Filing an asset under an enclave that is not there makes it invisible on
	// every page, so it is refused rather than accepted and later hunted down.
	if _, ok := s.Store.Enclave(a.EnclaveID); !ok {
		e, _ := s.Store.Enclave(r.PathValue("id"))
		s.render(w, r, "asset_form.html", page{
			Title: "Asset", Nav: "enclaves", SubNav: "assets", Enclave: e,
			Error: "There is no enclave called " + a.EnclaveID + ". Choose one that exists.",
			Data:  map[string]any{"Asset": a, "IsNew": a.ID == "", "Enclaves": s.Store.Enclaves()},
		})
		return
	}
	a.Name = f.str("name")
	a.FQDN = f.str("fqdn")
	a.Type = model.AssetType(f.str("type"))
	a.Role = f.str("role")
	a.Criticality = model.Criticality(f.str("criticality"))
	a.OS = f.str("os")
	a.OSVersion = f.str("os_version")
	a.Vendor = f.str("vendor")
	a.Model = f.str("model")
	a.Firmware = f.str("firmware")
	a.Serial = f.str("serial")
	a.IPs = f.csv("ips")
	a.MACs = f.csv("macs")
	a.Owner = f.str("owner")
	a.Location = f.str("location")
	a.Status = f.str("status")
	a.Notes = f.str("notes")
	a.Tags = f.csv("tags")

	if err := s.Store.PutAsset(a); err != nil {
		e, _ := s.Store.Enclave(a.EnclaveID)
		s.render(w, r, "asset_form.html", page{
			Title: "Asset", Nav: "enclaves", SubNav: "assets", Enclave: e, Error: err.Error(),
			Data: map[string]any{"Asset": a, "IsNew": a.ID == "", "Enclaves": s.Store.Enclaves()},
		})
		return
	}
	redirect(w, r, "/assets/"+a.ID, "Saved.", "")
}

func (s *Server) handleAssetDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	a, ok := s.Store.Asset(r.PathValue("aid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No asset with that identifier.")
		return
	}
	enclaveID := a.EnclaveID
	if err := s.Store.DeleteAsset(a.ID); err != nil {
		redirect(w, r, "/assets/"+a.ID, "", err.Error())
		return
	}
	redirect(w, r, "/enclaves/"+enclaveID+"/assets", "Removed "+a.DisplayName()+" and its findings.", "")
}
