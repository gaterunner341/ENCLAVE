package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

func (s *Server) handleRiskList(w http.ResponseWriter, r *http.Request) {
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	now := time.Now()
	entries := s.Store.Risks(e.ID)
	show := r.URL.Query().Get("show")
	rows := []*model.RiskEntry{}
	for _, rr := range entries {
		if show == "closed" && rr.Open() {
			continue
		}
		if show != "closed" && show != "all" && !rr.Open() {
			continue
		}
		rows = append(rows, rr)
	}
	overdue := 0
	for _, rr := range entries {
		if rr.Overdue(now) {
			overdue++
		}
	}
	s.render(w, r, "risks.html", page{
		Title: "Risk register · " + e.Name, Nav: "enclaves", SubNav: "risk", Enclave: e,
		Data: map[string]any{
			"Rows": rows, "Matrix": risk.MatrixRows(entries),
			"Total": len(entries), "Overdue": overdue, "Show": show,
			"Catalogs": s.Catalogs.All(),
		},
	})
}

func (s *Server) handleRiskForm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	var (
		entry *model.RiskEntry
		e     *model.Enclave
	)
	if rid := r.PathValue("rid"); rid != "" {
		found, ok := s.Store.Risk(rid)
		if !ok {
			s.fail(w, r, http.StatusNotFound, "No risk entry with that identifier.")
			return
		}
		entry = found
		e, _ = s.Store.Enclave(entry.EnclaveID)
	} else {
		found, ok := s.Store.Enclave(r.PathValue("id"))
		if !ok {
			s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
			return
		}
		e = found
		entry = &model.RiskEntry{
			EnclaveID: e.ID, Likelihood: 3, Impact: 3,
			Status: "open", Source: "manual", Detected: time.Now().UTC(),
		}
		// A risk entry raised from a finding starts with that finding attached.
		if fid := r.URL.Query().Get("finding"); fid != "" {
			if f, ok := s.Store.Finding(fid); ok {
				entry.Title = f.Title
				entry.Weakness = f.Description
				entry.Mitigation = f.FixText
				entry.FindingIDs = []string{f.ID}
				entry.AssetIDs = []string{f.AssetID}
				entry.ControlRefs = f.ControlRefs
				entry.Source = "scan"
				entry.Impact = impactFromSeverity(f.Severity)
			}
		}
	}
	title := "New risk entry"
	if entry.ID != "" {
		title = "Edit risk entry"
	}
	s.render(w, r, "risk_form.html", page{
		Title: title, Nav: "enclaves", SubNav: "risk", Enclave: e,
		Data: map[string]any{
			"Entry": entry, "IsNew": entry.ID == "",
			"Assets": s.Store.Assets(e.ID), "Catalogs": s.Catalogs.All(),
		},
	})
}

func impactFromSeverity(sev model.Severity) int {
	switch sev.Normalise() {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	}
	return 1
}

func (s *Server) handleRiskSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	entry := &model.RiskEntry{}
	if rid := r.PathValue("rid"); rid != "" {
		prev, ok := s.Store.Risk(rid)
		if !ok {
			s.fail(w, r, http.StatusNotFound, "No risk entry with that identifier.")
			return
		}
		cp := *prev
		entry = &cp
	} else {
		entry.EnclaveID = r.PathValue("id")
	}
	entry.Title = f.str("title")
	entry.Weakness = f.str("weakness")
	entry.Source = f.str("source")
	entry.Likelihood = f.int("likelihood", 3)
	entry.Impact = f.int("impact", 3)
	entry.Status = f.str("status")
	entry.Owner = f.str("owner")
	entry.Mitigation = f.str("mitigation")
	entry.Resources = f.str("resources")
	entry.AssetIDs = f.list("asset_ids")
	entry.FindingIDs = f.csv("finding_ids")
	entry.Due = f.date("due")
	if d := f.date("detected"); d != nil {
		entry.Detected = *d
	}
	if entry.Status == "completed" || entry.Status == "closed" {
		if entry.Completed == nil {
			now := time.Now().UTC()
			entry.Completed = &now
		}
	} else {
		entry.Completed = nil
	}

	entry.ControlRefs = map[string][]string{}
	for _, cat := range s.Catalogs.All() {
		ids := []string{}
		for _, raw := range f.csv("controls_" + cat.ID) {
			if cat.Has(raw) {
				ids = append(ids, raw)
			}
		}
		if len(ids) > 0 {
			entry.ControlRefs[cat.ID] = ids
		}
	}

	entry.Milestones = nil
	descs := r.Form["milestone_description"]
	dues := r.Form["milestone_due"]
	for i, d := range descs {
		if strings.TrimSpace(d) == "" {
			continue
		}
		m := model.Milestone{Description: strings.TrimSpace(d)}
		if i < len(dues) && dues[i] != "" {
			if t, err := time.Parse("2006-01-02", dues[i]); err == nil {
				t = t.UTC()
				m.Due = &t
			}
		}
		entry.Milestones = append(entry.Milestones, m)
	}

	if err := s.Store.PutRisk(entry); err != nil {
		e, _ := s.Store.Enclave(entry.EnclaveID)
		s.render(w, r, "risk_form.html", page{
			Title: "Risk entry", Nav: "enclaves", SubNav: "risk", Enclave: e, Error: err.Error(),
			Data: map[string]any{
				"Entry": entry, "IsNew": entry.ID == "",
				"Assets": s.Store.Assets(entry.EnclaveID), "Catalogs": s.Catalogs.All(),
			},
		})
		return
	}
	redirect(w, r, "/enclaves/"+entry.EnclaveID+"/risk", "Saved.", "")
}

func (s *Server) handleRiskDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	entry, ok := s.Store.Risk(r.PathValue("rid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No risk entry with that identifier.")
		return
	}
	enclaveID := entry.EnclaveID
	if err := s.Store.DeleteRisk(entry.ID); err != nil {
		redirect(w, r, "/enclaves/"+enclaveID+"/risk", "", err.Error())
		return
	}
	redirect(w, r, "/enclaves/"+enclaveID+"/risk", "Removed the entry.", "")
}
