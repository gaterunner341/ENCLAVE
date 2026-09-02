package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

// handleGapAnalysis renders one baseline measured against one enclave: the
// page the whole tool exists to produce.
func (s *Server) handleGapAnalysis(w http.ResponseWriter, r *http.Request) {
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	if len(e.Baselines) == 0 {
		s.render(w, r, "baseline_empty.html", page{
			Title: "Baseline · " + e.Name, Nav: "enclaves", SubNav: "baseline", Enclave: e,
			Data: map[string]any{"Catalogs": s.Catalogs.All()},
		})
		return
	}
	// Which of the enclave's baselines is being shown.
	selected := e.Baselines[0]
	if want := r.URL.Query().Get("catalog"); want != "" {
		for _, b := range e.Baselines {
			if b.CatalogID == want {
				selected = b
			}
		}
	}
	cat := s.Catalogs.MustGet(selected.CatalogID)
	profile := selected.ProfileID
	if p := r.URL.Query().Get("profile"); p != "" {
		profile = p
	}

	now := time.Now()
	assets := s.Store.Assets(e.ID)
	findings := s.Store.Findings(e.ID)
	an := risk.Analyse(cat, profile, e, assets, findings, s.Store.Assessments(e.ID), now)

	wantState := r.URL.Query().Get("state")
	wantFamily := r.URL.Query().Get("family")
	families := an.Families
	if wantState != "" || wantFamily != "" {
		filtered := []risk.FamilyGap{}
		for _, fam := range families {
			if wantFamily != "" && fam.ID != wantFamily {
				continue
			}
			if wantState == "" {
				filtered = append(filtered, fam)
				continue
			}
			kept := risk.FamilyGap{ID: fam.ID, Name: fam.Name, Counts: fam.Counts}
			for _, g := range fam.Controls {
				if string(g.State) == wantState {
					kept.Controls = append(kept.Controls, g)
					kept.Total++
				}
			}
			if kept.Total > 0 {
				filtered = append(filtered, kept)
			}
		}
		families = filtered
	}

	s.render(w, r, "baseline.html", page{
		Title: cat.Name + " · " + e.Name, Nav: "enclaves", SubNav: "baseline", Enclave: e,
		Data: map[string]any{
			"Analysis": an, "Families": families, "Catalog": cat,
			"Profile": profile, "Selected": selected,
			"States": donut(countsByState(an.Counts), gapStateOrder(), gapStateClasses),
			"Worst":  an.Worst(12),
			"State":  wantState, "Family": wantFamily,
			"AssetIndex": s.assetIndex(),
		},
	})
}

func (s *Server) handleControlDetail(w http.ResponseWriter, r *http.Request) {
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	cat, ok := s.Catalogs.Get(r.PathValue("cat"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No catalog with that identifier.")
		return
	}
	controlID := r.PathValue("ctl")
	ctl, ok := cat.Control(controlID)
	if !ok {
		s.fail(w, r, http.StatusNotFound, cat.Name+" has no control "+controlID+".")
		return
	}
	now := time.Now()
	assessments := s.Store.Assessments(e.ID)
	an := risk.Analyse(cat, "", e, s.Store.Assets(e.ID), s.Store.Findings(e.ID), assessments, now)

	var gap risk.ControlGap
	for _, fam := range an.Families {
		for _, g := range fam.Controls {
			if catalog.NormaliseID(g.Control.ID) == catalog.NormaliseID(ctl.ID) {
				gap = g
			}
		}
	}
	assessment := assessments[cat.ID+"|"+ctl.ID]
	if assessment == nil {
		assessment = &model.Assessment{
			EnclaveID: e.ID, CatalogID: cat.ID, ControlID: ctl.ID,
			Status: model.ImplNotAssessed,
		}
	}

	// Related controls: the parent of an enhancement, and its siblings.
	related := []catalog.Control{}
	base := catalog.BaseID(ctl.ID)
	for _, c := range cat.FamilyControls(ctl.FamilyID, "") {
		if c.ID != ctl.ID && (catalog.BaseID(c.ID) == base) {
			related = append(related, c)
		}
	}

	s.render(w, r, "control.html", page{
		Title: ctl.ID + " · " + e.Name, Nav: "enclaves", SubNav: "baseline", Enclave: e,
		Data: map[string]any{
			"Catalog": cat, "Control": ctl, "Gap": gap,
			"Assessment": assessment, "Related": related,
			"AssetIndex": s.assetIndex(),
		},
	})
}

func (s *Server) handleAssessmentSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	cat, ok := s.Catalogs.Get(r.PathValue("cat"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No catalog with that identifier.")
		return
	}
	controlID := r.PathValue("ctl")
	if !cat.Has(controlID) {
		s.fail(w, r, http.StatusNotFound, cat.Name+" has no control "+controlID+".")
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	a, _ := s.Store.Assessment(e.ID, cat.ID, controlID)
	if a == nil {
		a = &model.Assessment{EnclaveID: e.ID, CatalogID: cat.ID, ControlID: controlID}
	}
	a.Status = model.ImplStatus(f.str("status"))
	a.Origination = f.str("origination")
	a.Responsible = f.str("responsible")
	a.Narrative = f.str("narrative")
	a.Evidence = f.lines("evidence")
	a.AssessedBy = f.str("assessed_by")
	a.ReviewDue = f.date("review_due")
	if a.Status != model.ImplNotAssessed {
		now := time.Now().UTC()
		if d := f.date("assessed_at"); d != nil {
			a.AssessedAt = d
		} else if a.AssessedAt == nil {
			a.AssessedAt = &now
		}
	}
	if err := s.Store.PutAssessment(a); err != nil {
		redirect(w, r, controlURL(e.ID, cat.ID, controlID), "", err.Error())
		return
	}
	redirect(w, r, controlURL(e.ID, cat.ID, controlID), "Assessment saved.", "")
}

func controlURL(enclaveID, catalogID, controlID string) string {
	return "/enclaves/" + enclaveID + "/baseline/" + catalogID + "/" + urlEscape(controlID)
}

// ---------- catalogues ----------

func (s *Server) handleCatalogList(w http.ResponseWriter, r *http.Request) {
	type row struct {
		Catalog *catalog.Catalog
		UsedBy  []*model.Enclave
	}
	rows := []row{}
	enclaves := s.Store.Enclaves()
	for _, c := range s.Catalogs.All() {
		rw := row{Catalog: c}
		for _, e := range enclaves {
			if e.HasBaseline(c.ID) {
				rw.UsedBy = append(rw.UsedBy, e)
			}
		}
		rows = append(rows, rw)
	}
	s.render(w, r, "catalogs.html", page{
		Title: "Control baselines", Nav: "catalogs",
		Data: map[string]any{"Rows": rows, "Dir": s.Catalogs.Dir()},
	})
}

func (s *Server) handleCatalogDetail(w http.ResponseWriter, r *http.Request) {
	c, ok := s.Catalogs.Get(r.PathValue("cid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No catalog with that identifier.")
		return
	}
	profile := r.URL.Query().Get("profile")
	type famRow struct {
		ID       string
		Name     string
		Controls []catalog.Control
	}
	fams := []famRow{}
	for _, id := range c.FamilyIDs(profile) {
		fams = append(fams, famRow{ID: id, Name: c.FamilyName(id), Controls: c.FamilyControls(id, profile)})
	}
	s.render(w, r, "catalog.html", page{
		Title: c.Name, Nav: "catalogs",
		Data: map[string]any{"Catalog": c, "Families": fams, "Profile": profile, "Count": c.Count(profile)},
	})
}

func (s *Server) handleCatalogImport(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		redirect(w, r, "/catalogs", "", "The upload could not be read: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		redirect(w, r, "/catalogs", "", "Choose a catalog file to upload.")
		return
	}
	defer file.Close()
	data, err := readCapped(file, s.MaxUpload)
	if err != nil {
		redirect(w, r, "/catalogs", "", err.Error())
		return
	}
	cat, err := catalog.Load(data, header.Filename)
	if err != nil {
		redirect(w, r, "/catalogs", "", "That file could not be read as a control catalog: "+err.Error())
		return
	}
	if id := strings.TrimSpace(r.FormValue("id")); id != "" {
		cat.ID = catalog.Slug(id)
	}
	if name := strings.TrimSpace(r.FormValue("name")); name != "" {
		cat.Name = name
	}
	if err := s.Catalogs.Add(cat, data, header.Filename); err != nil {
		redirect(w, r, "/catalogs", "", err.Error())
		return
	}
	redirect(w, r, "/catalogs/"+cat.ID,
		"Loaded "+cat.Name+" with "+itoa(len(cat.Controls))+" controls.", "")
}

func (s *Server) handleCatalogDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	id := r.PathValue("cid")
	if err := s.Catalogs.Remove(id); err != nil {
		redirect(w, r, "/catalogs", "", err.Error())
		return
	}
	redirect(w, r, "/catalogs", "Removed "+id+".", "")
}
