package web

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

// dashboardRow is one enclave's line on the front page.
type dashboardRow struct {
	Risk      risk.EnclaveRisk
	Coverage  float64
	Verified  float64
	Baseline  string
	OpenRisks int
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	enclaves := s.Store.Enclaves()
	rows := make([]dashboardRow, 0, len(enclaves))

	totals := map[model.Severity]int{}
	var worstOpen []*model.Finding
	overallOpen, overallAssets := 0, 0

	for _, e := range enclaves {
		assets := s.Store.Assets(e.ID)
		findings := s.Store.Findings(e.ID)
		row := dashboardRow{Risk: risk.ScoreEnclave(e, assets, findings, now)}
		overallAssets += len(assets)
		overallOpen += row.Risk.Open
		for sev, n := range row.Risk.BySev {
			totals[sev] += n
		}
		for _, rr := range s.Store.Risks(e.ID) {
			if rr.Open() {
				row.OpenRisks++
			}
		}
		if len(e.Baselines) > 0 {
			b := e.Baselines[0]
			cat := s.Catalogs.MustGet(b.CatalogID)
			row.Baseline = cat.Name
			if b.ProfileID != "" {
				row.Baseline += " · " + cat.ProfileName(b.ProfileID)
			}
			an := risk.Analyse(cat, b.ProfileID, e, assets, findings, s.Store.Assessments(e.ID), now)
			row.Coverage, row.Verified = an.Coverage(), an.Verified()
		}
		rows = append(rows, row)
		for _, f := range findings {
			if f.Live() && f.Severity.Rank() >= model.SeverityHigh.Rank() {
				worstOpen = append(worstOpen, f)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Risk.Index > rows[j].Risk.Index })

	overdue := risk.OverdueFindings(s.Store.Findings(""), now)
	sort.Slice(worstOpen, func(i, j int) bool {
		if worstOpen[i].Severity.Rank() != worstOpen[j].Severity.Rank() {
			return worstOpen[i].Severity.Rank() > worstOpen[j].Severity.Rank()
		}
		return worstOpen[i].FirstSeen.Before(worstOpen[j].FirstSeen)
	})
	if len(worstOpen) > 12 {
		worstOpen = worstOpen[:12]
	}
	if len(overdue) > 12 {
		overdue = overdue[:12]
	}

	s.render(w, r, "dashboard.html", page{
		Title: "Overview", Nav: "dashboard",
		Data: map[string]any{
			"Rows":       rows,
			"Counts":     s.Store.Counts(),
			"Severity":   donut(countsBySeverity(totals), severityOrder, severityClasses),
			"Ages":       risk.AgeProfile(s.Store.Findings(""), now),
			"Worst":      worstOpen,
			"Overdue":    overdue,
			"AssetTotal": overallAssets,
			"OpenTotal":  overallOpen,
			"AssetIndex": s.assetIndex(),
		},
	})
}

// assetIndex maps asset identifiers to records, so a template listing findings
// can name the machine each one is about without a lookup per row.
func (s *Server) assetIndex() map[string]*model.Asset {
	out := map[string]*model.Asset{}
	for _, a := range s.Store.AllAssets() {
		out[a.ID] = a
	}
	return out
}

func (s *Server) enclaveIndex() map[string]*model.Enclave {
	out := map[string]*model.Enclave{}
	for _, e := range s.Store.Enclaves() {
		out[e.ID] = e
	}
	return out
}

func (s *Server) handleEnclaveList(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	type row struct {
		Enclave *model.Enclave
		Assets  int
		Open    int
		Index   float64
		Band    string
	}
	rows := []row{}
	for _, e := range s.Store.Enclaves() {
		assets := s.Store.Assets(e.ID)
		er := risk.ScoreEnclave(e, assets, s.Store.Findings(e.ID), now)
		rows = append(rows, row{Enclave: e, Assets: len(assets), Open: er.Open, Index: er.Index, Band: er.Band})
	}
	s.render(w, r, "enclaves.html", page{
		Title: "Enclaves", Nav: "enclaves",
		Data: map[string]any{"Rows": rows},
	})
}

func (s *Server) handleEnclaveOverview(w http.ResponseWriter, r *http.Request) {
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	now := time.Now()
	assets := s.Store.Assets(e.ID)
	findings := s.Store.Findings(e.ID)
	er := risk.ScoreEnclave(e, assets, findings, now)

	byType := map[string]int{}
	for _, a := range assets {
		byType[a.Type.Label()]++
	}
	typeOrder := sortedKeys(byType)

	analyses := []risk.Analysis{}
	for _, b := range e.Baselines {
		cat := s.Catalogs.MustGet(b.CatalogID)
		analyses = append(analyses, risk.Analyse(cat, b.ProfileID, e, assets, findings,
			s.Store.Assessments(e.ID), now))
	}

	openRisks := 0
	for _, rr := range s.Store.Risks(e.ID) {
		if rr.Open() {
			openRisks++
		}
	}

	s.render(w, r, "enclave.html", page{
		Title: e.Name, Nav: "enclaves", SubNav: "overview", Enclave: e,
		Data: map[string]any{
			"Risk":       er,
			"Severity":   donut(countsBySeverity(er.BySev), severityOrder, severityClasses),
			"Ages":       risk.AgeProfile(findings, now),
			"Analyses":   analyses,
			"ByType":     byType,
			"TypeOrder":  typeOrder,
			"Scans":      firstN(s.Store.Scans(e.ID), 5),
			"OpenRisks":  openRisks,
			"AssetIndex": s.assetIndex(),
			"Overdue":    firstNF(risk.OverdueFindings(findings, now), 8),
			"Available":  s.Catalogs.All(),
		},
	})
}

func (s *Server) handleEnclaveForm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	var e *model.Enclave
	if id := r.PathValue("id"); id != "" {
		found, ok := s.Store.Enclave(id)
		if !ok {
			s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
			return
		}
		e = found
	} else {
		e = &model.Enclave{
			Confidentiality: model.ImpactModerate,
			Integrity:       model.ImpactModerate,
			Availability:    model.ImpactModerate,
			Status:          "Active",
			Environment:     "Production",
		}
	}
	title := "New enclave"
	if e.ID != "" {
		title = "Edit " + e.Name
	}
	s.render(w, r, "enclave_form.html", page{
		Title: title, Nav: "enclaves", SubNav: "settings", Enclave: e,
		Data: map[string]any{"Enclave": e, "IsNew": e.ID == "", "Catalogs": s.Catalogs.All()},
	})
}

func (s *Server) handleEnclaveSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	id := r.PathValue("id")
	e := &model.Enclave{}
	if id != "" {
		if prev, ok := s.Store.Enclave(id); ok {
			copy := *prev
			e = &copy
		}
	}
	if id == "" {
		e.ID = model.SlugID(firstNonBlank(f.str("id"), f.str("name")))
	} else {
		e.ID = id
	}
	e.Name = f.str("name")
	e.Description = f.str("description")
	e.Owner = f.str("owner")
	e.SecurityContact = f.str("security_contact")
	e.Organization = f.str("organization")
	e.Location = f.str("location")
	e.Environment = f.str("environment")
	e.Status = f.str("status")
	e.Confidentiality = model.Impact(f.str("confidentiality")).Normalise()
	e.Integrity = model.Impact(f.str("integrity")).Normalise()
	e.Availability = model.Impact(f.str("availability")).Normalise()
	e.AuthorizationStatus = f.str("authorization_status")
	e.AuthorizationExpires = f.date("authorization_expires")
	e.Tags = f.csv("tags")

	e.Networks = nil
	for _, line := range f.lines("networks") {
		cidr, label, _ := strings.Cut(line, " ")
		e.Networks = append(e.Networks, model.Network{
			CIDR: strings.TrimSpace(cidr), Label: strings.TrimSpace(label),
		})
	}

	if err := s.Store.PutEnclave(e); err != nil {
		s.render(w, r, "enclave_form.html", page{
			Title: "Enclave", Nav: "enclaves", Error: err.Error(),
			Data: map[string]any{"Enclave": e, "IsNew": id == "", "Catalogs": s.Catalogs.All()},
		})
		return
	}
	redirect(w, r, "/enclaves/"+e.ID, "Saved.", "")
}

func (s *Server) handleEnclaveDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	id := r.PathValue("id")
	e, ok := s.Store.Enclave(id)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	// Deleting an enclave discards its assets, findings and history, so the
	// name has to be typed to confirm it.
	if f, _ := newForm(r); f == nil || !strings.EqualFold(f.str("confirm"), e.Name) {
		redirect(w, r, "/enclaves/"+id+"/edit", "", "Type the enclave name exactly to confirm deletion.")
		return
	}
	if err := s.Store.DeleteEnclave(id); err != nil {
		redirect(w, r, "/enclaves/"+id, "", err.Error())
		return
	}
	redirect(w, r, "/enclaves", "Deleted "+e.Name+" and everything recorded against it.", "")
}

func (s *Server) handleBaselineAssign(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	switch f.str("action") {
	case "remove":
		target := f.str("catalog_id")
		kept := e.Baselines[:0]
		for _, b := range e.Baselines {
			if b.CatalogID != target {
				kept = append(kept, b)
			}
		}
		e.Baselines = kept
	default:
		// The catalogue and its profile arrive as one value so that a profile
		// can never be paired with a catalogue that does not define it.
		catID, profileFromPair, paired := strings.Cut(f.str("baseline"), "|")
		if !paired {
			catID = f.str("catalog_id")
		}
		cat, ok := s.Catalogs.Get(catID)
		if !ok {
			redirect(w, r, "/enclaves/"+e.ID, "", "No catalog with that identifier.")
			return
		}
		profile := profileFromPair
		if !paired {
			profile = f.str("profile_id")
		}
		if profile != "" {
			if _, ok := cat.Profile(profile); !ok {
				redirect(w, r, "/enclaves/"+e.ID, "", "That catalog has no profile called "+profile+".")
				return
			}
		}
		replaced := false
		for i := range e.Baselines {
			if e.Baselines[i].CatalogID == catID {
				e.Baselines[i].ProfileID = profile
				e.Baselines[i].Note = f.str("note")
				replaced = true
			}
		}
		if !replaced {
			e.Baselines = append(e.Baselines, model.BaselineRef{
				CatalogID: catID, ProfileID: profile,
				Note: f.str("note"), AddedAt: time.Now().UTC(),
			})
		}
	}
	if err := s.Store.PutEnclave(e); err != nil {
		redirect(w, r, "/enclaves/"+e.ID, "", err.Error())
		return
	}
	// A newly assigned baseline needs its findings mapped against it before the
	// gap page can say anything useful.
	n, err := s.Importer.Reannotate(e.ID)
	msg := "Baselines updated."
	if err == nil && n > 0 {
		msg += " Control references were recalculated for " + itoa(n) + " findings."
	}
	redirect(w, r, "/enclaves/"+e.ID+"/baseline", msg, "")
}

func itoa(n int) string { return strconv.Itoa(n) }

func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstN[T any](in []T, n int) []T {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func firstNF(in []*model.Finding, n int) []*model.Finding { return firstN(in, n) }
