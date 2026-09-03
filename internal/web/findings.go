package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

func (s *Server) handleFindingList(w http.ResponseWriter, r *http.Request) {
	e, ok := s.Store.Enclave(r.PathValue("id"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No enclave with that identifier.")
		return
	}
	q := r.URL.Query()
	filters := findingFilters{
		Text:        strings.ToLower(strings.TrimSpace(q.Get("q"))),
		Severity:    q.Get("severity"),
		Status:      q.Get("status"),
		Disposition: q.Get("disposition"),
		AssetID:     q.Get("asset"),
		ScanID:      q.Get("scan"),
		Control:     q.Get("control"),
		Catalog:     q.Get("catalog"),
		Show:        q.Get("show"),
		Overdue:     q.Get("overdue") == "1",
		Unmapped:    q.Get("unmapped") == "1",
	}
	if filters.Show == "" {
		filters.Show = "open"
	}
	now := time.Now()
	all := s.Store.Findings(e.ID)
	assets := s.assetIndex()
	rows := filterFindings(all, filters, assets, now)

	counts := map[model.Severity]int{}
	accepted := 0
	for _, f := range rows {
		if f.Live() {
			counts[f.Severity.Normalise()]++
		}
		if f.Accepted() {
			accepted++
		}
	}
	// The result set can be very large; the page shows a window and says so.
	const window = 500
	shown := rows
	if len(shown) > window {
		shown = shown[:window]
	}

	s.render(w, r, "findings.html", page{
		Title: "Findings · " + e.Name, Nav: "enclaves", SubNav: "findings", Enclave: e,
		Data: map[string]any{
			"Rows": shown, "Total": len(rows), "AllTotal": len(all),
			"Truncated": len(rows) > len(shown), "Window": window,
			"Filters": filters, "AssetIndex": assets,
			"Assets": s.Store.Assets(e.ID), "Scans": s.Store.Scans(e.ID),
			"Counts": counts, "Accepted": accepted,
		},
	})
}

type findingFilters struct {
	Text, Severity, Status, Disposition string
	AssetID, ScanID, Control, Catalog   string
	Show                                string // live, all, closed
	Overdue, Unmapped                   bool
}

// Active reports whether anything narrows the default view, which the template
// uses to offer a "clear filters" link only when it would do something.
func (f findingFilters) Active() bool {
	return f.Text != "" || f.Severity != "" || f.Status != "" || f.Disposition != "" ||
		f.AssetID != "" || f.ScanID != "" || f.Control != "" || f.Overdue || f.Unmapped ||
		(f.Show != "" && f.Show != "open")
}

func filterFindings(in []*model.Finding, f findingFilters, assets map[string]*model.Asset, now time.Time) []*model.Finding {
	out := make([]*model.Finding, 0, len(in))
	for _, fd := range in {
		switch f.Show {
		case "closed":
			if fd.Live() {
				continue
			}
		case "accepted":
			if !fd.Accepted() {
				continue
			}
		case "live":
			// Everything still an exposure, accepted risks included.
			if !fd.Live() {
				continue
			}
		case "all":
		default:
			// The default is work outstanding. An accepted risk is not that,
			// so it is reached through its own choice rather than sitting in
			// the list somebody is working from.
			if !fd.NeedsWork() {
				continue
			}
		}
		if f.Severity != "" && string(fd.Severity.Normalise()) != f.Severity {
			continue
		}
		if f.Status != "" && string(fd.Status.Normalise()) != f.Status {
			continue
		}
		if f.Disposition != "" && string(fd.Disposition) != f.Disposition {
			continue
		}
		if f.AssetID != "" && fd.AssetID != f.AssetID {
			continue
		}
		if f.ScanID != "" && fd.ScanID != f.ScanID {
			continue
		}
		if f.Unmapped && len(fd.ControlRefs) > 0 {
			continue
		}
		if f.Overdue && !risk.PastTarget(fd, now) {
			continue
		}
		if f.Control != "" {
			hit := false
			for cat, refs := range fd.ControlRefs {
				if f.Catalog != "" && cat != f.Catalog {
					continue
				}
				for _, id := range refs {
					if strings.EqualFold(id, f.Control) {
						hit = true
					}
				}
			}
			if !hit {
				continue
			}
		}
		if f.Text != "" && !findingMatches(fd, assets[fd.AssetID], f.Text) {
			continue
		}
		out = append(out, fd)
	}
	return out
}

func findingMatches(f *model.Finding, a *model.Asset, q string) bool {
	var b strings.Builder
	b.WriteString(strings.ToLower(f.Title))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(f.RuleID))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(f.GroupID))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(f.Description))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(strings.Join(f.CVEs, " ")))
	b.WriteByte(' ')
	b.WriteString(strings.ToLower(strings.Join(f.CCIs, " ")))
	if a != nil {
		b.WriteByte(' ')
		b.WriteString(strings.ToLower(a.DisplayName()))
	}
	for _, refs := range f.ControlRefs {
		b.WriteByte(' ')
		b.WriteString(strings.ToLower(strings.Join(refs, " ")))
	}
	hay := b.String()
	for _, term := range strings.Fields(q) {
		if !strings.Contains(hay, term) {
			return false
		}
	}
	return true
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	f, ok := s.Store.Finding(r.PathValue("fid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No finding with that identifier.")
		return
	}
	a, _ := s.Store.Asset(f.AssetID)
	e, _ := s.Store.Enclave(f.EnclaveID)
	sc, _ := s.Store.Scan(f.ScanID)

	// Where else the same rule fires in this enclave: the difference between
	// one misconfigured host and a systemic gap.
	siblings := []*model.Finding{}
	for _, other := range s.Store.Findings(f.EnclaveID) {
		if other.ID != f.ID && other.RuleID == f.RuleID && f.RuleID != "" {
			siblings = append(siblings, other)
		}
	}
	sort.Slice(siblings, func(i, j int) bool { return siblings[i].AssetID < siblings[j].AssetID })

	type ref struct {
		CatalogID string
		Catalog   string
		Control   string
		Title     string
	}
	refs := []ref{}
	for _, catID := range sortedKeys(f.ControlRefs) {
		cat := s.Catalogs.MustGet(catID)
		for _, id := range f.ControlRefs[catID] {
			ctl, _ := cat.Control(id)
			refs = append(refs, ref{CatalogID: catID, Catalog: cat.Name, Control: id, Title: ctl.Title})
		}
	}

	s.render(w, r, "finding.html", page{
		Title: f.Title, Nav: "enclaves", SubNav: "findings", Enclave: e,
		Data: map[string]any{
			"Finding": f, "Asset": a, "Scan": sc, "Refs": refs,
			"Siblings": firstN(siblings, 25), "SiblingTotal": len(siblings),
			"AssetIndex": s.assetIndex(), "Due": risk.Due(f),
			"Overdue": risk.PastTarget(f, time.Now()),
		},
	})
}

func (s *Server) handleDisposition(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, ok := s.Store.Finding(r.PathValue("fid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No finding with that identifier.")
		return
	}
	form, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	d := model.Disposition(form.str("disposition"))
	note := form.str("note")
	// A decision to accept or mitigate risk is a decision somebody owns, so it
	// cannot be recorded anonymously or without a reason.
	if (d == model.DispositionRiskAccepted || d == model.DispositionMitigated || d == model.DispositionFalsePositive) &&
		(note == "" || form.str("by") == "") {
		redirect(w, r, "/findings/"+f.ID, "", "Accepting, mitigating or dismissing a finding needs a name and a reason.")
		return
	}
	if err := s.Store.SetDisposition(f.ID, d, note, form.str("by"), form.date("due")); err != nil {
		redirect(w, r, "/findings/"+f.ID, "", err.Error())
		return
	}
	redirect(w, r, "/findings/"+f.ID, "Recorded.", "")
}
