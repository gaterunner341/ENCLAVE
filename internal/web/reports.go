package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	enclaves := s.Store.Enclaves()

	type baselineRow struct {
		Enclave  *model.Enclave
		Catalog  string
		Profile  string
		Analysis risk.Analysis
	}
	rows := []baselineRow{}
	// A cross-enclave view of one framework answers the question a programme
	// manager actually asks: where is this control weak across the estate?
	catID := r.URL.Query().Get("catalog")
	if catID == "" && len(enclaves) > 0 && len(enclaves[0].Baselines) > 0 {
		catID = enclaves[0].Baselines[0].CatalogID
	}
	worstControls := map[string]*controlRollup{}

	for _, e := range enclaves {
		assets := s.Store.Assets(e.ID)
		findings := s.Store.Findings(e.ID)
		assessments := s.Store.Assessments(e.ID)
		for _, b := range e.Baselines {
			cat := s.Catalogs.MustGet(b.CatalogID)
			an := risk.Analyse(cat, b.ProfileID, e, assets, findings, assessments, now)
			rows = append(rows, baselineRow{
				Enclave: e, Catalog: cat.Name,
				Profile: cat.ProfileName(b.ProfileID), Analysis: an,
			})
			if b.CatalogID != catID {
				continue
			}
			for _, fam := range an.Families {
				for _, g := range fam.Controls {
					cr := worstControls[g.Control.ID]
					if cr == nil {
						cr = &controlRollup{ControlID: g.Control.ID, Title: g.Control.Title, Family: fam.Name}
						worstControls[g.Control.ID] = cr
					}
					cr.Total++
					if g.State.Open() {
						cr.Failing++
						cr.Enclaves = append(cr.Enclaves, e.Name)
					}
				}
			}
		}
	}
	weakest := []*controlRollup{}
	for _, cr := range worstControls {
		if cr.Failing > 0 {
			weakest = append(weakest, cr)
		}
	}
	sortByFailing(weakest)

	s.render(w, r, "reports.html", page{
		Title: "Reports", Nav: "reports",
		Data: map[string]any{
			"Rows": rows, "Weakest": firstN(weakest, 40),
			"Catalog": catID, "Catalogs": s.Catalogs.All(),
			"Counts": s.Store.Counts(),
		},
	})
}

// controlRollup is one control seen across every enclave measured against the
// same framework.
type controlRollup struct {
	ControlID string
	Title     string
	Family    string
	Failing   int
	Total     int
	Enclaves  []string
}

// Share is the proportion of enclaves where the control is not met.
func (c controlRollup) Share() float64 {
	if c.Total == 0 {
		return 0
	}
	return float64(c.Failing) / float64(c.Total) * 100
}

func sortByFailing(in []*controlRollup) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Failing != in[j].Failing {
			return in[i].Failing > in[j].Failing
		}
		return in[i].ControlID < in[j].ControlID
	})
}

// handleExportCSV serves the data behind a page as a spreadsheet, because a
// report that cannot be handed to somebody in Excel does not get used.
func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	enclaveID := r.URL.Query().Get("enclave")
	now := time.Now()

	filename := "enclave-" + kind + "-" + now.Format("20060102") + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()

	switch kind {
	case "assets":
		_ = cw.Write([]string{"Enclave", "Asset", "FQDN", "Type", "Role", "Criticality",
			"Platform", "Vendor", "Model", "Serial", "IP addresses", "MAC addresses",
			"Owner", "Location", "Status", "First seen", "Last seen", "Open findings", "Tags"})
		enclaves := s.enclaveIndex()
		open := map[string]int{}
		for _, f := range s.Store.Findings(enclaveID) {
			if f.Live() {
				open[f.AssetID]++
			}
		}
		for _, a := range s.assetsFor(enclaveID) {
			name := ""
			if e, ok := enclaves[a.EnclaveID]; ok {
				name = e.Name
			}
			_ = cw.Write([]string{
				name, a.DisplayName(), a.FQDN, a.Type.Label(), a.Role, a.Criticality.Label(),
				a.Platform(), a.Vendor, a.Model, a.Serial,
				strings.Join(a.IPs, " "), strings.Join(a.MACs, " "),
				a.Owner, a.Location, a.Status,
				fmtDate(a.FirstSeen), fmtDateP(a.LastSeen),
				strconv.Itoa(open[a.ID]), strings.Join(a.Tags, " "),
			})
		}

	case "findings":
		_ = cw.Write([]string{"Enclave", "Asset", "Rule", "Group", "Title", "Severity",
			"Status", "Disposition", "First seen", "Last seen", "Age (days)", "Due",
			"Overdue", "CCIs", "CVEs", "CVSS", "Controls", "Fix"})
		enclaves := s.enclaveIndex()
		assets := s.assetIndex()
		for _, f := range s.Store.Findings(enclaveID) {
			name, asset := "", ""
			if e, ok := enclaves[f.EnclaveID]; ok {
				name = e.Name
			}
			if a, ok := assets[f.AssetID]; ok {
				asset = a.DisplayName()
			}
			refs := []string{}
			for _, cat := range sortedKeys(f.ControlRefs) {
				refs = append(refs, cat+": "+strings.Join(f.ControlRefs[cat], " "))
			}
			due := ""
			if d := risk.Due(f); d != nil {
				due = d.Format("2006-01-02")
			}
			cvss := ""
			if f.CVSS > 0 {
				cvss = strconv.FormatFloat(f.CVSS, 'f', 1, 64)
			}
			_ = cw.Write([]string{
				name, asset, f.RuleID, f.GroupID, f.Title, f.Severity.Label(),
				f.Status.Label(), f.Disposition.Label(),
				fmtDate(f.FirstSeen), fmtDate(f.LastSeen), strconv.Itoa(f.AgeDays(now)), due,
				boolWord(risk.PastTarget(f, now)),
				strings.Join(f.CCIs, " "), strings.Join(f.CVEs, " "), cvss,
				strings.Join(refs, "; "), oneLineOf(f.FixText),
			})
		}

	case "baseline":
		catID := r.URL.Query().Get("catalog")
		_ = cw.Write([]string{"Enclave", "Catalog", "Profile", "Family", "Control", "Title",
			"State", "Implementation", "Origination", "Responsible", "Assessed",
			"Open findings", "Passing checks", "Assets affected", "Risk score", "Narrative"})
		for _, e := range s.enclavesFor(enclaveID) {
			assets := s.Store.Assets(e.ID)
			findings := s.Store.Findings(e.ID)
			assessments := s.Store.Assessments(e.ID)
			for _, b := range e.Baselines {
				if catID != "" && b.CatalogID != catID {
					continue
				}
				cat := s.Catalogs.MustGet(b.CatalogID)
				an := risk.Analyse(cat, b.ProfileID, e, assets, findings, assessments, now)
				for _, fam := range an.Families {
					for _, g := range fam.Controls {
						impl, orig, resp, assessed, narrative := "Not assessed", "", "", "", ""
						if g.Assessment != nil {
							impl = g.Assessment.Status.Label()
							orig = g.Assessment.Origination
							resp = g.Assessment.Responsible
							assessed = fmtDateP(g.Assessment.AssessedAt)
							narrative = oneLineOf(g.Assessment.Narrative)
						}
						_ = cw.Write([]string{
							e.Name, cat.Name, cat.ProfileName(b.ProfileID), fam.Name,
							g.Control.ID, g.Control.Title, g.State.Label(),
							impl, orig, resp, assessed,
							strconv.Itoa(g.OpenCount), strconv.Itoa(g.PassCount),
							strconv.Itoa(g.Assets),
							strconv.FormatFloat(g.RiskScore, 'f', 1, 64), narrative,
						})
					}
				}
			}
		}

	case "risks":
		_ = cw.Write([]string{"Enclave", "Title", "Weakness", "Source", "Status", "Owner",
			"Likelihood", "Impact", "Score", "Band", "Detected", "Due", "Completed",
			"Overdue", "Controls", "Mitigation", "Resources", "Milestones"})
		enclaves := s.enclaveIndex()
		for _, rr := range s.Store.Risks(enclaveID) {
			name := ""
			if e, ok := enclaves[rr.EnclaveID]; ok {
				name = e.Name
			}
			refs := []string{}
			for _, cat := range sortedKeys(rr.ControlRefs) {
				refs = append(refs, cat+": "+strings.Join(rr.ControlRefs[cat], " "))
			}
			ms := []string{}
			for _, m := range rr.Milestones {
				entry := m.Description
				if m.Due != nil {
					entry += " (due " + m.Due.Format("2006-01-02") + ")"
				}
				ms = append(ms, entry)
			}
			_ = cw.Write([]string{
				name, rr.Title, oneLineOf(rr.Weakness), rr.Source, rr.Status, rr.Owner,
				strconv.Itoa(rr.Likelihood), strconv.Itoa(rr.Impact),
				strconv.Itoa(rr.Score()), rr.Band(),
				fmtDate(rr.Detected), fmtDateP(rr.Due), fmtDateP(rr.Completed),
				boolWord(rr.Overdue(now)), strings.Join(refs, "; "),
				oneLineOf(rr.Mitigation), oneLineOf(rr.Resources), strings.Join(ms, "; "),
			})
		}

	default:
		http.Error(w, "Nothing is exported under that name. Use assets, findings, baseline or risks.", http.StatusNotFound)
	}
}

// handleAPI serves the same data as JSON for anything that has to consume it
// programmatically.
func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	enclaveID := r.URL.Query().Get("enclave")
	now := time.Now()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	switch r.PathValue("kind") {
	case "enclaves":
		_ = enc.Encode(s.Store.Enclaves())
	case "assets":
		_ = enc.Encode(s.assetsFor(enclaveID))
	case "findings":
		_ = enc.Encode(s.Store.Findings(enclaveID))
	case "risks":
		_ = enc.Encode(s.Store.Risks(enclaveID))
	case "scans":
		_ = enc.Encode(s.Store.Scans(enclaveID))
	case "catalogs":
		_ = enc.Encode(s.Catalogs.All())
	case "summary":
		type row struct {
			Enclave  string  `json:"enclave"`
			Name     string  `json:"name"`
			Index    float64 `json:"risk_index"`
			Band     string  `json:"risk_band"`
			Assets   int     `json:"assets"`
			Open     int     `json:"open_findings"`
			Overdue  int     `json:"overdue_findings"`
			Coverage float64 `json:"baseline_coverage"`
			Verified float64 `json:"verified_coverage"`
		}
		out := []row{}
		for _, e := range s.enclavesFor(enclaveID) {
			assets := s.Store.Assets(e.ID)
			findings := s.Store.Findings(e.ID)
			er := risk.ScoreEnclave(e, assets, findings, now)
			rw := row{
				Enclave: e.ID, Name: e.Name, Index: er.Index, Band: er.Band,
				Assets: len(assets), Open: er.Open, Overdue: er.Overdue,
			}
			if len(e.Baselines) > 0 {
				b := e.Baselines[0]
				an := risk.Analyse(s.Catalogs.MustGet(b.CatalogID), b.ProfileID, e,
					assets, findings, s.Store.Assessments(e.ID), now)
				rw.Coverage, rw.Verified = an.Coverage(), an.Verified()
			}
			out = append(out, rw)
		}
		_ = enc.Encode(out)
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = enc.Encode(map[string]string{
			"error":     "unknown collection",
			"available": "enclaves, assets, findings, risks, scans, catalogs, summary",
		})
	}
}

func (s *Server) assetsFor(enclaveID string) []*model.Asset {
	if enclaveID == "" {
		return s.Store.AllAssets()
	}
	return s.Store.Assets(enclaveID)
}

func (s *Server) enclavesFor(enclaveID string) []*model.Enclave {
	if enclaveID == "" {
		return s.Store.Enclaves()
	}
	if e, ok := s.Store.Enclave(enclaveID); ok {
		return []*model.Enclave{e}
	}
	return nil
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

func fmtDateP(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtDate(*t)
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func oneLineOf(s string) string { return strings.Join(strings.Fields(s), " ") }

// ExportCSV is the exported form of the CSV handler, so that the command line
// can produce exactly the same files the browser does.
func (s *Server) ExportCSV(w http.ResponseWriter, r *http.Request) { s.handleExportCSV(w, r) }
