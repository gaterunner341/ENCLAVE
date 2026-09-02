// Package web serves the whole application: one HTML template, a handful of
// routes, and no client-side framework. Every page is rendered from the
// derived view, so what is on screen is always what the log says.
package web

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkittelson/enclave/internal/model"
	"github.com/pkittelson/enclave/internal/resolve"
	"github.com/pkittelson/enclave/internal/store"
)

//go:embed page.html
var pageHTML string

const flashCookie = "enclave_flash"

// fieldRow is one row of the provenance table.
type fieldRow struct {
	Name  string
	Value model.FieldValue
}

// pageData is everything a page can read. One struct for every page keeps the
// template a single file, which is worth more than the fields it wastes.
type pageData struct {
	Page string

	LiveHosts     int
	Obs           int
	Built         time.Time
	NavUnassigned int
	NavConflicts  int

	Flash    string
	FlashErr string

	Controls   []controlHead
	Enclaves   []enclaveView
	Hosts      []*model.Host
	Host       *model.Host
	Query      string
	Unassigned []*model.Host
	Conflicts  []*model.Host

	Mappings []*store.Mapping
	Imports  []store.ImportRecord

	Filename   string
	Headers    []string
	SampleRows [][]string
	StageID    string
	SourceID   string
	SourceKind string
	Kinds      []resolve.Kind
	MapRows    []mapRow

	Edit          *model.Enclave
	AllEnclaves   []*model.Enclave
	EnclaveCounts map[string]int
}

// controlHead is the column heading for one control.
type controlHead struct {
	ID    string
	Label string
	Hint  string
}

// Server wires the engine, the store and the templates together.
type Server struct {
	engine  *Engine
	store   *store.Store
	tmpl    *template.Template
	staging *stagingArea
}

// NewServer parses the template and returns a server ready to route.
func NewServer(engine *Engine, st *store.Store) (*Server, error) {
	funcs := template.FuncMap{
		"ago": ago,
		// band turns "points short of target" into a severity class, so the
		// colour on screen means the same thing in every column.
		"band": func(overTarget int) string {
			switch {
			case overTarget <= 0:
				return "ok"
			case overTarget <= 5:
				return "warn"
			case overTarget <= 15:
				return "high"
			default:
				return "crit"
			}
		},
		"sub100": func(n int) int { return 100 - n },
		"hasConflict": func(fields map[string]model.FieldValue) bool {
			return conflictCount(fields) > 0
		},
		"sortedFields": sortedFields,
		"joinCIDRs":    func(c []string) string { return strings.Join(c, ", ") },
		"percent":      percent,
		"itoa":         itoa,
	}
	tmpl, err := template.New("page").Funcs(funcs).Parse(pageHTML)
	if err != nil {
		return nil, err
	}
	return &Server{engine: engine, store: st, tmpl: tmpl, staging: newStaging()}, nil
}

// Routes returns the handler for the whole application.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.overview)
	mux.HandleFunc("GET /hosts", s.hosts)
	mux.HandleFunc("GET /host/{id}", s.host)
	mux.HandleFunc("GET /unassigned", s.unassigned)
	mux.HandleFunc("GET /conflicts", s.conflicts)

	mux.HandleFunc("GET /import", s.importGet)
	mux.HandleFunc("POST /import/upload", s.importUpload)
	mux.HandleFunc("POST /import/commit", s.importCommit)

	mux.HandleFunc("GET /enclaves", s.enclaves)
	mux.HandleFunc("POST /enclaves/save", s.enclaveSave)
	mux.HandleFunc("POST /enclaves/delete", s.enclaveDelete)
	mux.HandleFunc("POST /mappings/delete", s.mappingDelete)
	mux.HandleFunc("POST /assign", s.assign)

	// Anything else is a mistyped URL, not a page.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	return mux
}

// base fills in the parts of the page that are the same everywhere.
func (s *Server) base(page string) *pageData {
	hosts, obs, built := s.engine.Stats()
	d := &pageData{
		Page:          page,
		LiveHosts:     hosts,
		Obs:           obs,
		Built:         built,
		NavUnassigned: len(s.engine.Unassigned()),
		NavConflicts:  len(s.engine.Conflicts()),
		Kinds:         resolve.Kinds(),
	}
	for _, c := range s.engine.Controls() {
		d.Controls = append(d.Controls, controlHead{ID: c.ID, Label: c.Label, Hint: c.Hint})
	}
	return d
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, d *pageData) {
	s.renderFlash(w, r, d)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, d); err != nil {
		log.Printf("render %s: %v", d.Page, err)
	}
}

// renderFlash moves any pending message onto the page and clears it, so a
// refresh does not show the same confirmation twice.
func (s *Server) renderFlash(w http.ResponseWriter, r *http.Request, d *pageData) {
	msg, isErr := s.takeFlash(w, r)
	if msg == "" {
		return
	}
	if isErr {
		d.FlashErr = msg
	} else {
		d.Flash = msg
	}
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := r.Cookie(flashCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1})
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		return "", false
	}
	kind, msg, ok := strings.Cut(raw, ":")
	if !ok {
		return "", false
	}
	return msg, kind == "err"
}

// flashRedirect leaves a message for the next page and goes there. Every write
// ends this way, so a reload never repeats the write.
func (s *Server) flashRedirect(w http.ResponseWriter, r *http.Request, to, msg string, isErr bool) {
	kind := "ok"
	if isErr {
		kind = "err"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookie,
		Value:    url.QueryEscape(kind + ":" + msg),
		Path:     "/",
		HttpOnly: true,
		MaxAge:   30,
	})
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	d := s.base("overview")
	enclaves := s.store.ActiveEnclaves()
	d.Enclaves, d.EnclaveCounts = s.engine.enclaveViews(enclaves)
	d.Unassigned = s.engine.Unassigned()
	d.Conflicts = s.engine.Conflicts()
	s.render(w, r, d)
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	d := s.base("hosts")
	d.Query = r.URL.Query().Get("q")
	d.Hosts = s.engine.Hosts(d.Query)
	s.render(w, r, d)
}

func (s *Server) host(w http.ResponseWriter, r *http.Request) {
	h := s.engine.Host(r.PathValue("id"))
	if h == nil {
		http.NotFound(w, r)
		return
	}
	d := s.base("host")
	d.Host = h
	s.render(w, r, d)
}

func (s *Server) unassigned(w http.ResponseWriter, r *http.Request) {
	d := s.base("unassigned")
	d.Unassigned = s.engine.Unassigned()
	d.Enclaves, d.EnclaveCounts = s.engine.enclaveViews(s.store.ActiveEnclaves())
	s.render(w, r, d)
}

func (s *Server) conflicts(w http.ResponseWriter, r *http.Request) {
	d := s.base("conflicts")
	d.Conflicts = s.engine.Conflicts()
	s.render(w, r, d)
}

// sortedFields returns a host's fields in a fixed order, so the same machine
// reads the same way every time it is opened.
func sortedFields(fields map[string]model.FieldValue) []fieldRow {
	order := map[string]int{
		model.FieldIP: 1, model.FieldOS: 2, model.FieldOSVersion: 3,
		model.FieldOwner: 4, model.FieldLocation: 5, model.FieldDeviceRole: 6,
		model.FieldManufacturer: 7, model.FieldHardwareModel: 8,
		model.FieldEDRStatus: 9, model.FieldDiskEncrypted: 10,
		model.FieldLastVulnScan: 11, model.FieldLastBenchmarkScan: 12,
	}
	rows := make([]fieldRow, 0, len(fields))
	for name, v := range fields {
		rows = append(rows, fieldRow{Name: fieldLabel(name), Value: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		ra, rb := order[fieldKey(a.Name)], order[fieldKey(b.Name)]
		if ra == 0 {
			ra = 99
		}
		if rb == 0 {
			rb = 99
		}
		if ra != rb {
			return ra < rb
		}
		return a.Name < b.Name
	})
	return rows
}

// ago renders a time the way a person reads one.
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hr ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
	return t.Format("2 Jan 2006")
}

func percent(part, whole int) int {
	if whole <= 0 {
		return 0
	}
	return part * 100 / whole
}

func itoa(n int) string { return strconv.Itoa(n) }
