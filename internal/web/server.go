// Package web serves the ENCLAVE interface: server-rendered HTML, one
// stylesheet, and a small amount of JavaScript for table filtering. There is
// no client framework and no build step, because the result has to remain a
// single executable that runs with nothing else installed.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/importer"
	"github.com/gaterunner341/enclave/internal/mapping"
	"github.com/gaterunner341/enclave/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds everything the handlers need.
type Server struct {
	Store    *store.Store
	Catalogs *catalog.Registry
	Mappings *mapping.Registry
	Importer *importer.Importer

	// Version is shown in the footer so a screenshot in a report identifies
	// which build produced it.
	Version string
	// ReadOnly disables every mutating route, for a deployment that only
	// publishes results.
	ReadOnly bool
	// MaxUpload caps an uploaded scan file.
	MaxUpload int64

	tmpl *template.Template
	mux  *http.ServeMux
}

// New builds a server and parses the templates. A template error is fatal at
// construction rather than at first request, so a broken build cannot start.
func New(s *store.Store, cats *catalog.Registry, maps *mapping.Registry, version string) (*Server, error) {
	srv := &Server{
		Store:     s,
		Catalogs:  cats,
		Mappings:  maps,
		Importer:  importer.New(s, cats, maps),
		Version:   version,
		MaxUpload: 128 << 20,
	}
	tmpl, err := template.New("").Funcs(srv.funcs()).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	srv.tmpl = tmpl
	srv.routes()
	return srv, nil
}

// Handler is the server's http.Handler.
func (s *Server) Handler() http.Handler { return s.logging(s.mux) }

func (s *Server) routes() {
	m := http.NewServeMux()

	staticFS, _ := fs.Sub(assets, "static")
	m.Handle("GET /static/", http.StripPrefix("/static/", cacheFor(time.Hour, http.FileServer(http.FS(staticFS)))))

	m.HandleFunc("GET /{$}", s.handleDashboard)
	m.HandleFunc("GET /enclaves", s.handleEnclaveList)
	m.HandleFunc("GET /enclaves/new", s.handleEnclaveForm)
	m.HandleFunc("POST /enclaves/new", s.handleEnclaveSave)
	m.HandleFunc("GET /enclaves/{id}", s.handleEnclaveOverview)
	m.HandleFunc("GET /enclaves/{id}/edit", s.handleEnclaveForm)
	m.HandleFunc("POST /enclaves/{id}/edit", s.handleEnclaveSave)
	m.HandleFunc("POST /enclaves/{id}/delete", s.handleEnclaveDelete)
	m.HandleFunc("POST /enclaves/{id}/baselines", s.handleBaselineAssign)

	m.HandleFunc("GET /enclaves/{id}/assets", s.handleAssetList)
	m.HandleFunc("GET /enclaves/{id}/assets/new", s.handleAssetForm)
	m.HandleFunc("POST /enclaves/{id}/assets/new", s.handleAssetSave)
	m.HandleFunc("GET /assets/{aid}", s.handleAssetDetail)
	m.HandleFunc("GET /assets/{aid}/edit", s.handleAssetForm)
	m.HandleFunc("POST /assets/{aid}/edit", s.handleAssetSave)
	m.HandleFunc("POST /assets/{aid}/delete", s.handleAssetDelete)

	m.HandleFunc("GET /enclaves/{id}/findings", s.handleFindingList)
	m.HandleFunc("GET /enclaves/{id}/findings/new", s.handleFindingForm)
	m.HandleFunc("POST /enclaves/{id}/findings/new", s.handleFindingSave)
	m.HandleFunc("GET /assets/{aid}/findings/new", s.handleFindingForm)
	m.HandleFunc("POST /assets/{aid}/findings/new", s.handleFindingSave)
	m.HandleFunc("GET /findings/{fid}", s.handleFindingDetail)
	m.HandleFunc("POST /findings/{fid}/disposition", s.handleDisposition)

	m.HandleFunc("GET /enclaves/{id}/baseline", s.handleGapAnalysis)
	m.HandleFunc("GET /enclaves/{id}/baseline/{cat}/{ctl}", s.handleControlDetail)
	m.HandleFunc("POST /enclaves/{id}/baseline/{cat}/{ctl}", s.handleAssessmentSave)

	m.HandleFunc("GET /enclaves/{id}/risk", s.handleRiskList)
	m.HandleFunc("GET /enclaves/{id}/risk/new", s.handleRiskForm)
	m.HandleFunc("POST /enclaves/{id}/risk/new", s.handleRiskSave)
	m.HandleFunc("GET /risk/{rid}/edit", s.handleRiskForm)
	m.HandleFunc("POST /risk/{rid}/edit", s.handleRiskSave)
	m.HandleFunc("POST /risk/{rid}/delete", s.handleRiskDelete)

	m.HandleFunc("GET /enclaves/{id}/scans", s.handleScanList)
	m.HandleFunc("GET /scans/{sid}", s.handleScanDetail)
	m.HandleFunc("POST /scans/{sid}/delete", s.handleScanDelete)
	m.HandleFunc("GET /import", s.handleImportForm)
	m.HandleFunc("POST /import", s.handleImportUpload)
	m.HandleFunc("POST /import/confirm", s.handleImportConfirm)

	m.HandleFunc("GET /catalogs", s.handleCatalogList)
	m.HandleFunc("GET /catalogs/{cid}", s.handleCatalogDetail)
	m.HandleFunc("POST /catalogs/import", s.handleCatalogImport)
	m.HandleFunc("POST /catalogs/{cid}/delete", s.handleCatalogDelete)

	m.HandleFunc("GET /mappings", s.handleMappingList)
	m.HandleFunc("GET /mappings/{mid}", s.handleMappingDetail)
	m.HandleFunc("POST /mappings/import", s.handleMappingImport)
	m.HandleFunc("POST /mappings/{mid}/delete", s.handleMappingDelete)
	m.HandleFunc("POST /mappings/reannotate", s.handleReannotate)

	m.HandleFunc("GET /data", s.handleData)
	m.HandleFunc("GET /data/backup", s.handleBackup)
	m.HandleFunc("POST /data/restore", s.handleRestore)
	m.HandleFunc("POST /data/snapshot", s.handleSnapshot)
	m.HandleFunc("GET /data/backups/{name}", s.handleSavedBundle)

	m.HandleFunc("GET /vulnerabilities", s.handleVulnList)
	m.HandleFunc("GET /vulnerabilities/{cve}", s.handleVulnDetail)

	m.HandleFunc("GET /reports", s.handleReports)
	m.HandleFunc("GET /export/{kind}", s.handleExportCSV)
	m.HandleFunc("GET /api/{kind}", s.handleAPI)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})

	m.HandleFunc("/", s.handleNotFound)
	s.mux = m
}

func cacheFor(d time.Duration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(d.Seconds())))
		h.ServeHTTP(w, r)
	})
}

func (s *Server) logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Nothing is loaded from another origin and nothing embeds these pages,
		// so the policy is as tight as the interface allows. Inline styles are
		// permitted because chart geometry is carried in style attributes;
		// scripts stay restricted to the single file served from here.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; "+
				"img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		h.ServeHTTP(rec, r)
		if rec.status >= 400 || time.Since(start) > time.Second {
			log.Printf("%s %s -> %d in %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// guard blocks a mutating request when the server is read-only.
func (s *Server) guard(w http.ResponseWriter, r *http.Request) bool {
	if !s.ReadOnly {
		return true
	}
	s.fail(w, r, http.StatusForbidden, "This ENCLAVE instance is running read-only, so nothing can be changed here.")
	return false
}

// page is the data every template receives.
type page struct {
	Title    string
	Nav      string
	SubNav   string
	Enclave  any
	Flash    string
	Error    string
	Data     any
	Version  string
	ReadOnly bool
	Now      time.Time
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	p.Version = s.Version
	p.ReadOnly = s.ReadOnly
	p.Now = time.Now()
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("ok")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("err")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf strings.Builder
	if err := s.tmpl.ExecuteTemplate(&buf, name, p); err != nil {
		log.Printf("rendering %s: %v", name, err)
		http.Error(w, "The page could not be rendered: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, buf.String())
}

// fail renders an error page rather than a bare status line, so that a wrong
// URL does not look like the application has fallen over.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, msg string) {
	w.WriteHeader(code)
	s.render(w, r, "error.html", page{
		Title: http.StatusText(code),
		Data:  map[string]any{"Code": code, "Status": http.StatusText(code), "Message": msg},
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.fail(w, r, http.StatusNotFound, "There is no page at "+r.URL.Path+".")
}

// redirect sends the browser somewhere with a message attached, which is how
// every form submission reports its outcome.
func redirect(w http.ResponseWriter, r *http.Request, to, ok, errMsg string) {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	switch {
	case errMsg != "":
		to += sep + "err=" + urlEscape(errMsg)
	case ok != "":
		to += sep + "ok=" + urlEscape(ok)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}
