package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/tenable"
)

// handleConnectors is where the one outbound connection ENCLAVE can make is
// turned on, configured and used.
func (s *Server) handleConnectors(w http.ResponseWriter, r *http.Request) {
	cfg, cfgErr := tenable.LoadConfig(s.Store.Dir())
	creds, credErr := tenable.LoadCredentials(s.Store.Dir())

	data := map[string]any{
		"Config": cfg, "Credentials": creds,
		"OnDisk":    tenable.CredentialsOnDisk(s.Store.Dir()),
		"Enclaves":  s.Store.Enclaves(),
		"EnvAccess": tenable.EnvAccessKey, "EnvSecret": tenable.EnvSecretKey,
		"Dir": s.Store.Dir(),
	}
	if cfgErr != nil {
		data["ConfigError"] = cfgErr.Error()
	}
	if credErr != nil {
		data["CredentialError"] = credErr.Error()
	}

	// Listing what is on the console is a live call, so it happens only when
	// asked for rather than on every visit to the page.
	if r.URL.Query().Get("list") == "1" && cfg.Enabled {
		results, err := s.tenableResults(r.Context(), cfg, creds)
		if err != nil {
			data["ListError"] = err.Error()
		} else {
			data["Results"] = results
		}
	}
	// Imports the connector has already made, so the page shows its own history.
	pulled := []*model.Scan{}
	for _, sc := range s.Store.Scans("") {
		if tenable.FromScan(sc) {
			pulled = append(pulled, sc)
		}
	}
	data["Pulled"] = firstN(pulled, 15)

	s.render(w, r, "connectors.html", page{
		Title: "Connectors", Nav: "connectors", Data: data,
	})
}

func (s *Server) tenableResults(ctx context.Context, cfg tenable.Config, creds tenable.Credentials) ([]tenable.ScanResult, error) {
	sync, err := s.tenableSyncer(cfg, creds)
	if err != nil {
		return nil, err
	}
	// Ninety days is enough history to find what somebody is looking for
	// without asking a busy console for everything it has ever run.
	return sync.Available(ctx, time.Now().AddDate(0, 0, -90))
}

func (s *Server) tenableSyncer(cfg tenable.Config, creds tenable.Credentials) (*tenable.Syncer, error) {
	client, err := tenable.New(cfg, creds)
	if err != nil {
		return nil, err
	}
	return &tenable.Syncer{
		Store: s.Store, Importer: s.Importer, Client: client, Config: cfg,
	}, nil
}

// handleConnectorSave records the settings. Nothing here reaches the network.
func (s *Server) handleConnectorSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	dir := s.Store.Dir()
	cfg, _ := tenable.LoadConfig(dir)
	cfg.Enabled = f.bool("enabled")
	cfg.URL = f.str("url")
	cfg.EnclaveID = f.str("enclave_id")
	cfg.PlaceByAddress = f.bool("place_by_address")
	cfg.CreateAssets = f.bool("create_assets")
	cfg.Repositories = f.csv("repositories")
	cfg.CACertFile = f.str("ca_cert_file")
	cfg.InsecureSkipVerify = f.bool("insecure_skip_verify")
	cfg.TimeoutSeconds = f.int("timeout_seconds", 0)

	if err := cfg.Validate(); err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	if err := tenable.SaveConfig(dir, cfg); err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}

	// Credentials are handled separately, because writing a secret to disk is a
	// decision somebody makes rather than a side effect of saving a form.
	access, secret := f.str("access_key"), f.str("secret_key")
	user, pass := f.str("username"), f.str("password")
	switch {
	case f.bool("forget_credentials"):
		if err := tenable.ForgetCredentials(dir); err != nil {
			redirect(w, r, "/connectors", "", err.Error())
			return
		}
		redirect(w, r, "/connectors", "Saved. The stored credentials were removed.", "")
		return
	case f.bool("store_credentials") && (access != "" || user != ""):
		creds := tenable.Credentials{AccessKey: access, SecretKey: secret, Username: user, Password: pass}
		if err := tenable.SaveCredentials(dir, creds); err != nil {
			redirect(w, r, "/connectors", "", err.Error())
			return
		}
		redirect(w, r, "/connectors",
			"Saved. The credentials are on disk in "+dir+", readable only by this account.", "")
		return
	}
	msg := "Saved."
	if !cfg.Enabled {
		msg += " The connector is off, so ENCLAVE makes no outbound connection."
	}
	redirect(w, r, "/connectors", msg, "")
}

// handleConnectorTest makes one call, so that a misconfiguration is found here
// rather than halfway through an import.
func (s *Server) handleConnectorTest(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	cfg, err := tenable.LoadConfig(s.Store.Dir())
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	if !cfg.Enabled {
		redirect(w, r, "/connectors", "", "Turn the connector on before testing it.")
		return
	}
	creds, err := tenable.LoadCredentials(s.Store.Dir())
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	client, err := tenable.New(cfg, creds)
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout())
	defer cancel()
	desc, err := client.Test(ctx)
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	redirect(w, r, "/connectors?list=1", "Working: "+desc+".", "")
}

// handleConnectorImport pulls the chosen results, or everything outstanding.
func (s *Server) handleConnectorImport(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	dir := s.Store.Dir()
	cfg, err := tenable.LoadConfig(dir)
	if err != nil || !cfg.Enabled {
		redirect(w, r, "/connectors", "", "The connector is not turned on.")
		return
	}
	creds, err := tenable.LoadCredentials(dir)
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	sync, err := s.tenableSyncer(cfg, creds)
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	// A download of a large console can legitimately take minutes, so the
	// deadline is the configured timeout per result rather than the request.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout()*4)
	defer cancel()

	if f.bool("sync_all") {
		rep, err := sync.SyncAll(ctx, time.Now().AddDate(0, 0, -90), 25)
		if err != nil {
			redirect(w, r, "/connectors", "", err.Error())
			return
		}
		msg := describeSync(rep)
		errMsg := ""
		if len(rep.Errors) > 0 {
			errMsg = "Some results could not be taken: " + strings.Join(rep.Errors, "; ")
		}
		recordSync(dir, cfg)
		redirect(w, r, "/connectors?list=1", msg, errMsg)
		return
	}

	ids := f.list("result_ids")
	if len(ids) == 0 {
		redirect(w, r, "/connectors?list=1", "", "Choose which scan results to take.")
		return
	}
	available, err := sync.Available(ctx, time.Now().AddDate(0, 0, -365))
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	byID := map[string]tenable.ScanResult{}
	for _, r := range available {
		byID[r.ID] = r
	}
	rep := &tenable.SyncReport{}
	for _, id := range ids {
		result, ok := byID[id]
		if !ok {
			rep.Errors = append(rep.Errors, "scan result "+id+" is no longer on the console")
			continue
		}
		rep.Checked++
		out, err := sync.Import(ctx, result, f.bool("force"))
		if err != nil {
			rep.Errors = append(rep.Errors, result.Name+": "+err.Error())
			continue
		}
		if out.Skipped != "" {
			rep.Skipped++
			continue
		}
		rep.Imported++
		rep.Findings += out.Summary.FindingsAdded + out.Summary.FindingsUpdated
		rep.Assets += out.Summary.AssetsCreated + out.Summary.AssetsMatched
	}
	errMsg := ""
	if len(rep.Errors) > 0 {
		errMsg = strings.Join(rep.Errors, "; ")
	}
	recordSync(dir, cfg)
	redirect(w, r, "/connectors?list=1", describeSync(rep), errMsg)
}

func recordSync(dir string, cfg tenable.Config) {
	now := time.Now().UTC()
	cfg.LastSync = &now
	_ = tenable.SaveConfig(dir, cfg)
}

func describeSync(rep *tenable.SyncReport) string {
	if rep.Imported == 0 {
		if rep.Skipped > 0 {
			return "Nothing new: everything checked was already on file or still running."
		}
		return "Nothing was taken."
	}
	return plural(rep.Imported, "Took 1 scan result", "Took "+itoa(rep.Imported)+" scan results") +
		", covering " + itoa(rep.Assets) + " assets and " + itoa(rep.Findings) + " findings."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
