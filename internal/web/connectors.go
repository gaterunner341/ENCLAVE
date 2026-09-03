package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/tenable"
)

// handleConnectors lists what has been set up. Connectors are things with
// identities that can be added and removed, not one set of settings pretending
// there can only ever be one console.
func (s *Server) handleConnectors(w http.ResponseWriter, r *http.Request) {
	dir := s.Store.Dir()
	all, err := tenable.LoadConnectors(dir)
	data := map[string]any{
		"Connectors": all,
		"EnvAccess":  tenable.EnvAccessKey,
		"EnvSecret":  tenable.EnvSecretKey,
		"Dir":        dir,
	}
	if err != nil {
		data["LoadError"] = err.Error()
	}
	live := 0
	type row struct {
		Connector   *tenable.Connector
		Credentials string
		OnDisk      bool
		Enclave     *model.Enclave
		Imports     int
	}
	rows := make([]row, 0, len(all))
	for _, c := range all {
		if c.Enabled {
			live++
		}
		creds, _ := tenable.LoadCredentials(dir, c.ID)
		rw := row{
			Connector: c, Credentials: creds.Source(),
			OnDisk: tenable.CredentialsOnDisk(dir, c.ID),
		}
		if e, ok := s.Store.Enclave(c.EnclaveID); ok {
			rw.Enclave = e
		}
		for _, sc := range s.Store.Scans("") {
			if strings.HasPrefix(sc.SourceRef, tenable.SourceName+":") &&
				strings.Contains(sc.Notes, c.Host()) {
				rw.Imports++
			}
		}
		rows = append(rows, rw)
	}
	data["Rows"] = rows
	data["Live"] = live

	// Listing what is on a console is a live call, so it happens only when
	// asked for rather than on every visit.
	if id := r.URL.Query().Get("list"); id != "" {
		results, host, err := s.tenableList(r.Context(), dir, id)
		if err != nil {
			data["ListError"] = err.Error()
		} else {
			data["Results"] = results
			data["ListedID"] = id
			data["ListedHost"] = host
		}
	}
	pulled := []*model.Scan{}
	for _, sc := range s.Store.Scans("") {
		if tenable.FromScan(sc) {
			pulled = append(pulled, sc)
		}
	}
	data["Pulled"] = firstN(pulled, 15)

	s.render(w, r, "connectors.html", page{Title: "Connectors", Nav: "import", Data: data})
}

func (s *Server) tenableList(ctx context.Context, dir, id string) ([]tenable.ScanResult, string, error) {
	sync, conn, err := s.syncer(dir, id)
	if err != nil {
		return nil, "", err
	}
	results, err := sync.Available(ctx, time.Now().AddDate(0, 0, -90))
	return results, conn.Host(), err
}

// syncer builds everything needed to talk to one connector.
func (s *Server) syncer(dir, id string) (*tenable.Syncer, *tenable.Connector, error) {
	conn, err := tenable.GetConnector(dir, id)
	if err != nil {
		return nil, nil, err
	}
	if !conn.Enabled {
		return nil, nil, errConnectorOff(conn)
	}
	creds, err := tenable.LoadCredentials(dir, id)
	if err != nil {
		return nil, nil, err
	}
	client, err := tenable.New(conn, creds)
	if err != nil {
		return nil, nil, err
	}
	return &tenable.Syncer{
		Store: s.Store, Importer: s.Importer, Client: client, Config: conn,
	}, conn, nil
}

func errConnectorOff(c *tenable.Connector) error {
	return &offError{name: c.Name}
}

type offError struct{ name string }

func (e *offError) Error() string {
	return e.name + " is switched off, so nothing will be fetched through it."
}

// handleConnectorForm adds one or edits an existing one.
func (s *Server) handleConnectorForm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	dir := s.Store.Dir()
	conn := &tenable.Connector{Kind: tenable.KindSecurityCenter, CreateAssets: true, Enabled: true}
	isNew := true
	if id := r.PathValue("cid"); id != "" {
		found, err := tenable.GetConnector(dir, id)
		if err != nil {
			s.fail(w, r, http.StatusNotFound, "No connector with that identifier.")
			return
		}
		conn, isNew = found, false
	}
	creds, _ := tenable.LoadCredentials(dir, conn.ID)
	envA, envS, _, _ := tenable.EnvNames(conn.ID)
	s.render(w, r, "connector_form.html", page{
		Title: connectorTitle(conn, isNew), Nav: "import",
		Data: s.connectorFormData(conn, isNew, creds, envA, envS),
	})
}

func connectorTitle(c *tenable.Connector, isNew bool) string {
	if isNew {
		return "Add a connector"
	}
	return "Edit " + c.Name
}

func (s *Server) connectorFormData(c *tenable.Connector, isNew bool, creds tenable.Credentials, envA, envS string) map[string]any {
	dir := s.Store.Dir()
	return map[string]any{
		"Connector": c, "IsNew": isNew,
		"Enclaves":    s.Store.Enclaves(),
		"Credentials": creds,
		"OnDisk":      !isNew && tenable.CredentialsOnDisk(dir, c.ID),
		"FromEnv":     !isNew && tenable.FromEnvironment(c.ID),
		"EnvAccess":   envA, "EnvSecret": envS,
		"PlainAccess": tenable.EnvAccessKey, "PlainSecret": tenable.EnvSecretKey,
		"Dir": dir,
	}
}

// handleConnectorSave writes one connector. Nothing here reaches the network.
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
	id := r.PathValue("cid")
	isNew := id == ""

	conn := &tenable.Connector{Kind: tenable.KindSecurityCenter}
	if !isNew {
		existing, err := tenable.GetConnector(dir, id)
		if err != nil {
			s.fail(w, r, http.StatusNotFound, "No connector with that identifier.")
			return
		}
		conn = existing
	}
	conn.Name = f.str("name")
	if isNew {
		conn.ID = model.SlugID(firstNonBlank(f.str("id"), f.str("name")))
	}
	conn.Enabled = f.bool("enabled")
	conn.URL = f.str("url")
	conn.EnclaveID = f.str("enclave_id")
	conn.PlaceByAddress = f.bool("place_by_address")
	conn.CreateAssets = f.bool("create_assets")
	conn.Repositories = f.csv("repositories")
	conn.CACertFile = f.str("ca_cert_file")
	conn.InsecureSkipVerify = f.bool("insecure_skip_verify")
	conn.TimeoutSeconds = f.int("timeout_seconds", 0)

	access, secret := f.str("access_key"), f.str("secret_key")
	user, pass := f.str("username"), f.str("password")
	creds := tenable.Credentials{AccessKey: access, SecretKey: secret, Username: user, Password: pass}
	envA, envS, _, _ := tenable.EnvNames(conn.ID)

	if err := tenable.SaveConnector(dir, conn); err != nil {
		s.render(w, r, "connector_form.html", page{
			Title: connectorTitle(conn, isNew), Nav: "import", Error: err.Error(),
			Data: s.connectorFormData(conn, isNew, creds, envA, envS),
		})
		return
	}

	msg := "Saved " + conn.Name + "."
	switch {
	case f.bool("forget_credentials"):
		if err := tenable.ForgetCredentials(dir, conn.ID); err != nil {
			redirect(w, r, "/connectors", "", err.Error())
			return
		}
		msg += " The stored credentials were removed."
	case creds.Complete():
		// Typing a key into the form is the intent to store it. Asking for a
		// separate tick and silently discarding what was typed without it was
		// a trap, and lost the secret with no word about it.
		if err := tenable.SaveCredentials(dir, conn.ID, creds); err != nil {
			redirect(w, r, "/connectors", "", err.Error())
			return
		}
		msg += " The credentials are stored in " + dir + ", readable only by this account."
	case access != "" || secret != "" || user != "" || pass != "":
		// Half a credential is not a credential, and dropping it silently is
		// how somebody ends up wondering why nothing works.
		redirect(w, r, "/connectors/"+conn.ID+"/edit", "",
			"Nothing was stored: an access key needs its secret key, and a username needs its password.")
		return
	}
	if !conn.Enabled {
		msg += " It is switched off, so nothing is fetched through it."
	}
	redirect(w, r, "/connectors", msg, "")
}

// handleConnectorDelete removes one, and its credentials with it.
func (s *Server) handleConnectorDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	dir := s.Store.Dir()
	conn, err := tenable.GetConnector(dir, r.PathValue("cid"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No connector with that identifier.")
		return
	}
	if err := tenable.DeleteConnector(dir, conn.ID); err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	msg := "Removed " + conn.Name + ", and any credentials stored for it."
	msg += " Results already imported through it are untouched."
	redirect(w, r, "/connectors", msg, "")
}

// handleConnectorTest makes one call, so a misconfiguration is found here
// rather than halfway through an import.
func (s *Server) handleConnectorTest(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	dir := s.Store.Dir()
	id := r.PathValue("cid")
	sync, conn, err := s.syncer(dir, id)
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), conn.Timeout())
	defer cancel()
	desc, err := sync.Client.Test(ctx)
	if err != nil {
		redirect(w, r, "/connectors", "", conn.Name+": "+err.Error())
		return
	}
	redirect(w, r, "/connectors?list="+urlEscape(id), conn.Name+" is working: "+desc+".", "")
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
	id := r.PathValue("cid")
	sync, conn, err := s.syncer(dir, id)
	if err != nil {
		redirect(w, r, "/connectors", "", err.Error())
		return
	}
	// A download of a busy console legitimately takes minutes.
	ctx, cancel := context.WithTimeout(context.Background(), conn.Timeout()*4)
	defer cancel()
	back := "/connectors?list=" + urlEscape(id)

	if f.bool("sync_all") {
		rep, err := sync.SyncAll(ctx, time.Now().AddDate(0, 0, -90), 25)
		if err != nil {
			redirect(w, r, "/connectors", "", conn.Name+": "+err.Error())
			return
		}
		tenable.RecordSync(dir, id)
		redirect(w, r, back, describeSync(conn, rep), joinErrors(rep.Errors))
		return
	}

	ids := f.list("result_ids")
	if len(ids) == 0 {
		redirect(w, r, back, "", "Choose which scan results to take.")
		return
	}
	available, err := sync.Available(ctx, time.Now().AddDate(0, 0, -365))
	if err != nil {
		redirect(w, r, "/connectors", "", conn.Name+": "+err.Error())
		return
	}
	byID := map[string]tenable.ScanResult{}
	for _, res := range available {
		byID[res.ID] = res
	}
	rep := &tenable.SyncReport{}
	for _, want := range ids {
		result, ok := byID[want]
		if !ok {
			rep.Errors = append(rep.Errors, "scan result "+want+" is no longer on the console")
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
	tenable.RecordSync(dir, id)
	redirect(w, r, back, describeSync(conn, rep), joinErrors(rep.Errors))
}

func joinErrors(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	return "Some results could not be taken: " + strings.Join(errs, "; ")
}

func describeSync(conn *tenable.Connector, rep *tenable.SyncReport) string {
	if rep.Imported == 0 {
		if rep.Skipped > 0 {
			return "Nothing new from " + conn.Name + ": everything checked was already on file or still running."
		}
		return "Nothing was taken from " + conn.Name + "."
	}
	return plural(rep.Imported, "Took 1 scan result", "Took "+itoa(rep.Imported)+" scan results") +
		" from " + conn.Name + ", covering " + itoa(rep.Assets) + " assets and " +
		itoa(rep.Findings) + " findings."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
