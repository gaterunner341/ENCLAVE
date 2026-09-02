package web

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/pkittelson/enclave/internal/model"
	"github.com/pkittelson/enclave/internal/store"
)

// frameworks are the control frameworks an enclave can be held to. The choice
// is recorded rather than enforced: it says which language a finding should be
// written in when it leaves here.
var frameworks = map[string]bool{"cis": true, "csf": true, "iso": true, "nist": true}

var impacts = map[string]bool{"Low": true, "Moderate": true, "High": true}

func (s *Server) enclaves(w http.ResponseWriter, r *http.Request) {
	d := s.base("enclaves")
	d.AllEnclaves = s.store.ActiveEnclaves()
	d.Enclaves, d.EnclaveCounts = s.engine.enclaveViews(d.AllEnclaves)
	if id := r.URL.Query().Get("edit"); id != "" {
		d.Edit = s.store.Enclave(id)
	}
	s.render(w, r, d)
}

// enclaveSave adds or updates an enclave. The address ranges are parsed here
// rather than at match time, because a typo that silently stops matching hosts
// is the worst failure this program has.
func (s *Server) enclaveSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.flashRedirect(w, r, "/enclaves", "That form could not be read.", true)
		return
	}
	id := strings.ToUpper(strings.TrimSpace(r.FormValue("id")))
	if id == "" {
		s.flashRedirect(w, r, "/enclaves", "An enclave needs an identifier.", true)
		return
	}

	var cidrs []string
	for _, raw := range strings.Split(r.FormValue("cidrs"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			s.flashRedirect(w, r, "/enclaves",
				fmt.Sprintf("%q is not an address range. Write it as 10.12.0.0/16.", raw), true)
			return
		}
		cidrs = append(cidrs, p.Masked().String())
	}
	if len(cidrs) == 0 {
		s.flashRedirect(w, r, "/enclaves", "Give the enclave at least one address range.", true)
		return
	}

	impact := r.FormValue("impact")
	if !impacts[impact] {
		impact = "Moderate"
	}
	framework := r.FormValue("framework")
	if !frameworks[framework] {
		framework = "cis"
	}

	enc := &model.Enclave{
		ID:        id,
		Name:      strings.TrimSpace(r.FormValue("name")),
		CIDRs:     cidrs,
		Owner:     strings.TrimSpace(r.FormValue("owner")),
		Impact:    impact,
		Framework: framework,
		Exposed:   r.FormValue("exposed") != "",
		CreatedAt: time.Now(),
	}
	if err := s.store.PutEnclave(enc); err != nil {
		s.flashRedirect(w, r, "/enclaves", "That enclave could not be saved: "+err.Error(), true)
		return
	}
	if err := s.engine.Rebuild(); err != nil {
		s.flashRedirect(w, r, "/enclaves", "Saved, but the view could not be rebuilt: "+err.Error(), true)
		return
	}
	s.flashRedirect(w, r, "/enclaves", id+" saved. Hosts have been placed again.", false)
}

// enclaveDelete removes an enclave, refusing while it still holds hosts.
func (s *Server) enclaveDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.flashRedirect(w, r, "/enclaves", "That form could not be read.", true)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	held := 0
	for _, h := range s.engine.Hosts("") {
		if h.EnclaveID == id {
			held++
		}
	}
	if err := s.store.DeleteEnclave(id, held); err != nil {
		s.flashRedirect(w, r, "/enclaves", err.Error(), true)
		return
	}
	if err := s.engine.Rebuild(); err != nil {
		s.flashRedirect(w, r, "/enclaves", "Removed, but the view could not be rebuilt: "+err.Error(), true)
		return
	}
	s.flashRedirect(w, r, "/enclaves", id+" removed.", false)
}

// mappingDelete forgets a saved column mapping.
func (s *Server) mappingDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.flashRedirect(w, r, "/import", "That form could not be read.", true)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if err := s.store.DeleteMapping(name); err != nil {
		s.flashRedirect(w, r, "/import", "That mapping could not be removed: "+err.Error(), true)
		return
	}
	s.flashRedirect(w, r, "/import", "\""+name+"\" removed.", false)
}

// assign places a host by hand. The decision is recorded separately from the
// log so a later import cannot quietly overturn it.
func (s *Server) assign(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.flashRedirect(w, r, "/unassigned", "That form could not be read.", true)
		return
	}
	hostID := strings.TrimSpace(r.FormValue("host"))
	enclaveID := strings.TrimSpace(r.FormValue("enclave"))

	host := s.engine.Host(hostID)
	if host == nil {
		s.flashRedirect(w, r, "/unassigned", "That host is no longer in the inventory.", true)
		return
	}
	if s.store.Enclave(enclaveID) == nil {
		s.flashRedirect(w, r, "/unassigned", "That enclave no longer exists.", true)
		return
	}

	if err := s.store.PutDecision(&store.Decision{
		HostID:    hostID,
		EnclaveID: enclaveID,
		Reason:    "assigned by hand from the claim queue",
		At:        time.Now(),
		By:        "console",
	}); err != nil {
		s.flashRedirect(w, r, "/unassigned", "That assignment could not be saved: "+err.Error(), true)
		return
	}
	name := host.DisplayName()
	if err := s.engine.Rebuild(); err != nil {
		s.flashRedirect(w, r, "/unassigned", "Assigned, but the view could not be rebuilt: "+err.Error(), true)
		return
	}
	s.flashRedirect(w, r, "/unassigned", name+" assigned to "+enclaveID+".", false)
}
