package web

import (
	"fmt"
	"net/http"

	"github.com/gaterunner341/enclave/internal/store"
)

// handleUnplaced lists assets that no enclave page would show, and assets
// sitting in an enclave their addresses disagree with.
func (s *Server) handleUnplaced(w http.ResponseWriter, r *http.Request) {
	all := s.Store.UnplacedAssets()
	orphaned := []store.Placement{}
	misfiled := []store.Placement{}
	for _, p := range all {
		if p.Problem.Orphaned() {
			orphaned = append(orphaned, p)
		} else {
			misfiled = append(misfiled, p)
		}
	}
	// How many assets could not be checked at all, so the page does not imply
	// that everything else has been verified.
	unverifiable := 0
	for _, a := range s.Store.AllAssets() {
		if len(a.IPs) == 0 {
			unverifiable++
		}
	}
	s.render(w, r, "unplaced.html", page{
		Title: "Unplaced assets", Nav: "enclaves",
		Data: map[string]any{
			"Orphaned": orphaned, "Misfiled": misfiled,
			"Enclaves": s.Store.Enclaves(), "Total": len(s.Store.AllAssets()),
			"Unverifiable": unverifiable,
		},
	})
}

// handleMoveAssets reassigns assets to an enclave.
func (s *Server) handleMoveAssets(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	ids := f.list("asset_ids")
	if len(ids) == 0 {
		redirect(w, r, "/assets/unplaced", "", "Choose at least one asset to move.")
		return
	}
	target := f.str("enclave_id")
	moved, err := s.Store.MoveAssets(ids, target)
	if err != nil {
		redirect(w, r, "/assets/unplaced", "", err.Error())
		return
	}
	name := target
	if e, ok := s.Store.Enclave(target); ok {
		name = e.Name
	}
	back := f.str("return")
	if back == "" {
		back = "/assets/unplaced"
	}
	redirect(w, r, back, fmt.Sprintf("Moved %d assets into %s, with their findings.", moved, name), "")
}
