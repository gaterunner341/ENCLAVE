package web

import (
	"net/http"
	"strings"

	"github.com/gaterunner341/enclave/internal/model"
)

// handlePeople is the directory: who exists, what post each of them holds, and
// which enclaves name them.
func (s *Server) handlePeople(w http.ResponseWriter, r *http.Request) {
	people := s.Store.People()
	type row struct {
		Person   *model.Person
		Roles    []string
		Enclaves int
	}
	rows := make([]row, 0, len(people))
	for _, p := range people {
		use := s.Store.PersonUsage(p.ID)
		rw := row{Person: p, Enclaves: len(use.Enclaves)}
		for _, role := range use.Roles {
			rw.Roles = append(rw.Roles, role.Name+" (organisation-wide)")
		}
		// The per-enclave posts they hold, named once each.
		seen := map[string]bool{}
		for _, e := range use.Enclaves {
			for roleID, held := range e.Contacts {
				if held != p.ID || seen[roleID] {
					continue
				}
				seen[roleID] = true
				if role, ok := s.Store.Role(roleID); ok {
					rw.Roles = append(rw.Roles, role.Name)
				}
			}
		}
		rows = append(rows, rw)
	}
	s.render(w, r, "people.html", page{
		Title: "People and roles", Nav: "people",
		Data: map[string]any{
			"Rows":  rows,
			"Roles": s.Store.Roles(), "People": s.Store.ActivePeople(),
			"PersonIndex": s.Store.PersonIndex(),
			"Enclaves":    s.Store.Enclaves(),
		},
	})
}

func (s *Server) handlePersonForm(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	p := &model.Person{}
	if id := r.PathValue("pid"); id != "" {
		found, ok := s.Store.Person(id)
		if !ok {
			s.fail(w, r, http.StatusNotFound, "Nobody on file with that identifier.")
			return
		}
		p = found
	}
	title := "Add somebody"
	if p.ID != "" {
		title = "Edit " + p.Name
	}
	s.render(w, r, "person_form.html", page{
		Title: title, Nav: "people",
		Data: map[string]any{
			"Person": p, "IsNew": p.ID == "",
			"Usage": s.Store.PersonUsage(p.ID),
		},
	})
}

func (s *Server) handlePersonSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	p := &model.Person{}
	if id := r.PathValue("pid"); id != "" {
		prev, ok := s.Store.Person(id)
		if !ok {
			s.fail(w, r, http.StatusNotFound, "Nobody on file with that identifier.")
			return
		}
		cp := *prev
		p = &cp
	}
	p.Name = f.str("name")
	p.Title = f.str("title")
	p.Email = f.str("email")
	p.Phone = f.str("phone")
	p.Organization = f.str("organization")
	p.Location = f.str("location")
	p.Notes = f.str("notes")
	p.Inactive = f.bool("inactive")

	if err := s.Store.PutPerson(p); err != nil {
		s.render(w, r, "person_form.html", page{
			Title: "Person", Nav: "people", Error: err.Error(),
			Data: map[string]any{"Person": p, "IsNew": p.ID == "", "Usage": s.Store.PersonUsage(p.ID)},
		})
		return
	}
	redirect(w, r, "/people", "Saved "+p.Name+".", "")
}

func (s *Server) handlePersonDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	p, ok := s.Store.Person(r.PathValue("pid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "Nobody on file with that identifier.")
		return
	}
	// Removing somebody named on enclaves takes their name off those records,
	// so the name is typed to confirm it, as with deleting an enclave.
	use := s.Store.PersonUsage(p.ID)
	if f, _ := newForm(r); use.Any() && (f == nil || !strings.EqualFold(f.str("confirm"), p.Name)) {
		redirect(w, r, "/people/"+p.ID+"/edit", "",
			"Type the name exactly to confirm, because removing them takes their name off records that use it.")
		return
	}
	if err := s.Store.DeletePerson(p.ID); err != nil {
		redirect(w, r, "/people", "", err.Error())
		return
	}
	msg := "Removed " + p.Name + "."
	if use.Any() {
		msg += " Any role they held is now unassigned."
	}
	redirect(w, r, "/people", msg, "")
}

// handleRoleSave creates or updates a post, and records who holds an
// organisation-wide one.
func (s *Server) handleRoleSave(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	f, err := newForm(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	id := r.PathValue("rid")
	role := &model.Role{ID: id}
	if existing, ok := s.Store.Role(id); ok {
		role = &existing
	} else if id == "" {
		role.ID = model.SlugID(firstNonBlank(f.str("id"), f.str("name")))
		role.Order = 1000
	}
	role.Name = f.str("name")
	role.Description = f.str("description")
	role.Scope = model.RoleScope(f.str("scope"))
	if role.Scope == "" {
		role.Scope = model.ScopeSystem
	}
	role.Order = f.int("order", role.Order)
	if role.Scope == model.ScopeOrganization {
		role.Holder = f.str("holder")
	} else {
		// A post held separately for each enclave has no organisation-wide
		// holder, so keeping one would be a value nothing reads.
		role.Holder = ""
	}
	if err := s.Store.PutRole(role); err != nil {
		redirect(w, r, "/people", "", err.Error())
		return
	}
	redirect(w, r, "/people", "Saved the "+role.Name+" role.", "")
}

func (s *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	role, ok := s.Store.Role(r.PathValue("rid"))
	if !ok {
		s.fail(w, r, http.StatusNotFound, "No role with that identifier.")
		return
	}
	if err := s.Store.DeleteRole(role.ID); err != nil {
		redirect(w, r, "/people", "", err.Error())
		return
	}
	redirect(w, r, "/people", "Removed the "+role.Name+" role and every assignment to it.", "")
}
