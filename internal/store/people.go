package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// People returns the directory, active people first, then alphabetically.
func (s *Store) People() []*model.Person {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortPeople(s.people)
}

// ActivePeople is the directory without anybody marked as having left, which is
// what a dropdown for a new assignment should offer.
func (s *Store) ActivePeople() []*model.Person {
	out := []*model.Person{}
	for _, p := range s.People() {
		if !p.Inactive {
			out = append(out, p)
		}
	}
	return out
}

func sortPeople(m map[string]*model.Person) []*model.Person {
	out := make([]*model.Person, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Inactive != out[j].Inactive {
			return !out[i].Inactive
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// Person looks somebody up.
func (s *Store) Person(id string) (*model.Person, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.people[id]
	return p, ok
}

// PersonIndex maps identifiers to records, for a page that renders many names.
func (s *Store) PersonIndex() map[string]*model.Person {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*model.Person, len(s.people))
	for k, v := range s.people {
		out[k] = v
	}
	return out
}

// PutPerson creates or updates somebody.
func (s *Store) PutPerson(p *model.Person) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if p.ID == "" {
		p.ID = s.NextID("person")
	}
	if prev, ok := s.people[p.ID]; ok {
		p.Created = prev.Created
	} else if p.Created.IsZero() {
		p.Created = now
	}
	p.Updated = now
	s.people[p.ID] = p
	s.dirty["people"] = true
	return s.saveLocked()
}

// PersonUse reports where somebody is named, so that removing them can say what
// it would leave behind rather than quietly breaking references.
type PersonUse struct {
	Enclaves []*model.Enclave
	Roles    []model.Role
}

// Any reports whether the person is referenced anywhere.
func (u PersonUse) Any() bool { return len(u.Enclaves) > 0 || len(u.Roles) > 0 }

// PersonUsage finds every enclave and organisation-wide role that names them.
func (s *Store) PersonUsage(id string) PersonUse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	use := PersonUse{}
	for _, e := range s.enclaves {
		for _, held := range e.Contacts {
			if held == id {
				use.Enclaves = append(use.Enclaves, e)
				break
			}
		}
	}
	sort.Slice(use.Enclaves, func(i, j int) bool { return use.Enclaves[i].Name < use.Enclaves[j].Name })
	for _, r := range s.roles {
		if r.Holder == id {
			use.Roles = append(use.Roles, *r)
		}
	}
	model.SortRoles(use.Roles)
	return use
}

// DeletePerson removes somebody and every reference to them. Leaving dangling
// references would put a blank where a name used to be with no explanation, so
// the caller is expected to have been shown the usage first.
func (s *Store) DeletePerson(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.people[id]; !ok {
		return fmt.Errorf("no person %q", id)
	}
	delete(s.people, id)
	touchedEnclaves := false
	for _, e := range s.enclaves {
		for role, held := range e.Contacts {
			if held == id {
				delete(e.Contacts, role)
				touchedEnclaves = true
			}
		}
	}
	touchedRoles := false
	for _, r := range s.roles {
		if r.Holder == id {
			r.Holder = ""
			touchedRoles = true
		}
	}
	s.dirty["people"] = true
	s.dirty["enclaves"] = touchedEnclaves || s.dirty["enclaves"]
	s.dirty["roles"] = touchedRoles || s.dirty["roles"]
	return s.saveLocked()
}

// ---------- roles ----------

// Roles returns the posts in the order they should be shown.
func (s *Store) Roles() []model.Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Role, 0, len(s.roles))
	for _, r := range s.roles {
		out = append(out, *r)
	}
	model.SortRoles(out)
	return out
}

// RolesInScope returns the roles held for the organisation, or the ones held
// per enclave.
func (s *Store) RolesInScope(scope model.RoleScope) []model.Role {
	out := []model.Role{}
	for _, r := range s.Roles() {
		if r.Scope == scope {
			out = append(out, r)
		}
	}
	return out
}

// Role looks one up.
func (s *Store) Role(id string) (model.Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[id]
	if !ok {
		return model.Role{}, false
	}
	return *r, true
}

// PutRole creates or updates a post.
func (s *Store) PutRole(r *model.Role) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.roles[r.ID]; ok {
		// A built-in role stays built in however it is renamed, so that it is
		// restored rather than lost if the file is ever rebuilt.
		r.BuiltIn = prev.BuiltIn
	}
	if r.Holder != "" {
		if _, ok := s.people[r.Holder]; !ok {
			return fmt.Errorf("there is nobody with identifier %q to hold that role", r.Holder)
		}
	}
	s.roles[r.ID] = r
	s.dirty["roles"] = true
	return s.saveLocked()
}

// DeleteRole removes a post and every assignment to it.
func (s *Store) DeleteRole(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[id]; !ok {
		return fmt.Errorf("no role %q", id)
	}
	delete(s.roles, id)
	for _, e := range s.enclaves {
		if _, held := e.Contacts[id]; held {
			delete(e.Contacts, id)
			s.dirty["enclaves"] = true
		}
	}
	s.dirty["roles"] = true
	return s.saveLocked()
}

// SetContact records who holds a role over one enclave. An empty person
// identifier clears it, which for an organisation-scoped role means falling
// back to whoever holds it organisation-wide.
func (s *Store) SetContact(enclaveID, roleID, personID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enclaves[enclaveID]
	if !ok {
		return fmt.Errorf("no enclave %q", enclaveID)
	}
	if _, ok := s.roles[roleID]; !ok {
		return fmt.Errorf("no role %q", roleID)
	}
	if personID != "" {
		if _, ok := s.people[personID]; !ok {
			return fmt.Errorf("there is nobody with identifier %q", personID)
		}
	}
	if e.Contacts == nil {
		e.Contacts = map[string]string{}
	}
	if personID == "" {
		delete(e.Contacts, roleID)
	} else {
		e.Contacts[roleID] = personID
	}
	e.Updated = time.Now().UTC()
	s.dirty["enclaves"] = true
	return s.saveLocked()
}

// Contacts resolves every role for one enclave, in display order.
type Contact struct {
	Role      model.Role
	Person    *model.Person
	Inherited bool
}

// Contacts is who holds each role over the enclave, including the ones
// inherited from the organisation.
func (s *Store) Contacts(enclaveID string) []Contact {
	e, _ := s.Enclave(enclaveID)
	people := s.PersonIndex()
	out := []Contact{}
	for _, role := range s.Roles() {
		id, inherited := e.Contact(role)
		out = append(out, Contact{Role: role, Person: people[id], Inherited: inherited})
	}
	return out
}
