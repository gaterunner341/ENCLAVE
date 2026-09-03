package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Person is somebody who holds a role over one or more enclaves. Keeping them
// in one place means a name is spelled the same everywhere, a change of post is
// one edit rather than twenty, and a report can say who to ask rather than what
// somebody typed into a box eighteen months ago.
type Person struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Title        string `json:"title,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Organization string `json:"organization,omitempty"`
	Location     string `json:"location,omitempty"`
	Notes        string `json:"notes,omitempty"`
	// Inactive keeps somebody who has left on file, so historical records still
	// resolve, without offering them for new assignments.
	Inactive bool      `json:"inactive,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

// Display is the name with the job title attached, which is how a person is
// identified in a dropdown where two people may share a surname.
func (p *Person) Display() string {
	if p == nil {
		return ""
	}
	if strings.TrimSpace(p.Title) == "" {
		return p.Name
	}
	return p.Name + ", " + p.Title
}

// Contact is the name and the way to reach them, for a page that has room.
func (p *Person) Contact() string {
	if p == nil {
		return ""
	}
	parts := []string{p.Name}
	if p.Email != "" {
		parts = append(parts, p.Email)
	}
	if p.Phone != "" {
		parts = append(parts, p.Phone)
	}
	return strings.Join(parts, " · ")
}

// Validate checks what a person filling in the form can get wrong.
func (p *Person) Validate() error {
	var problems []string
	if strings.TrimSpace(p.Name) == "" {
		problems = append(problems, "a name is required")
	}
	if e := strings.TrimSpace(p.Email); e != "" && !emailish.MatchString(e) {
		problems = append(problems, "that does not look like an email address: "+e)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// emailish is deliberately loose. The point is to catch a phone number typed
// into the email box, not to adjudicate the addressing standards.
var emailish = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// RoleScope says whether a role is held once for the whole organisation or
// separately for each enclave. A Chief Information Officer is the same person
// across every system; a System Owner is not.
type RoleScope string

const (
	ScopeOrganization RoleScope = "organization"
	ScopeSystem       RoleScope = "system"
)

func (s RoleScope) Label() string {
	if s == ScopeOrganization {
		return "Held once for the organisation"
	}
	return "Held separately for each enclave"
}

// Role is a post somebody holds. The set is editable, because the titles differ
// between organisations and ENCLAVE has no business insisting on its own.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Scope       RoleScope `json:"scope"`
	// Order decides where the role appears on a form. Roles are read in a
	// conventional order and shuffling them is confusing.
	Order int `json:"order"`
	// Holder is the person who holds an organisation-scoped role. Every enclave
	// inherits it unless it names somebody else.
	Holder string `json:"holder,omitempty"`
	// BuiltIn marks the roles ENCLAVE ships with, which can be renamed and
	// reordered but are restored if removed and the data is reloaded.
	BuiltIn bool `json:"built_in,omitempty"`
}

// Validate checks a role definition.
func (r *Role) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("a role needs a name")
	}
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("role identifier must be 2-64 characters of letters, digits, dot, dash or underscore")
	}
	if r.Scope != ScopeOrganization && r.Scope != ScopeSystem {
		return fmt.Errorf("a role is held either for the organisation or for each enclave")
	}
	return nil
}

// DefaultRoles are the posts ENCLAVE starts with. They are the ones most
// commonly recorded against a system, and every one of them can be renamed,
// reordered, removed or added to.
func DefaultRoles() []Role {
	return []Role{
		{ID: "cio", Name: "Chief Information Officer", Scope: ScopeOrganization, Order: 10, BuiltIn: true,
			Description: "Accountable for the organisation's information technology."},
		{ID: "ciso", Name: "Chief Information Security Officer", Scope: ScopeOrganization, Order: 20, BuiltIn: true,
			Description: "Accountable for the organisation's security programme."},
		{ID: "ao", Name: "Authorizing Official", Scope: ScopeOrganization, Order: 30, BuiltIn: true,
			Description: "Accepts the risk of operating a system, and signs the authorisation."},
		{ID: "system-owner", Name: "System Owner", Scope: ScopeSystem, Order: 40, BuiltIn: true,
			Description: "Responsible for the enclave's operation and its security posture."},
		{ID: "data-owner", Name: "Data Owner", Scope: ScopeSystem, Order: 50, BuiltIn: true,
			Description: "Responsible for the information the enclave holds and who may see it."},
		{ID: "iso", Name: "Information Security Officer", Scope: ScopeSystem, Order: 60, BuiltIn: true,
			Description: "Day-to-day security responsibility for the enclave."},
	}
}

// SortRoles puts roles into their declared order, then alphabetically, so a
// form reads the same way every time.
func SortRoles(roles []Role) {
	sort.Slice(roles, func(i, j int) bool {
		if roles[i].Order != roles[j].Order {
			return roles[i].Order < roles[j].Order
		}
		return strings.ToLower(roles[i].Name) < strings.ToLower(roles[j].Name)
	})
}

// Contact resolves who holds a role over this enclave: the person the enclave
// names, or the organisation-wide holder when it names nobody.
//
// The distinction matters on the page: an inherited name is a fact about the
// organisation, and a named one is a decision about this system.
func (e *Enclave) Contact(role Role) (personID string, inherited bool) {
	if e != nil && e.Contacts != nil {
		if id := strings.TrimSpace(e.Contacts[role.ID]); id != "" {
			return id, false
		}
	}
	if role.Scope == ScopeOrganization && strings.TrimSpace(role.Holder) != "" {
		return role.Holder, true
	}
	return "", false
}
