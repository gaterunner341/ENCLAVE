package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// migrateContactsToPeople turns the free-text owner and security contact fields
// that enclaves used to carry into records in the directory, and points the
// enclaves at them by role.
//
// It works on the files rather than on loaded records, because the fields it
// reads no longer exist on the struct: a typed load would drop them before the
// migration could see them.
//
// Two people who were typed the same way become one record. Two who were typed
// differently stay separate, because guessing that "D. Rennick" and "Dave
// Rennick" are the same person is not a guess a tool should make on somebody's
// authorisation record.
func migrateContactsToPeople(dir string) error {
	path := filepath.Join(dir, "enclaves.json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// Decoded loosely, so the fields being retired are still readable.
	var enclaves []map[string]any
	if err := json.Unmarshal(raw, &enclaves); err != nil {
		return fmt.Errorf("reading enclaves.json: %w", err)
	}

	people, err := loadPeopleFile(dir)
	if err != nil {
		return err
	}
	byName := map[string]*model.Person{}
	for _, p := range people {
		byName[strings.ToLower(strings.TrimSpace(p.Name))] = p
	}

	now := time.Now().UTC()
	seq := 0
	find := func(name string) *model.Person {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			return nil
		}
		if p, ok := byName[key]; ok {
			return p
		}
		seq++
		p := &model.Person{
			ID:      fmt.Sprintf("person-migrated-%04d", seq),
			Name:    strings.TrimSpace(name),
			Notes:   "Created automatically from a point of contact recorded before the directory existed.",
			Created: now, Updated: now,
		}
		byName[key] = p
		people = append(people, p)
		return p
	}

	changed := false
	for _, e := range enclaves {
		contacts := map[string]string{}
		if existing, ok := e["contacts"].(map[string]any); ok {
			for k, v := range existing {
				if id, ok := v.(string); ok {
					contacts[k] = id
				}
			}
		}
		// The two fields being retired map onto the two roles that carried the
		// same meaning.
		for field, role := range map[string]string{
			"owner":            "system-owner",
			"security_contact": "iso",
		} {
			name, _ := e[field].(string)
			if strings.TrimSpace(name) == "" {
				continue
			}
			if _, already := contacts[role]; already {
				continue
			}
			if p := find(name); p != nil {
				contacts[role] = p.ID
				changed = true
			}
		}
		delete(e, "owner")
		delete(e, "security_contact")
		if len(contacts) > 0 {
			e["contacts"] = contacts
		}
	}

	if err := savePeopleFile(dir, people); err != nil {
		return err
	}
	if err := ensureRolesFile(dir); err != nil {
		return err
	}
	if !changed && len(enclaves) == 0 {
		return nil
	}
	return writeJSON(path, enclaves)
}

func loadPeopleFile(dir string) ([]*model.Person, error) {
	b, err := os.ReadFile(filepath.Join(dir, "people.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var people []*model.Person
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(b, &people); err != nil {
		return nil, fmt.Errorf("reading people.json: %w", err)
	}
	return people, nil
}

func savePeopleFile(dir string, people []*model.Person) error {
	if len(people) == 0 {
		return nil
	}
	return writeJSON(filepath.Join(dir, "people.json"), people)
}

// ensureRolesFile writes the built-in posts if the data set has none, so that
// the contacts the migration just created have somewhere to hang.
func ensureRolesFile(dir string) error {
	path := filepath.Join(dir, "roles.json")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 2 {
		return nil
	}
	roles := model.DefaultRoles()
	out := make([]*model.Role, 0, len(roles))
	for i := range roles {
		out = append(out, &roles[i])
	}
	return writeJSON(path, out)
}
