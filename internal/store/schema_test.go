package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gaterunner341/enclave/internal/model"
)

func TestOpenStampsANewDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	stamp, stamped, err := ReadStamp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !stamped {
		t.Fatal("a new data directory should be stamped, so the next build knows what it is")
	}
	if stamp.Schema != SchemaVersion {
		t.Errorf("schema = %d, want %d", stamp.Schema, SchemaVersion)
	}
	if stamp.WrittenAt.IsZero() {
		t.Error("the stamp should record when it was written")
	}
}

func TestUnstampedDataIsAdoptedNotRejected(t *testing.T) {
	// A directory written by a build from before stamping existed still has to
	// open, or upgrading would strand everybody who already had data.
	dir := t.TempDir()
	body, err := json.Marshal([]*model.Enclave{{ID: "CORE", Name: "Core"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enclaves.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("unstamped data should open: %v", err)
	}
	if len(s.Enclaves()) != 1 {
		t.Error("the existing records were not read")
	}
	if _, stamped, _ := ReadStamp(dir); !stamped {
		t.Error("opening unstamped data should stamp it")
	}
}

func TestDataFromANewerBuildIsRefusedClearly(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, stampFile), Stamp{Schema: SchemaVersion + 5, WrittenBy: "v9.9"}); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir)
	if err == nil {
		t.Fatal("data from a newer schema should be refused rather than guessed at")
	}
	var newer *ErrNewerSchema
	if !errors.As(err, &newer) {
		t.Fatalf("expected a schema error, got %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range []string{"v9.9", "upgrade ENCLAVE"} {
		if !contains(msg, want) {
			t.Errorf("the message should mention %q: %s", want, msg)
		}
	}
}

func TestUnreadableStampIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stampFile), []byte("{ nonsense"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Error("a corrupt stamp should be reported, not ignored")
	}
}

func TestReloadPicksUpDataChangedUnderneath(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutEnclave(&model.Enclave{ID: "CORE", Name: "Core"}); err != nil {
		t.Fatal(err)
	}

	// Another process, or a restore, replaces the files on disk.
	body, _ := json.Marshal([]*model.Enclave{{ID: "OTHER", Name: "Somewhere else"}})
	if err := os.WriteFile(filepath.Join(dir, "enclaves.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Enclave("OTHER"); !ok {
		t.Error("reload did not pick up the replaced data")
	}
	if _, ok := s.Enclave("CORE"); ok {
		t.Error("reload should discard what was in memory, not merge with it")
	}
}

func TestReloadLeavesTheStoreAloneWhenTheFilesAreBroken(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutEnclave(&model.Enclave{ID: "CORE", Name: "Core"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enclaves.json"), []byte("{ broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("reloading broken files should report an error")
	}
	if _, ok := s.Enclave("CORE"); !ok {
		t.Error("a failed reload emptied the running store")
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestMigrationTurnsTypedContactsIntoPeople(t *testing.T) {
	dir := t.TempDir()
	// A data set as an earlier build wrote it: schema 1, contacts as free text.
	old := `[
	  {"id":"CORE","name":"Core Operations","owner":"D. Rennick","security_contact":"S. Ortiz",
	   "confidentiality":"moderate","integrity":"moderate","availability":"high",
	   "created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"},
	  {"id":"LAB","name":"Engineering Lab","owner":"D. Rennick",
	   "confidentiality":"low","integrity":"low","availability":"low",
	   "created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}
	]`
	if err := os.WriteFile(filepath.Join(dir, "enclaves.json"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, stampFile), Stamp{Schema: 1, WrittenBy: "old"}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("data from the previous schema should open: %v", err)
	}
	if stamp, _, _ := ReadStamp(dir); stamp.Schema != SchemaVersion {
		t.Errorf("the directory was not re-stamped: %d", stamp.Schema)
	}

	// The two names became two people, and the one named twice became one.
	people := s.People()
	if len(people) != 2 {
		t.Fatalf("expected 2 people, got %d: %v", len(people), names(people))
	}
	byName := map[string]string{}
	for _, p := range people {
		byName[p.Name] = p.ID
	}
	if byName["D. Rennick"] == "" || byName["S. Ortiz"] == "" {
		t.Fatalf("the typed names were not carried across: %v", names(people))
	}

	// And the enclaves point at them by role.
	core, _ := s.Enclave("CORE")
	ownerRole, ok := s.Role("system-owner")
	if !ok {
		t.Fatal("the built-in roles were not created")
	}
	if id, _ := core.Contact(ownerRole); id != byName["D. Rennick"] {
		t.Errorf("CORE's System Owner = %q, want the record for D. Rennick", id)
	}
	isoRole, _ := s.Role("iso")
	if id, _ := core.Contact(isoRole); id != byName["S. Ortiz"] {
		t.Errorf("CORE's Information Security Officer = %q", id)
	}
	lab, _ := s.Enclave("LAB")
	if id, _ := lab.Contact(ownerRole); id != byName["D. Rennick"] {
		t.Error("the same person named on two enclaves should be one record used twice")
	}
	if id, _ := lab.Contact(isoRole); id != "" {
		t.Error("LAB named no security contact, so it should have none")
	}

	// Running again changes nothing, because the directory is already there.
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.People()) != 2 {
		t.Errorf("reopening created duplicates: %v", names(again.People()))
	}
}

func TestMigrationOnAnEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, stampFile), Stamp{Schema: 1}); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("an empty schema 1 directory should migrate cleanly: %v", err)
	}
	if len(s.People()) != 0 {
		t.Error("nothing was there, so nobody should have been invented")
	}
	if len(s.Roles()) == 0 {
		t.Error("the built-in roles should still be available")
	}
}

func names(people []*model.Person) []string {
	out := []string{}
	for _, p := range people {
		out = append(out, p.Name)
	}
	return out
}

func TestMigrationTurnsOneSetOfConnectorSettingsIntoAList(t *testing.T) {
	dir := t.TempDir()
	// A data set as the first connector release wrote it: schema 2, one console
	// stored as though there could only ever be one, with its key beside it.
	if err := os.WriteFile(filepath.Join(dir, "tenable.json"), []byte(`{
	  "enabled": true, "url": "https://192.168.1.120:8834/", "enclave_id": "NET",
	  "place_by_address": true, "create_assets": true, "insecure_skip_verify": true,
	  "timeout_seconds": 120
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tenable-credentials.json"),
		[]byte(`{"access_key":"AK123","secret_key":"SK456"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, stampFile), Stamp{Schema: 2, WrittenBy: "old"}); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir); err != nil {
		t.Fatalf("data from the previous schema should open: %v", err)
	}
	if stamp, _, _ := ReadStamp(dir); stamp.Schema != SchemaVersion {
		t.Errorf("schema = %d, want %d", stamp.Schema, SchemaVersion)
	}

	var connectors []map[string]any
	b, err := os.ReadFile(filepath.Join(dir, "connectors.json"))
	if err != nil {
		t.Fatalf("the settings did not become a connector: %v", err)
	}
	if err := json.Unmarshal(b, &connectors); err != nil {
		t.Fatal(err)
	}
	if len(connectors) != 1 {
		t.Fatalf("got %d connectors, want 1", len(connectors))
	}
	c := connectors[0]
	// It is named after the console it reaches, since the old shape carried no
	// name at all.
	if c["id"] != "192.168.1.120-8834" {
		t.Errorf("id = %v", c["id"])
	}
	if c["name"] != "192.168.1.120:8834" {
		t.Errorf("name = %v", c["name"])
	}
	for key, want := range map[string]any{
		"enabled": true, "url": "https://192.168.1.120:8834/", "enclave_id": "NET",
		"place_by_address": true, "create_assets": true, "insecure_skip_verify": true,
		"kind": "tenable-sc",
	} {
		if c[key] != want {
			t.Errorf("%s = %v, want %v", key, c[key], want)
		}
	}
	if c["timeout_seconds"] != float64(120) {
		t.Errorf("timeout = %v", c["timeout_seconds"])
	}

	// The stored key moved with it, keyed by the new identifier.
	var creds map[string]map[string]string
	b, err = os.ReadFile(filepath.Join(dir, "connector-credentials.json"))
	if err != nil {
		t.Fatalf("the stored key was lost: %v", err)
	}
	if err := json.Unmarshal(b, &creds); err != nil {
		t.Fatal(err)
	}
	if creds["192.168.1.120-8834"]["access_key"] != "AK123" {
		t.Errorf("credentials = %v", creds)
	}
	if info, err := os.Stat(filepath.Join(dir, "connector-credentials.json")); err != nil {
		t.Fatal(err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the migrated credentials file is mode %o, want 600", perm)
	}

	// The old shapes are gone. A secret left behind for something nothing reads
	// outlives the reason anybody had it.
	for _, name := range []string{"tenable.json", "tenable-credentials.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was left behind", name)
		}
	}

	// Running again changes nothing.
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "connectors.json"))
	_ = json.Unmarshal(b, &connectors)
	if len(connectors) != 1 {
		t.Errorf("reopening duplicated the connector: %d", len(connectors))
	}
}

func TestMigrationWithNoConnectorSettings(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, stampFile), Stamp{Schema: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatalf("a directory with no connector should migrate cleanly: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "connectors.json")); !os.IsNotExist(err) {
		t.Error("a connector was invented where there was none")
	}
}
