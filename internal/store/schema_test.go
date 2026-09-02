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
