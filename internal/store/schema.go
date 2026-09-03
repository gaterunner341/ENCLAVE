package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SchemaVersion is the layout of the data directory that this build writes and
// understands. It goes up whenever a change would stop an older build reading
// what a newer one wrote, which is the only thing that makes an upgrade unsafe.
const SchemaVersion = 2

// stampFile records what wrote the data directory, so that a build can tell
// whether it is looking at data it understands before it touches any of it.
const stampFile = "schema.json"

// Stamp is the contents of schema.json.
type Stamp struct {
	Schema    int       `json:"schema"`
	WrittenBy string    `json:"written_by,omitempty"`
	WrittenAt time.Time `json:"written_at"`
}

// ReadStamp reads the version stamp from a data directory.
//
// A directory with no stamp is not an error. It is either brand new, or it was
// written by a build from before stamping existed; the presence of data files
// tells the two apart, and either way its contents are schema 1.
func ReadStamp(dir string) (Stamp, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, stampFile))
	if os.IsNotExist(err) {
		return Stamp{Schema: 1}, false, nil
	}
	if err != nil {
		return Stamp{}, false, err
	}
	var s Stamp
	if err := json.Unmarshal(b, &s); err != nil {
		return Stamp{}, false, fmt.Errorf("%s is not readable: %w", stampFile, err)
	}
	if s.Schema <= 0 {
		return Stamp{}, false, fmt.Errorf("%s does not say which schema it is", stampFile)
	}
	return s, true, nil
}

// WriteStamp records the current schema version in a data directory.
func WriteStamp(dir, buildVersion string) error {
	return writeJSON(filepath.Join(dir, stampFile), Stamp{
		Schema:    SchemaVersion,
		WrittenBy: buildVersion,
		WrittenAt: time.Now().UTC(),
	})
}

// BuildVersion is stamped into the data directory and into backup bundles so
// that a support question can be answered from the files alone. The command
// sets it at startup.
var BuildVersion = "dev"

// ErrNewerSchema is returned when the data was written by a build newer than
// this one. Guessing at a layout from the future is how data gets corrupted,
// so this is refused rather than attempted.
type ErrNewerSchema struct {
	Found, Understood int
	WrittenBy         string
}

func (e *ErrNewerSchema) Error() string {
	by := ""
	if e.WrittenBy != "" {
		by = " by ENCLAVE " + e.WrittenBy
	}
	return fmt.Sprintf(
		"this data was written%s using schema %d, and this build only understands schema %d; "+
			"upgrade ENCLAVE, or point --data at a copy written by this version",
		by, e.Found, e.Understood)
}

// migration turns a data directory from one schema version into the next.
//
// There are none yet: schema 1 is the first. The list exists so that the first
// change to the layout is a matter of appending one step, rather than of
// working out afterwards how to rescue everybody's data.
type migration struct {
	from, to int
	describe string
	apply    func(dir string) error
}

var migrations = []migration{
	{
		from: 1, to: 2,
		describe: "points of contact become a directory of people",
		apply:    migrateContactsToPeople,
	},
}

// prepare brings a data directory up to the current schema, or reports clearly
// why it cannot. It runs before anything is read.
func prepare(dir string) error {
	stamp, stamped, err := ReadStamp(dir)
	if err != nil {
		return err
	}
	if stamp.Schema > SchemaVersion {
		return &ErrNewerSchema{Found: stamp.Schema, Understood: SchemaVersion, WrittenBy: stamp.WrittenBy}
	}
	migrated := false
	for stamp.Schema < SchemaVersion {
		step, ok := nextMigration(stamp.Schema)
		if !ok {
			return fmt.Errorf(
				"this data uses schema %d and there is no route from it to schema %d; "+
					"restore from a backup taken with the version that wrote it",
				stamp.Schema, SchemaVersion)
		}
		if err := step.apply(dir); err != nil {
			return fmt.Errorf("upgrading data from schema %d to %d (%s): %w",
				step.from, step.to, step.describe, err)
		}
		stamp.Schema = step.to
		migrated = true
	}
	// Recording what has been established means the next start does not work it
	// out again: an unstamped directory gets a stamp, and a directory that has
	// just been migrated gets the version it was migrated to. Leaving the old
	// stamp in place would run every migration again on every start.
	if !stamped || migrated || stamp.Schema != SchemaVersion {
		return WriteStamp(dir, BuildVersion)
	}
	return nil
}

func nextMigration(from int) (migration, bool) {
	for _, m := range migrations {
		if m.from == from {
			return m, true
		}
	}
	return migration{}, false
}
