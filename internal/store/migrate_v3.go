package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// migrateConnectorSettings turns the single set of Tenable settings that an
// earlier build wrote into an entry in the list of connectors.
//
// The first version stored one console's settings as though there could only
// ever be one, with no name, no list and no way to remove it. This moves what
// is there into a connector with an identity, so it can sit alongside others
// and be deleted like anything else. Any stored key moves with it, keyed by
// the new connector's identifier.
//
// It works on the files rather than on loaded records, because the shapes it
// reads no longer exist in the code.
func migrateConnectorSettings(dir string) error {
	oldConfig := filepath.Join(dir, "tenable.json")
	raw, err := os.ReadFile(oldConfig)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var old struct {
		Enabled            bool       `json:"enabled"`
		URL                string     `json:"url"`
		EnclaveID          string     `json:"enclave_id"`
		PlaceByAddress     bool       `json:"place_by_address"`
		CreateAssets       bool       `json:"create_assets"`
		Repositories       []string   `json:"repositories"`
		CACertFile         string     `json:"ca_cert_file"`
		InsecureSkipVerify bool       `json:"insecure_skip_verify"`
		TimeoutSeconds     int        `json:"timeout_seconds"`
		LastSync           *time.Time `json:"last_sync"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		return fmt.Errorf("reading tenable.json: %w", err)
	}

	now := time.Now().UTC()
	id := connectorIDFrom(old.URL)
	name := hostOf(old.URL)
	if name == "" {
		name = "Security Center"
	}
	entry := map[string]any{
		"id": id, "name": name, "kind": "tenable-sc",
		"enabled": old.Enabled, "url": old.URL, "enclave_id": old.EnclaveID,
		"place_by_address": old.PlaceByAddress, "create_assets": old.CreateAssets,
		"created": now, "updated": now,
	}
	for key, value := range map[string]any{
		"repositories": old.Repositories, "ca_cert_file": old.CACertFile,
		"insecure_skip_verify": old.InsecureSkipVerify, "timeout_seconds": old.TimeoutSeconds,
		"last_sync": old.LastSync,
	} {
		switch v := value.(type) {
		case []string:
			if len(v) > 0 {
				entry[key] = v
			}
		case string:
			if v != "" {
				entry[key] = v
			}
		case bool:
			if v {
				entry[key] = v
			}
		case int:
			if v != 0 {
				entry[key] = v
			}
		case *time.Time:
			if v != nil {
				entry[key] = v
			}
		}
	}

	// Anything already in the new file wins, so running twice cannot duplicate.
	existing := []map[string]any{}
	if b, err := os.ReadFile(filepath.Join(dir, "connectors.json")); err == nil {
		_ = json.Unmarshal(b, &existing)
	}
	for _, c := range existing {
		if fmt.Sprint(c["id"]) == id {
			return retireOldFiles(dir)
		}
	}
	if err := writeJSON(filepath.Join(dir, "connectors.json"), append(existing, entry)); err != nil {
		return err
	}

	// A stored key moves with its connector rather than being left behind for
	// a shape nothing reads any more.
	if b, err := os.ReadFile(filepath.Join(dir, "tenable-credentials.json")); err == nil {
		var creds map[string]any
		if json.Unmarshal(b, &creds) == nil && len(creds) > 0 {
			store := map[string]any{}
			if existing, err := os.ReadFile(filepath.Join(dir, "connector-credentials.json")); err == nil {
				_ = json.Unmarshal(existing, &store)
			}
			if _, taken := store[id]; !taken {
				store[id] = creds
				if err := writeJSONMode(filepath.Join(dir, "connector-credentials.json"), store, 0o600); err != nil {
					return err
				}
			}
		}
	}
	return retireOldFiles(dir)
}

// retireOldFiles removes the shapes nothing reads any more. The credentials
// file in particular must not linger: a secret left on disk for a thing that no
// longer exists outlives the reason anybody had it.
func retireOldFiles(dir string) error {
	for _, name := range []string{"tenable.json", "tenable-credentials.json"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// connectorIDFrom derives a stable identifier from the console's address, so
// the migrated connector is named after the thing it connects to.
func connectorIDFrom(rawURL string) string {
	host := hostOf(rawURL)
	if host == "" {
		return "security-center"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(host) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "security-center"
	}
	return out
}

func hostOf(rawURL string) string {
	v := strings.TrimSpace(rawURL)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	v = strings.TrimRight(v, "/")
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	return v
}

// writeJSONMode is writeJSON with an explicit file mode, for the file that
// holds secrets.
func writeJSONMode(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, perm)
}
