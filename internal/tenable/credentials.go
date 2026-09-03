package tenable

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Credentials authenticate to a Security Center. Keys are preferred; a username
// and password work against releases that predate them.
type Credentials struct {
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

// HaveKeys reports whether API key authentication is available.
func (c Credentials) HaveKeys() bool { return c.AccessKey != "" && c.SecretKey != "" }

// HavePassword reports whether username and password authentication is available.
func (c Credentials) HavePassword() bool { return c.Username != "" && c.Password != "" }

// Complete reports whether there is anything to authenticate with.
func (c Credentials) Complete() bool { return c.HaveKeys() || c.HavePassword() }

// Source describes what is in use, so a page can say so rather than leaving
// somebody to guess whether the file or the environment won.
func (c Credentials) Source() string {
	switch {
	case !c.Complete():
		return "none supplied"
	case c.HaveKeys():
		return "API keys"
	default:
		return "username and password"
	}
}

// Environment variables are the way to supply credentials without writing them
// to disk. Each connector can have its own, and a single-connector deployment
// can use the plain names.
const (
	EnvAccessKey = "ENCLAVE_TENABLE_ACCESS_KEY"
	EnvSecretKey = "ENCLAVE_TENABLE_SECRET_KEY"
	EnvUsername  = "ENCLAVE_TENABLE_USERNAME"
	EnvPassword  = "ENCLAVE_TENABLE_PASSWORD"
)

// EnvNames are the per-connector variable names, which take precedence over the
// plain ones so that two consoles can have different keys.
func EnvNames(connectorID string) (access, secret, user, pass string) {
	suffix := envSuffix(connectorID)
	return "ENCLAVE_TENABLE_" + suffix + "_ACCESS_KEY",
		"ENCLAVE_TENABLE_" + suffix + "_SECRET_KEY",
		"ENCLAVE_TENABLE_" + suffix + "_USERNAME",
		"ENCLAVE_TENABLE_" + suffix + "_PASSWORD"
}

// envSuffix turns a connector identifier into something legal in an
// environment variable name.
func envSuffix(id string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(id)) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// credentialStore is the file's shape: one entry per connector.
type credentialStore map[string]Credentials

func loadStore(dir string) (credentialStore, error) {
	b, err := os.ReadFile(filepath.Join(dir, CredentialsStore))
	if os.IsNotExist(err) {
		return credentialStore{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return credentialStore{}, nil
	}
	out := credentialStore{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s could not be read: %w", CredentialsStore, err)
	}
	return out, nil
}

func saveStore(dir string, store credentialStore) error {
	if len(store) == 0 {
		err := os.Remove(filepath.Join(dir, CredentialsStore))
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CredentialsStore), b, 0o600)
}

// LoadCredentials assembles one connector's credentials. The environment always
// wins over the file, and a variable named for the connector wins over the
// plain one, so no deployment is stuck with a stale secret and two consoles can
// hold different keys.
func LoadCredentials(dir, connectorID string) (Credentials, error) {
	store, err := loadStore(dir)
	if err != nil {
		return Credentials{}, err
	}
	stored := store[connectorID]
	envA, envS, envU, envP := EnvNames(connectorID)
	return Credentials{
		AccessKey: firstSet(os.Getenv(envA), os.Getenv(EnvAccessKey), stored.AccessKey),
		SecretKey: firstSet(os.Getenv(envS), os.Getenv(EnvSecretKey), stored.SecretKey),
		Username:  firstSet(os.Getenv(envU), os.Getenv(EnvUsername), stored.Username),
		Password:  firstSet(os.Getenv(envP), os.Getenv(EnvPassword), stored.Password),
	}, nil
}

// SaveCredentials stores one connector's secrets with owner-only permissions.
func SaveCredentials(dir, connectorID string, c Credentials) error {
	store, err := loadStore(dir)
	if err != nil {
		return err
	}
	store[connectorID] = c
	return saveStore(dir, store)
}

// ForgetCredentials removes one connector's stored secrets.
func ForgetCredentials(dir, connectorID string) error {
	store, err := loadStore(dir)
	if err != nil {
		return err
	}
	if _, ok := store[connectorID]; !ok {
		return nil
	}
	delete(store, connectorID)
	return saveStore(dir, store)
}

// CredentialsOnDisk reports whether a connector's secrets are stored in the
// data directory, which a page should say out loud.
func CredentialsOnDisk(dir, connectorID string) bool {
	store, err := loadStore(dir)
	if err != nil {
		return false
	}
	_, ok := store[connectorID]
	return ok
}

// FromEnvironment reports whether the credentials in use came from the
// environment, so a page can say that storing more would change nothing.
func FromEnvironment(connectorID string) bool {
	envA, _, envU, _ := EnvNames(connectorID)
	for _, name := range []string{envA, EnvAccessKey, envU, EnvUsername} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}
	return false
}

func writeFile(path string, body []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// A rename keeps the destination's old mode, so it is set again for the
	// case where the file already existed with looser permissions.
	return os.Chmod(path, perm)
}

func firstSet(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
