// Package tenable pulls scan results from a Tenable Security Center over its
// REST API, instead of somebody exporting a file and uploading it.
//
// This is the only part of ENCLAVE that makes an outbound connection, and it
// does nothing at all until somebody configures it. That is deliberate: the
// rest of the tool is safe to run on an isolated network precisely because it
// never talks to anything, and turning that off is a decision the operator
// makes rather than a default they inherit.
//
// The connector fetches; it does not parse. A downloaded result goes through
// exactly the same reader as a file somebody uploads, so there is one place
// where the Nessus format is understood and one set of rules about what a
// finding means.
package tenable

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// ConfigFile is where the connector's settings live inside the data directory.
const ConfigFile = "tenable.json"

// CredentialsFile holds the secret key when somebody chooses to store it rather
// than supply it from the environment. It is written with owner-only
// permissions and is deliberately left out of backups.
const CredentialsFile = "tenable-credentials.json"

// Environment variables are the way to supply credentials without writing them
// to disk at all, which is what most people should do.
const (
	EnvAccessKey = "ENCLAVE_TENABLE_ACCESS_KEY"
	EnvSecretKey = "ENCLAVE_TENABLE_SECRET_KEY"
	EnvUsername  = "ENCLAVE_TENABLE_USERNAME"
	EnvPassword  = "ENCLAVE_TENABLE_PASSWORD"
)

// Config is everything about reaching one Security Center, apart from the
// secrets.
type Config struct {
	// Enabled is the switch. While it is off ENCLAVE makes no outbound
	// connection of any kind, which is the state it ships in.
	Enabled bool `json:"enabled"`

	// URL is the Security Center's address, for example
	// https://securitycenter.example.org. The /rest prefix is added.
	URL string `json:"url"`

	// EnclaveID is where imported results land when placement by address does
	// not put them somewhere else.
	EnclaveID string `json:"enclave_id"`
	// PlaceByAddress routes each host to the enclave whose network range
	// contains it, which is what a scan spanning several enclaves needs.
	PlaceByAddress bool `json:"place_by_address"`
	// CreateAssets allows an import to add hosts that are not yet inventoried.
	CreateAssets bool `json:"create_assets"`

	// Repositories limits which Security Center repositories are offered, by
	// name. Empty means all of them.
	Repositories []string `json:"repositories,omitempty"`

	// CACertFile is a PEM bundle to verify the server against, which is what a
	// Security Center with an internal certificate authority needs.
	CACertFile string `json:"ca_cert_file,omitempty"`
	// InsecureSkipVerify turns off certificate verification. It is here because
	// self-signed certificates are common on these appliances, and it is named
	// so that nobody can turn it on by accident or claim they did not know.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// Timeout bounds a single request. A large download legitimately takes a
	// while, so this is generous rather than absent.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`

	// StoreCredentials writes the keys to disk beside this file, for a
	// deployment where setting environment variables is not practical.
	StoreCredentials bool `json:"store_credentials,omitempty"`

	LastSync *time.Time `json:"last_sync,omitempty"`
}

// Credentials authenticate to Security Center. Keys are preferred; a username
// and password work against older releases that predate them.
type Credentials struct {
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

// HaveKeys reports whether API key authentication is available.
func (c Credentials) HaveKeys() bool { return c.AccessKey != "" && c.SecretKey != "" }

// HavePassword reports whether username and password authentication is
// available.
func (c Credentials) HavePassword() bool { return c.Username != "" && c.Password != "" }

// Complete reports whether there is anything to authenticate with.
func (c Credentials) Complete() bool { return c.HaveKeys() || c.HavePassword() }

// Source describes where the credentials came from, so a page can say so
// rather than leaving somebody guessing whether the file or the environment
// won.
func (c Credentials) Source() string {
	switch {
	case !c.Complete():
		return "not supplied"
	case c.HaveKeys():
		return "API keys"
	default:
		return "username and password"
	}
}

// Timeout is the configured request timeout, with a sensible floor.
func (c Config) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Validate rejects a configuration that could not work, and one that would be
// dangerous without saying so.
func (c Config) Validate() error {
	var problems []string
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.URL) == "" {
		problems = append(problems, "the Security Center address is required")
	} else {
		u, err := url.Parse(strings.TrimSpace(c.URL))
		switch {
		case err != nil:
			problems = append(problems, "the address could not be read: "+err.Error())
		case u.Scheme != "https":
			// Credentials would cross the network in the clear, and the
			// results are somebody's vulnerability data.
			problems = append(problems, "the address must start with https://")
		case u.Host == "":
			problems = append(problems, "the address has no host in it")
		}
	}
	if strings.TrimSpace(c.EnclaveID) == "" {
		problems = append(problems, "choose which enclave imported results belong to")
	}
	if c.CACertFile != "" {
		if _, err := os.Stat(c.CACertFile); err != nil {
			problems = append(problems, "the certificate file could not be read: "+err.Error())
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// Base is the REST root, with the prefix Security Center expects.
func (c Config) Base() string {
	return strings.TrimRight(strings.TrimSpace(c.URL), "/") + "/rest"
}

// Host is the address without the scheme, for a page that wants to name it
// without repeating the protocol.
func (c Config) Host() string {
	if u, err := url.Parse(strings.TrimSpace(c.URL)); err == nil && u.Host != "" {
		return u.Host
	}
	return c.URL
}

// LoadConfig reads the connector's settings from a data directory. A directory
// with no configuration returns a disabled one, which is the state that makes
// no connections.
func LoadConfig(dir string) (Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if os.IsNotExist(err) {
		return Config{CreateAssets: true}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("%s could not be read: %w", ConfigFile, err)
	}
	return c, nil
}

// SaveConfig writes the connector's settings.
func SaveConfig(dir string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, ConfigFile), b, 0o644)
}

// LoadCredentials assembles credentials from the environment first and the
// stored file second, so that setting an environment variable always overrides
// whatever is on disk and no deployment is stuck with a stale secret.
func LoadCredentials(dir string) (Credentials, error) {
	stored := Credentials{}
	b, err := os.ReadFile(filepath.Join(dir, CredentialsFile))
	if err == nil {
		if err := json.Unmarshal(b, &stored); err != nil {
			return Credentials{}, fmt.Errorf("%s could not be read: %w", CredentialsFile, err)
		}
	} else if !os.IsNotExist(err) {
		return Credentials{}, err
	}
	out := Credentials{
		AccessKey: firstSet(os.Getenv(EnvAccessKey), stored.AccessKey),
		SecretKey: firstSet(os.Getenv(EnvSecretKey), stored.SecretKey),
		Username:  firstSet(os.Getenv(EnvUsername), stored.Username),
		Password:  firstSet(os.Getenv(EnvPassword), stored.Password),
	}
	return out, nil
}

// SaveCredentials writes the secrets with owner-only permissions.
func SaveCredentials(dir string, c Credentials) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CredentialsFile), b, 0o600)
}

// ForgetCredentials removes the stored secrets.
func ForgetCredentials(dir string) error {
	err := os.Remove(filepath.Join(dir, CredentialsFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// CredentialsOnDisk reports whether secrets are stored in the data directory,
// which a page should say out loud.
func CredentialsOnDisk(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, CredentialsFile))
	return err == nil
}

func writeFile(path string, body []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, perm); err != nil {
		return err
	}
	// A rename does not change an existing file's mode, so it is set again for
	// the case where the file was already there with looser permissions.
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
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

// ImportOptions is what the connector hands the importer.
type ImportOptions struct {
	EnclaveID          string
	PlaceByAddress     bool
	CreateAssets       bool
	DefaultCriticality model.Criticality
}
