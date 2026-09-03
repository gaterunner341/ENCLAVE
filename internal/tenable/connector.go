package tenable

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// ConnectorsFile holds every connector that has been set up. It is a list
// rather than one set of settings, because an organisation with two consoles
// has two connectors and neither is "the" one.
const ConnectorsFile = "connectors.json"

// CredentialsStore holds the secrets for each connector, keyed by its
// identifier. It is written with owner-only permissions and is deliberately
// left out of backups.
const CredentialsStore = "connector-credentials.json"

// KindSecurityCenter is the only kind so far. It is recorded on every connector
// so that the list says what each one talks to rather than assuming.
const KindSecurityCenter = "tenable-sc"

// Connector is one configured link to an outside system.
type Connector struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`

	// Enabled is per connector, so one can be switched off without disturbing
	// the others or losing its settings.
	Enabled bool `json:"enabled"`

	URL       string `json:"url"`
	EnclaveID string `json:"enclave_id"`

	PlaceByAddress bool     `json:"place_by_address"`
	CreateAssets   bool     `json:"create_assets"`
	Repositories   []string `json:"repositories,omitempty"`

	CACertFile         string `json:"ca_cert_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	TimeoutSeconds     int    `json:"timeout_seconds,omitempty"`

	LastSync *time.Time `json:"last_sync,omitempty"`
	Created  time.Time  `json:"created"`
	Updated  time.Time  `json:"updated"`
}

// KindLabel names what the connector talks to.
func (c *Connector) KindLabel() string {
	if c.Kind == KindSecurityCenter {
		return "Tenable Security Center"
	}
	return c.Kind
}

// Timeout is the configured request timeout, with a sensible floor.
func (c *Connector) Timeout() time.Duration {
	if c == nil || c.TimeoutSeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Base is the REST root, with the prefix Security Center expects.
func (c *Connector) Base() string {
	return strings.TrimRight(strings.TrimSpace(c.URL), "/") + "/rest"
}

// Host is the address without the scheme.
func (c *Connector) Host() string {
	if u, err := url.Parse(strings.TrimSpace(c.URL)); err == nil && u.Host != "" {
		return u.Host
	}
	return c.URL
}

// Validate rejects a connector that could not work. A disabled one is still
// checked, because settings saved now are settings used later.
func (c *Connector) Validate() error {
	var problems []string
	if strings.TrimSpace(c.Name) == "" {
		problems = append(problems, "give the connector a name")
	}
	if !idPattern.MatchString(c.ID) {
		problems = append(problems, "the identifier must be 2 to 64 characters of letters, digits, dot, dash or underscore")
	}
	if strings.TrimSpace(c.URL) == "" {
		problems = append(problems, "the Security Center address is required")
	} else {
		u, err := url.Parse(strings.TrimSpace(c.URL))
		switch {
		case err != nil:
			problems = append(problems, "the address could not be read: "+err.Error())
		case u.Scheme != "https":
			// Credentials and somebody's vulnerability data both cross here.
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

// idPattern is the same shape enclave identifiers use, so that a connector
// identifier is safe in a URL and in a filename.
var idPattern = model.IDPattern

// LoadConnectors reads every connector, in a stable order.
func LoadConnectors(dir string) ([]*Connector, error) {
	b, err := os.ReadFile(filepath.Join(dir, ConnectorsFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var out []*Connector
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s could not be read: %w", ConnectorsFile, err)
	}
	sortConnectors(out)
	return out, nil
}

func sortConnectors(in []*Connector) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Enabled != in[j].Enabled {
			return in[i].Enabled
		}
		return strings.ToLower(in[i].Name) < strings.ToLower(in[j].Name)
	})
}

// Connector looks one up.
func GetConnector(dir, id string) (*Connector, error) {
	all, err := LoadConnectors(dir)
	if err != nil {
		return nil, err
	}
	for _, c := range all {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no connector %q", id)
}

// SaveConnector creates or replaces one, leaving the others alone.
func SaveConnector(dir string, c *Connector) error {
	if err := c.Validate(); err != nil {
		return err
	}
	all, err := LoadConnectors(dir)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	replaced := false
	for i, existing := range all {
		if existing.ID != c.ID {
			continue
		}
		c.Created = existing.Created
		// LastSync belongs to the connector's history rather than to the form,
		// so an edit does not forget when it was last used.
		if c.LastSync == nil {
			c.LastSync = existing.LastSync
		}
		all[i] = c
		replaced = true
	}
	if !replaced {
		if c.Created.IsZero() {
			c.Created = now
		}
		all = append(all, c)
	}
	c.Updated = now
	return writeConnectors(dir, all)
}

// DeleteConnector removes one and forgets its credentials with it. Leaving a
// secret behind for something that no longer exists is how a key outlives the
// reason anybody had it.
func DeleteConnector(dir, id string) error {
	all, err := LoadConnectors(dir)
	if err != nil {
		return err
	}
	kept := make([]*Connector, 0, len(all))
	found := false
	for _, c := range all {
		if c.ID == id {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		return fmt.Errorf("no connector %q", id)
	}
	if err := writeConnectors(dir, kept); err != nil {
		return err
	}
	return ForgetCredentials(dir, id)
}

func writeConnectors(dir string, all []*Connector) error {
	sortConnectors(all)
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, ConnectorsFile), b, 0o644)
}

// AnyEnabled reports whether this instance will make an outbound connection at
// all, which is the first thing somebody reviewing it wants to know.
func AnyEnabled(dir string) (bool, []*Connector) {
	all, err := LoadConnectors(dir)
	if err != nil {
		return false, nil
	}
	live := []*Connector{}
	for _, c := range all {
		if c.Enabled {
			live = append(live, c)
		}
	}
	return len(live) > 0, live
}

// RecordSync notes when a connector was last used.
func RecordSync(dir, id string) {
	c, err := GetConnector(dir, id)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	c.LastSync = &now
	_ = SaveConnector(dir, c)
}
