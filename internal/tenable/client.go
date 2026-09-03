package tenable

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxDownload bounds a single scan result. A Security Center export of a large
// estate is genuinely hundreds of megabytes, and an unbounded read of a remote
// response is how a service is made to run out of memory.
const MaxDownload = 512 << 20

// Client talks to one Security Center.
type Client struct {
	cfg   *Connector
	creds Credentials
	http  *http.Client

	// token and session are set by password authentication. Key authentication
	// needs neither.
	token   string
	session string
}

// New builds a client. It does not connect; nothing reaches the network until a
// method is called.
func New(cfg *Connector, creds Credentials) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !creds.Complete() {
		envA, envS, _, _ := EnvNames(cfg.ID)
		return nil, fmt.Errorf(
			"%s has no credentials. Enter an access key and secret key on its page, "+
				"or set %s and %s in the environment ENCLAVE runs in",
			cfg.Name, envA, envS)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("reading the certificate file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contains no certificates that could be read", cfg.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	return &Client{
		cfg: cfg, creds: creds,
		http: &http.Client{
			Timeout: cfg.Timeout(),
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				TLSHandshakeTimeout: 30 * time.Second,
				Proxy:               http.ProxyFromEnvironment,
			},
		},
	}, nil
}

// envelope is the shape Security Center wraps every response in.
type envelope struct {
	Type      string          `json:"type"`
	Response  json.RawMessage `json:"response"`
	ErrorCode json.Number     `json:"error_code"`
	ErrorMsg  string          `json:"error_msg"`
}

func (e envelope) err() error {
	code := strings.TrimSpace(e.ErrorCode.String())
	if code == "" || code == "0" {
		return nil
	}
	msg := strings.TrimSpace(e.ErrorMsg)
	if msg == "" {
		msg = "the request was refused"
	}
	return fmt.Errorf("Security Center returned error %s: %s", code, msg)
}

// authenticate obtains a session when using a username and password. With API
// keys there is nothing to do, because every request carries the key.
func (c *Client) authenticate(ctx context.Context) error {
	if c.creds.HaveKeys() || c.token != "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{
		"username": c.creds.Username,
		"password": c.creds.Password,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Base()+"/token", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return describeDialError(c.cfg, err)
	}
	defer resp.Body.Close()

	var env envelope
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return unreadable(resp, raw)
	}
	if err := env.err(); err != nil {
		return err
	}
	var token struct {
		Token json.Number `json:"token"`
	}
	if err := json.Unmarshal(env.Response, &token); err != nil {
		return fmt.Errorf("the login response carried no token: %w", err)
	}
	c.token = token.Token.String()
	for _, ck := range resp.Cookies() {
		if ck.Name == "TNS_SESSIONID" {
			c.session = ck.Value
		}
	}
	if c.token == "" {
		return fmt.Errorf("the login succeeded but returned no token")
	}
	return nil
}

// do issues an authenticated request and unwraps the envelope.
func (c *Client) do(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	if err := c.authenticate(ctx); err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Base()+path, reader)
	if err != nil {
		return nil, err
	}
	c.sign(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, describeDialError(c.cfg, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, unreadable(resp, raw)
	}
	if err := env.err(); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Security Center answered %s", resp.Status)
	}
	return env.Response, nil
}

// sign puts the credentials on a request. The header shapes are the ones
// Security Center documents: an API key pair, or a token and session from a
// password login.
func (c *Client) sign(req *http.Request) {
	if c.creds.HaveKeys() {
		req.Header.Set("X-APIKey",
			fmt.Sprintf("accessKey=%s; secretKey=%s", c.creds.AccessKey, c.creds.SecretKey))
		return
	}
	if c.token != "" {
		req.Header.Set("X-SecurityCenter", c.token)
	}
	if c.session != "" {
		req.AddCookie(&http.Cookie{Name: "TNS_SESSIONID", Value: c.session})
	}
}

// ScanResult is one completed scan on the Security Center.
type ScanResult struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Repository string    `json:"repository"`
	Owner      string    `json:"owner"`
	ScannedIPs int       `json:"scanned_ips"`
	Finished   time.Time `json:"finished"`
	Started    time.Time `json:"started"`
	// Imported is filled in by the caller from what is already on file, so a
	// page can show what has been taken and what has not.
	Imported bool `json:"imported"`
}

// Complete reports whether the result is finished and therefore downloadable.
func (r ScanResult) Complete() bool {
	s := strings.ToLower(r.Status)
	return s == "completed" || s == "partial"
}

// scanResultFields are the fields worth asking for. Security Center returns a
// very wide record otherwise, and the response for a busy console is large.
const scanResultFields = "id,name,status,finishTime,startTime,scannedIPs,repository,ownerID,owner,importStatus"

// ScanResults lists completed scans, newest first.
func (c *Client) ScanResults(ctx context.Context, since time.Time) ([]ScanResult, error) {
	path := "/scanResult?fields=" + scanResultFields
	if !since.IsZero() {
		path += "&startTime=" + strconv.FormatInt(since.Unix(), 10)
	}
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		Usable     []scanResultRow `json:"usable"`
		Manageable []scanResultRow `json:"manageable"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		// Some releases answer with a bare array rather than the two lists.
		var flat []scanResultRow
		if err2 := json.Unmarshal(raw, &flat); err2 != nil {
			return nil, fmt.Errorf("the list of scan results could not be read: %w", err)
		}
		body.Usable = flat
	}

	seen := map[string]bool{}
	out := []ScanResult{}
	for _, row := range append(append([]scanResultRow{}, body.Usable...), body.Manageable...) {
		r := row.convert()
		if r.ID == "" || seen[r.ID] {
			continue
		}
		if !c.wantRepository(r.Repository) {
			continue
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Finished.After(out[j].Finished) })
	return out, nil
}

func (c *Client) wantRepository(name string) bool {
	if len(c.cfg.Repositories) == 0 {
		return true
	}
	for _, want := range c.cfg.Repositories {
		if strings.EqualFold(strings.TrimSpace(want), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// scanResultRow is the wire shape. Security Center sends numbers as strings and
// timestamps as epoch strings, so everything is read loosely and converted.
type scanResultRow struct {
	ID         json.Number `json:"id"`
	Name       string      `json:"name"`
	Status     string      `json:"status"`
	FinishTime json.Number `json:"finishTime"`
	StartTime  json.Number `json:"startTime"`
	ScannedIPs json.Number `json:"scannedIPs"`
	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`
	Owner struct {
		Username string `json:"username"`
	} `json:"owner"`
}

func (r scanResultRow) convert() ScanResult {
	out := ScanResult{
		ID: strings.TrimSpace(r.ID.String()), Name: r.Name, Status: r.Status,
		Repository: r.Repository.Name, Owner: r.Owner.Username,
	}
	if n, err := r.ScannedIPs.Int64(); err == nil {
		out.ScannedIPs = int(n)
	}
	out.Finished = epoch(r.FinishTime)
	out.Started = epoch(r.StartTime)
	return out
}

func epoch(n json.Number) time.Time {
	secs, err := n.Int64()
	if err != nil || secs <= 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}

// Test checks that the address, the certificate and the credentials all work,
// and reports something a person can act on when they do not.
func (c *Client) Test(ctx context.Context) (string, error) {
	raw, err := c.do(ctx, http.MethodGet, "/system", nil)
	if err != nil {
		return "", err
	}
	var sys struct {
		Version     string `json:"version"`
		BuildID     string `json:"buildID"`
		ReleaseID   string `json:"releaseID"`
		ServerClass string `json:"serverClassification"`
	}
	_ = json.Unmarshal(raw, &sys)
	desc := "connected to " + c.cfg.Host()
	if sys.Version != "" {
		desc += ", Security Center " + sys.Version
	}
	return desc, nil
}

// Download fetches one scan result and returns the Nessus file inside it.
//
// Security Center answers with a zip, so the archive is opened and the result
// file taken out. Nothing here parses the result: it goes to the same reader
// that an uploaded file does.
func (c *Client) Download(ctx context.Context, id string) ([]byte, string, error) {
	if err := c.authenticate(ctx); err != nil {
		return nil, "", err
	}
	body, _ := json.Marshal(map[string]string{"downloadType": "v2"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.Base()+"/scanResult/"+id+"/download", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	c.sign(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", describeDialError(c.cfg, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("Security Center answered %s when asked for scan result %s", resp.Status, id)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownload+1))
	if err != nil {
		return nil, "", fmt.Errorf("reading scan result %s: %w", id, err)
	}
	if int64(len(raw)) > MaxDownload {
		return nil, "", fmt.Errorf("scan result %s is larger than the %d MB limit", id, MaxDownload>>20)
	}
	// An error is sometimes returned as JSON with a success status, so a body
	// that is not an archive is checked for one before being reported as junk.
	if !bytes.HasPrefix(raw, []byte("PK")) {
		var env envelope
		if json.Unmarshal(raw, &env) == nil {
			if err := env.err(); err != nil {
				return nil, "", err
			}
		}
		// A few releases answer with the bare XML rather than a zip.
		if bytes.Contains(raw[:min(len(raw), 4096)], []byte("<NessusClientData")) {
			return raw, "scan-" + id + ".nessus", nil
		}
		return nil, "", fmt.Errorf("scan result %s came back as neither an archive nor a Nessus file", id)
	}
	return unzipResult(raw, id)
}

// unzipResult takes the result file out of the archive Security Center sends.
func unzipResult(raw []byte, id string) ([]byte, string, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", fmt.Errorf("the archive for scan result %s could not be opened: %w", id, err)
	}
	var best *zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(name, ".nessus"):
			best = f
		case best == nil && strings.HasSuffix(name, ".xml"):
			best = f
		}
	}
	if best == nil {
		return nil, "", fmt.Errorf("the archive for scan result %s holds no Nessus file", id)
	}
	rc, err := best.Open()
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, MaxDownload+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > MaxDownload {
		return nil, "", fmt.Errorf("scan result %s expands to more than the %d MB limit", id, MaxDownload>>20)
	}
	return body, best.Name, nil
}

// describeDialError turns a transport failure into something actionable, since
// the usual one is a certificate an appliance signed itself.
func describeDialError(cfg *Connector, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "x509") || strings.Contains(msg, "certificate"):
		return fmt.Errorf(
			"the certificate presented by %s was not trusted: %w. "+
				"Point the connector at your certificate authority's PEM file, "+
				"or accept the certificate explicitly if it is self-signed",
			cfg.Host(), err)
	case strings.Contains(msg, "no such host"):
		return fmt.Errorf("%s could not be resolved: %w", cfg.Host(), err)
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "deadline exceeded"):
		return fmt.Errorf("%s did not answer: %w", cfg.Host(), err)
	}
	return err
}

func unreadable(resp *http.Response, raw []byte) error {
	snippet := strings.TrimSpace(string(raw))
	if len(snippet) > 160 {
		snippet = snippet[:160] + "…"
	}
	if snippet == "" {
		snippet = "an empty body"
	}
	return fmt.Errorf(
		"the answer was not the JSON the API returns (%s): %s. "+
			"Check the address points at Security Center itself rather than at a portal in front of it",
		resp.Status, snippet)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
