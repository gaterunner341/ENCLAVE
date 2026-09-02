package web

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkittelson/enclave/internal/connector"
	"github.com/pkittelson/enclave/internal/model"
	"github.com/pkittelson/enclave/internal/resolve"
	"github.com/pkittelson/enclave/internal/store"
)

// maxUpload is the largest CSV the import screen accepts. A file bigger than
// this is a database export, and belongs in a scheduled feed rather than a
// browser upload.
const maxUpload = 10 << 20

// mapRow is one line of the column-mapping table.
type mapRow struct {
	Group    string
	Key      string
	Label    string
	Selected string
}

// catalogEntry describes one thing a column can mean, and the header names
// that usually mean it. The aliases are what makes the mapping screen arrive
// pre-filled instead of empty.
type catalogEntry struct {
	Group   string
	Key     string
	Label   string
	Aliases []string
}

// catalog is the whole vocabulary the application understands. Identifiers
// come first because at least one of them is required.
var catalog = []catalogEntry{
	{"Identifiers", "id:" + model.IDHostname, "Host name",
		[]string{"hostname", "host name", "host", "computer name", "computername", "device name", "machine name", "system name", "asset name", "name", "netbios name"}},
	{"Identifiers", "id:" + model.IDFQDN, "Fully qualified name",
		[]string{"fqdn", "dns name", "full computer name", "full name", "dns hostname"}},
	{"Identifiers", "id:" + model.IDMAC, "MAC address",
		[]string{"mac", "mac address", "physical address", "hardware address", "ethernet address"}},
	{"Identifiers", "id:" + model.IDSerial, "Serial number",
		[]string{"serial", "serial number", "serialnumber", "service tag", "sn", "chassis serial"}},
	{"Identifiers", "id:" + model.IDUUID, "Hardware UUID",
		[]string{"uuid", "hardware uuid", "bios uuid", "device id", "deviceid", "agent id", "aid", "system uuid"}},
	{"Identifiers", "id:" + model.IDAssetTag, "Asset tag",
		[]string{"asset tag", "asset id", "asset number", "tag", "barcode"}},

	{"Placement", "f:" + model.FieldIP, "IP address",
		[]string{"ip", "ip address", "ipaddress", "ipv4", "ipv4 address", "local ip", "address", "primary ip"}},
	{"Placement", "f:" + model.FieldOwner, "Accountable owner",
		[]string{"owner", "primary user", "assigned to", "assigned user", "custodian", "responsible", "user"}},
	{"Placement", "f:" + model.FieldLocation, "Location",
		[]string{"location", "site", "physical location", "building", "office", "campus"}},
	{"Placement", "f:" + model.FieldDeviceRole, "Device role",
		[]string{"role", "device role", "device type", "type", "category", "class", "function"}},

	{"Platform", "f:" + model.FieldOS, "Operating system",
		[]string{"os", "operating system", "os name", "platform", "os platform", "product name"}},
	{"Platform", "f:" + model.FieldOSVersion, "OS version",
		[]string{"os version", "version", "os release", "os build", "build", "release"}},
	{"Platform", "f:" + model.FieldManufacturer, "Manufacturer",
		[]string{"manufacturer", "vendor", "make", "system manufacturer"}},
	{"Platform", "f:" + model.FieldHardwareModel, "Hardware model",
		[]string{"model", "hardware model", "system model", "product", "machine model"}},

	{"Assurance", "f:" + model.FieldEDRStatus, "Endpoint agent status",
		[]string{"agent status", "edr status", "sensor status", "agent health", "sensor health", "health", "status", "protection status"}},
	{"Assurance", "f:" + model.FieldDiskEncrypted, "Disk encrypted",
		[]string{"encrypted", "disk encrypted", "encryption status", "disk encryption", "bitlocker", "bitlocker status", "filevault"}},
	{"Assurance", "f:" + model.FieldLastVulnScan, "Last vulnerability scan",
		[]string{"last scan", "last scanned", "last vuln scan", "last vulnerability scan", "scan date", "last seen scan"}},
	{"Assurance", "f:" + model.FieldLastBenchmarkScan, "Last benchmark scan",
		[]string{"benchmark date", "last benchmark scan", "last stig scan", "compliance scan date", "last audit", "baseline date"}},
}

// fieldLabel returns the human name for a field key.
func fieldLabel(field string) string {
	for _, e := range catalog {
		if e.Key == "f:"+field {
			return e.Label
		}
	}
	return field
}

// fieldKey is fieldLabel in reverse, used to order the provenance table.
func fieldKey(label string) string {
	for _, e := range catalog {
		if e.Label == label {
			return strings.TrimPrefix(e.Key, "f:")
		}
	}
	return label
}

// staged is an uploaded file waiting for its columns to be described. It is
// held in memory only: nothing is written until the mapping is confirmed.
type staged struct {
	ID         string
	Filename   string
	Body       []byte
	Headers    []string
	SampleRows [][]string
	SourceID   string
	SourceKind string
	Selected   map[string]string
	At         time.Time
}

// stagingArea keeps uploads between the two halves of the import.
type stagingArea struct {
	mu    sync.Mutex
	items map[string]*staged
}

func newStaging() *stagingArea { return &stagingArea{items: map[string]*staged{}} }

func (a *stagingArea) put(s *staged) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Drop anything abandoned; a browser tab closed mid-import should not keep
	// a file resident for the life of the process.
	for id, item := range a.items {
		if time.Since(item.At) > time.Hour {
			delete(a.items, id)
		}
	}
	a.items[s.ID] = s
}

func (a *stagingArea) get(id string) *staged {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.items[id]
}

func (a *stagingArea) drop(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.items, id)
}

func (s *Server) importGet(w http.ResponseWriter, r *http.Request) {
	d := s.base("import")
	d.Mappings = s.store.SortedMappings()
	d.Imports = s.store.Imports()
	s.render(w, r, d)
}

// importError sends the operator back to the upload screen with a reason.
func (s *Server) importError(w http.ResponseWriter, r *http.Request, msg string) {
	s.flashRedirect(w, r, "/import", msg, true)
}

// importUpload reads the file, shows what is in it and guesses the mapping.
// Nothing is written here.
func (s *Server) importUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+1<<20)
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		s.importError(w, r, "That file is larger than 10 MB, or was not sent as a file.")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.importError(w, r, "Choose a CSV file first.")
		return
	}
	defer file.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(file); err != nil {
		s.importError(w, r, "Could not read that file.")
		return
	}
	body := buf.Bytes()

	headers, sample, err := preview(body)
	if err != nil {
		s.importError(w, r, err.Error())
		return
	}
	if len(headers) == 0 {
		s.importError(w, r, "That file has no column headers on its first row.")
		return
	}

	st := &staged{
		ID:         newStageID(),
		Filename:   header.Filename,
		Body:       body,
		Headers:    headers,
		SampleRows: sample,
		Selected:   map[string]string{},
		At:         time.Now(),
	}

	// A saved mapping wins over guessing: it was described by a person once,
	// and this is the same file next month.
	if name := strings.TrimSpace(r.FormValue("mapping")); name != "" {
		if m := s.store.Mapping(name); m != nil {
			st.SourceID, st.SourceKind = m.SourceID, m.SourceKind
			for key, col := range m.Columns {
				st.Selected[key] = col
			}
		}
	}
	for _, e := range catalog {
		if st.Selected[e.Key] == "" {
			st.Selected[e.Key] = guessColumn(headers, e.Aliases)
		}
	}
	if st.SourceID == "" {
		st.SourceID = sourceIDFromFilename(header.Filename)
	}

	s.staging.put(st)
	s.showMapping(w, r, st)
}

// showMapping renders the second half of the import.
func (s *Server) showMapping(w http.ResponseWriter, r *http.Request, st *staged) {
	d := s.base("import-map")
	d.Filename = st.Filename
	d.Headers = st.Headers
	d.SampleRows = st.SampleRows
	d.StageID = st.ID
	d.SourceID = st.SourceID
	d.SourceKind = st.SourceKind
	for _, e := range catalog {
		d.MapRows = append(d.MapRows, mapRow{
			Group:    e.Group,
			Key:      e.Key,
			Label:    e.Label,
			Selected: st.Selected[e.Key],
		})
	}
	s.render(w, r, d)
}

// importCommit re-reads the staged file with the confirmed mapping and appends
// the result to the log.
func (s *Server) importCommit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.importError(w, r, "That form could not be read. Try the upload again.")
		return
	}
	st := s.staging.get(r.FormValue("stage"))
	if st == nil {
		s.importError(w, r, "That upload expired. Upload the file again.")
		return
	}

	sourceID := strings.TrimSpace(r.FormValue("source_id"))
	if sourceID == "" {
		s.importError(w, r, "The source needs a name, so later collections can be recognised as the same feed.")
		return
	}
	sourceKind := strings.TrimSpace(r.FormValue("source_kind"))
	if resolveKind(sourceKind) == "" {
		s.importError(w, r, "Pick what kind of tool this came from. It decides which feed wins a disagreement.")
		return
	}

	columns := map[string]string{}
	for _, e := range catalog {
		if v := strings.TrimSpace(r.FormValue("col_" + e.Key)); v != "" {
			columns[e.Key] = v
		}
	}
	cm := buildColumnMap(columns)
	if len(cm.Identifiers) == 0 {
		s.importError(w, r, "Map at least one identifier. Without one there is nothing to merge rows on.")
		return
	}

	feed := &connector.CSV{
		SourceID:   sourceID,
		SourceKind: sourceKind,
		Map:        *cm,
		Batch:      st.ID,
	}
	obs, err := feed.Parse(bytes.NewReader(st.Body))
	if err != nil {
		s.importError(w, r, "That file could not be read: "+err.Error())
		return
	}
	if len(obs) == 0 {
		s.importError(w, r, "That mapping produced no rows. Check the columns you selected.")
		return
	}
	if err := s.store.Append(obs); err != nil {
		s.importError(w, r, "The observations could not be written: "+err.Error())
		return
	}
	if err := s.store.RecordImport(store.ImportRecord{
		At:           time.Now(),
		Filename:     st.Filename,
		SourceID:     sourceID,
		SourceKind:   sourceKind,
		Observations: len(obs),
	}); err != nil {
		log.Printf("import history: %v", err)
	}

	if name := strings.TrimSpace(r.FormValue("save_as")); name != "" {
		if err := s.store.PutMapping(&store.Mapping{
			Name:       name,
			SourceID:   sourceID,
			SourceKind: sourceKind,
			Columns:    columns,
		}); err != nil {
			log.Printf("save mapping: %v", err)
		}
	}

	s.staging.drop(st.ID)
	if err := s.engine.Rebuild(); err != nil {
		s.flashRedirect(w, r, "/import", "Imported, but the view could not be rebuilt: "+err.Error(), true)
		return
	}
	s.flashRedirect(w, r, "/", fmt.Sprintf("Imported %d rows from %s. %d live hosts.",
		len(obs), st.Filename, s.engine.Live()), false)
}

// buildColumnMap splits the flat form values into identifiers and fields.
func buildColumnMap(columns map[string]string) *connector.ColumnMap {
	cm := &connector.ColumnMap{
		Identifiers: map[string]string{},
		Fields:      map[string]string{},
	}
	for key, col := range columns {
		switch {
		case strings.HasPrefix(key, "id:"):
			cm.Identifiers[strings.TrimPrefix(key, "id:")] = col
		case strings.HasPrefix(key, "f:"):
			cm.Fields[strings.TrimPrefix(key, "f:")] = col
		}
	}
	return cm
}

// guessColumn picks the header that best matches a set of aliases: an exact
// match first, then a header that contains an alias.
func guessColumn(headers []string, aliases []string) string {
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	for _, alias := range aliases {
		a := norm(alias)
		for _, h := range headers {
			if norm(h) == a {
				return h
			}
		}
	}
	for _, alias := range aliases {
		a := norm(alias)
		if len(a) < 4 {
			continue
		}
		for _, h := range headers {
			if strings.Contains(norm(h), a) {
				return h
			}
		}
	}
	return ""
}

// preview reads the header row and the first few data rows, so the operator
// can see what each column actually holds before naming it.
func preview(body []byte) (headers []string, rows [][]string, err error) {
	rd := csv.NewReader(bytes.NewReader(body))
	rd.FieldsPerRecord = -1
	rd.LazyQuotes = true
	rd.TrimLeadingSpace = true
	headers, err = rd.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("that file is not readable as CSV: %w", err)
	}
	if len(headers) > 0 {
		headers[0] = strings.TrimPrefix(headers[0], "\ufeff")
	}
	for i := 0; i < 5; i++ {
		row, err := rd.Read()
		if err != nil {
			break
		}
		if len(row) < len(headers) {
			row = append(row, make([]string, len(headers)-len(row))...)
		}
		rows = append(rows, row[:len(headers)])
	}
	return headers, rows, nil
}

// resolveKind checks a submitted source kind against the known set.
func resolveKind(kind string) string {
	for _, k := range kindIDs() {
		if k == kind {
			return kind
		}
	}
	return ""
}

func kindIDs() []string {
	var out []string
	for _, k := range resolve.Kinds() {
		out = append(out, string(k.ID))
	}
	sort.Strings(out)
	return out
}

// sourceIDFromFilename offers a first guess at the feed's name, which is
// usually most of the file name.
func sourceIDFromFilename(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".csv")
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func newStageID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
