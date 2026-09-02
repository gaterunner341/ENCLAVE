package ingest

import (
	"encoding/csv"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gaterunner341/enclave/internal/model"
)

// Field names the pieces of a finding a spreadsheet column can supply. They
// are the vocabulary of the import mapping screen.
type Field string

const (
	FAssetName Field = "asset_name"
	FFQDN      Field = "fqdn"
	FIP        Field = "ip"
	FMAC       Field = "mac"
	FOS        Field = "os"
	FSerial    Field = "serial"
	FAssetType Field = "asset_type"
	FRole      Field = "role"

	FRuleID   Field = "rule_id"
	FGroupID  Field = "group_id"
	FTitle    Field = "title"
	FSeverity Field = "severity"
	FStatus   Field = "status"

	FDescription Field = "description"
	FCheck       Field = "check"
	FFix         Field = "fix"
	FDetails     Field = "details"
	FComments    Field = "comments"

	FCCI      Field = "cci"
	FCVE      Field = "cve"
	FControl  Field = "control"
	FCVSS     Field = "cvss"
	FPort     Field = "port"
	FProtocol Field = "protocol"
	FService  Field = "service"

	FFirstSeen Field = "first_seen"
	FLastSeen  Field = "last_seen"
)

// Fields is the ordered list shown on the mapping screen. The first block
// identifies the asset, the second the finding, the third the evidence.
var Fields = []Field{
	FAssetName, FFQDN, FIP, FMAC, FOS, FSerial, FAssetType, FRole,
	FTitle, FRuleID, FGroupID, FSeverity, FStatus,
	FDescription, FCheck, FFix, FDetails, FComments,
	FCCI, FCVE, FControl, FCVSS, FPort, FProtocol, FService,
	FFirstSeen, FLastSeen,
}

// Label describes a field for a person choosing columns.
func (f Field) Label() string {
	switch f {
	case FAssetName:
		return "Asset name"
	case FFQDN:
		return "Fully qualified name"
	case FIP:
		return "IP address"
	case FMAC:
		return "MAC address"
	case FOS:
		return "Operating system or platform"
	case FSerial:
		return "Serial number"
	case FAssetType:
		return "Asset type"
	case FRole:
		return "Role"
	case FRuleID:
		return "Rule or plugin identifier"
	case FGroupID:
		return "Group or vulnerability identifier"
	case FTitle:
		return "Finding title"
	case FSeverity:
		return "Severity"
	case FStatus:
		return "Result or status"
	case FDescription:
		return "Description"
	case FCheck:
		return "Check text"
	case FFix:
		return "Fix or solution"
	case FDetails:
		return "Finding details or output"
	case FComments:
		return "Comments"
	case FCCI:
		return "CCI reference"
	case FCVE:
		return "CVE"
	case FControl:
		return "Control identifier"
	case FCVSS:
		return "CVSS score"
	case FPort:
		return "Port"
	case FProtocol:
		return "Protocol"
	case FService:
		return "Service"
	case FFirstSeen:
		return "First seen"
	case FLastSeen:
		return "Last seen"
	}
	return string(f)
}

// Required reports whether an import cannot proceed without the field.
func (f Field) Required() bool { return f == FTitle }

// aliases are the column headings the common exporters use. Matching is done
// on a normalised heading, so case, punctuation and spacing do not matter.
var aliases = map[Field][]string{
	FAssetName: {"asset name", "asset names", "host", "hostname", "host name", "name", "netbios name",
		"netbios", "computer name", "device name", "system name", "target", "machine name", "asset"},
	FFQDN:      {"fqdn", "dns name", "dns", "full name", "host fqdn", "dns hostname"},
	FIP:        {"ip", "ip address", "ipv4", "ipv4 address", "host ip", "asset ip address", "ip addresses", "address"},
	FMAC:       {"mac", "mac address", "hardware address", "physical address"},
	FOS:        {"os", "operating system", "platform", "asset os name", "os name", "product"},
	FSerial:    {"serial", "serial number", "asset tag", "uuid", "bios uuid", "hardware uuid"},
	FAssetType: {"asset type", "device type", "type", "system type", "category"},
	FRole:      {"role", "function", "asset role", "business function"},

	FRuleID:  {"rule id", "rule", "plugin", "plugin id", "pluginid", "qid", "check id", "vulnerability id", "rule version", "stig id", "control number"},
	FGroupID: {"group id", "vuln num", "vulnerability number", "v-id", "vuln id", "group", "vulnid"},
	FTitle: {"title", "rule title", "plugin name", "vulnerability title", "finding", "finding title",
		"name of check", "vulnerability", "synopsis", "short description", "summary", "issue"},
	FSeverity: {"severity", "risk", "risk factor", "severity level", "vulnerability severity level",
		"criticality", "cat", "category", "raw severity", "severity code"},
	FStatus: {"status", "result", "state", "compliance status", "finding status", "check result", "pass fail"},

	FDescription: {"description", "vuln discuss", "discussion", "threat", "details", "vulnerability description", "background"},
	FCheck:       {"check", "check content", "check text", "audit", "test", "evidence required"},
	FFix:         {"fix", "fix text", "solution", "remediation", "vulnerability solution", "recommendation", "mitigation"},
	FDetails:     {"finding details", "plugin output", "output", "results", "actual value", "observed"},
	FComments:    {"comments", "comment", "notes", "analyst comment"},

	FCCI:      {"cci", "cci ref", "cci reference", "ccis"},
	FCVE:      {"cve", "cve id", "cve ids", "cves", "vulnerability cve ids"},
	FControl:  {"control", "control id", "nist control", "controls", "800-53", "nist 800-53", "safeguard", "subcategory"},
	FCVSS:     {"cvss", "cvss score", "cvss base score", "cvss v3 base score", "cvss3 base score", "cvssv3 score", "vulnerability cvssv3 score", "base score"},
	FPort:     {"port"},
	FProtocol: {"protocol", "proto", "transport"},
	FService:  {"service", "svc name", "service name"},

	FFirstSeen: {"first seen", "first discovered", "first detected", "date discovered", "detected", "created"},
	FLastSeen:  {"last seen", "last observed", "last detected", "last found", "scan date", "date"},
}

// CSVOptions carries the decisions a person makes on the import screen.
type CSVOptions struct {
	// Mapping is field to column heading. An empty entry means the field is
	// not supplied by the file.
	Mapping map[Field]string
	// Defaults fill in what the file does not carry.
	DefaultAssetName string
	DefaultAssetType model.AssetType
	Title            string
	Kind             string
	Delimiter        rune
}

// normHeading strips the differences between "CVSS V3 Base Score",
// "cvss_v3_base_score" and "CVSS v3 Base Score".
func normHeading(h string) string {
	var b strings.Builder
	prevSpace := true
	for _, r := range strings.ToLower(strings.TrimSpace(h)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevSpace = false
		default:
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

// DetectColumns proposes a mapping from a header row. Exact alias matches win;
// a heading that contains an alias is used only when nothing exact was found,
// so that "Description" does not steal the column "Vulnerability Description"
// was meant for.
func DetectColumns(header []string) map[Field]string {
	out := map[Field]string{}
	taken := map[string]bool{}
	normed := make([]string, len(header))
	for i, h := range header {
		normed[i] = normHeading(h)
	}
	for _, f := range Fields {
		for _, alias := range aliases[f] {
			for i, n := range normed {
				if n == alias && !taken[header[i]] {
					out[f] = header[i]
					taken[header[i]] = true
					break
				}
			}
			if _, ok := out[f]; ok {
				break
			}
		}
	}
	for _, f := range Fields {
		if _, ok := out[f]; ok {
			continue
		}
		for _, alias := range aliases[f] {
			if len(alias) < 4 {
				continue
			}
			for i, n := range normed {
				if strings.Contains(n, alias) && !taken[header[i]] {
					out[f] = header[i]
					taken[header[i]] = true
					break
				}
			}
			if _, ok := out[f]; ok {
				break
			}
		}
	}
	return out
}

// Preview describes a CSV file well enough for the import screen to show the
// user what was detected before anything is written.
type Preview struct {
	Header  []string
	Rows    [][]string
	Total   int
	Mapping map[Field]string
	Delim   rune
}

// PreviewCSV reads the header and the first few rows.
func PreviewCSV(data []byte, sample int) (*Preview, error) {
	delim := sniffDelimiter(data)
	r := newCSVReader(data, delim)
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("reading the header row: %w", err)
	}
	for i := range header {
		header[i] = strings.TrimSpace(strings.TrimPrefix(header[i], bom))
	}
	p := &Preview{Header: header, Mapping: DetectColumns(header), Delim: delim}
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		p.Total++
		if len(p.Rows) < sample {
			p.Rows = append(p.Rows, row)
		}
	}
	return p, nil
}

// bom is the UTF-8 byte order mark that Excel writes ahead of the first
// heading. Left in place it turns the first column name into one nothing
// matches.
const bom = "\ufeff"

func newCSVReader(data []byte, delim rune) *csv.Reader {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	r.Comma = delim
	return r
}

// sniffDelimiter picks between comma, tab, semicolon and pipe by counting them
// in the first line. Exports from European locales use semicolons often enough
// that guessing wrong is a real failure mode.
func sniffDelimiter(data []byte) rune {
	line := string(data)
	if i := strings.IndexAny(line, "\r\n"); i > 0 {
		line = line[:i]
	}
	best, bestN := ',', 0
	for _, d := range []rune{',', '\t', ';', '|'} {
		if n := strings.Count(line, string(d)); n > bestN {
			best, bestN = d, n
		}
	}
	return best
}

func parseCSV(data []byte, filename string, opts CSVOptions) (*Result, error) {
	delim := opts.Delimiter
	if delim == 0 {
		delim = sniffDelimiter(data)
	}
	r := newCSVReader(data, delim)
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("reading the header row: %w", err)
	}
	for i := range header {
		header[i] = strings.TrimSpace(strings.TrimPrefix(header[i], bom))
	}
	mapping := opts.Mapping
	if len(mapping) == 0 {
		mapping = DetectColumns(header)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	get := func(row []string, f Field) string {
		h, ok := mapping[f]
		if !ok || h == "" {
			return ""
		}
		i, ok := col[h]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	if h, ok := mapping[FTitle]; !ok || h == "" {
		return nil, fmt.Errorf("a finding title column has to be chosen before the file can be imported")
	}

	res := &Result{Scan: model.Scan{
		Format: string(FormatCSV), Filename: filename,
		Title: firstNonEmpty(opts.Title, "Imported results"),
		Kind:  firstNonEmpty(opts.Kind, "import"),
		Tool:  "CSV import",
	}}
	byHost := map[string]*Host{}
	order := []string{}
	line := 1

	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		line++
		title := oneLine(get(row, FTitle))
		if title == "" {
			continue
		}
		name := firstNonEmpty(get(row, FAssetName), get(row, FFQDN), get(row, FIP), opts.DefaultAssetName)
		if name == "" {
			name = "Unidentified asset"
		}
		key := strings.ToLower(name)
		h, ok := byHost[key]
		if !ok {
			h = &Host{
				Name:   name,
				FQDN:   get(row, FFQDN),
				Serial: get(row, FSerial),
				OS:     get(row, FOS),
				Role:   get(row, FRole),
				IPs:    splitList(get(row, FIP)),
				MACs:   splitList(get(row, FMAC)),
			}
			if t := strings.TrimSpace(get(row, FAssetType)); t != "" {
				h.Type = normaliseAssetType(t)
			}
			if h.Type == "" {
				h.Type = opts.DefaultAssetType
			}
			if h.Type == "" {
				h.Type = assetTypeFor(h.Role, h.OS, "")
			}
			byHost[key] = h
			order = append(order, key)
		} else {
			h.IPs = model.Dedup(append(h.IPs, splitList(get(row, FIP))...))
			h.MACs = model.Dedup(append(h.MACs, splitList(get(row, FMAC))...))
		}

		f := &model.Finding{
			Title:          title,
			RuleID:         get(row, FRuleID),
			GroupID:        get(row, FGroupID),
			Description:    clean(get(row, FDescription)),
			CheckText:      clean(get(row, FCheck)),
			FixText:        clean(get(row, FFix)),
			FindingDetails: clean(get(row, FDetails)),
			Comments:       clean(get(row, FComments)),
			CCIs:           splitList(get(row, FCCI)),
			CVEs:           splitList(get(row, FCVE)),
			Protocol:       get(row, FProtocol),
			Service:        get(row, FService),
		}
		if v := get(row, FCVSS); v != "" {
			if score, err := strconv.ParseFloat(v, 64); err == nil {
				f.CVSS = score
			}
		}
		if v := get(row, FPort); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				f.Port = p
			}
		}
		rawSev := get(row, FSeverity)
		f.RawSeverity = rawSev
		switch {
		case rawSev != "":
			f.Severity = model.SeverityFromCategory(rawSev)
		case f.CVSS > 0:
			f.Severity = model.SeverityFromCVSS(f.CVSS)
		default:
			f.Severity = model.SeverityInfo
		}
		if status := get(row, FStatus); status != "" {
			f.Status = model.FindingStatus(status).Normalise()
		} else {
			// A row in a vulnerability export exists because the condition was
			// found, so a file with no status column is read as all-open.
			f.Status = model.StatusOpen
		}
		if v := get(row, FFirstSeen); v != "" {
			if t, ok := parseTime(v); ok {
				f.FirstSeen = t
			}
		}
		if v := get(row, FLastSeen); v != "" {
			if t, ok := parseTime(v); ok {
				f.LastSeen = t
				if res.Scan.ScanDate.Before(t) {
					res.Scan.ScanDate = t
				}
			}
		}
		if ctl := get(row, FControl); ctl != "" {
			// A control column is a direct citation, recorded under a reserved
			// key that the mapping layer copies into every catalogue it can.
			f.ControlRefs = map[string][]string{"": splitList(ctl)}
		}
		h.Findings = append(h.Findings, f)
	}
	if len(order) == 0 {
		return nil, errNoRecords
	}
	for _, k := range order {
		res.Hosts = append(res.Hosts, byHost[k])
	}
	return res, nil
}

func normaliseAssetType(v string) model.AssetType {
	n := normHeading(v)
	for _, t := range model.AssetTypes {
		if n == normHeading(string(t)) || n == normHeading(t.Label()) {
			return t
		}
	}
	return assetTypeFor(v, v, "")
}

// HeaderSuggestions lists the columns not already claimed by a mapping, so the
// import screen can offer them.
func HeaderSuggestions(header []string, mapping map[Field]string) []string {
	used := map[string]bool{}
	for _, v := range mapping {
		used[v] = true
	}
	out := []string{}
	for _, h := range header {
		if !used[h] {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}
