// Package ingest reads scan result files and turns them into assets and
// findings. It is the only package that knows about file formats.
//
// Every parser produces the same shape: a Scan describing the artefact, and a
// list of Hosts each carrying its own findings. Whether the file came from a
// STIG checklist, a SCAP benchmark, a vulnerability scanner or a spreadsheet
// stops mattering the moment it leaves this package.
package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// Host is one target described by a result file, with the findings recorded
// against it.
type Host struct {
	Name      string
	FQDN      string
	Serial    string
	OS        string
	OSVersion string
	Vendor    string
	Model     string
	Role      string
	Type      model.AssetType
	IPs       []string
	MACs      []string
	Findings  []*model.Finding
}

// Result is everything one file contained.
type Result struct {
	Scan  model.Scan
	Hosts []*Host
	Notes []string
}

// Total counts the findings across every host.
func (r *Result) Total() int {
	n := 0
	for _, h := range r.Hosts {
		n += len(h.Findings)
	}
	return n
}

// Format names a supported input file type.
type Format string

const (
	FormatCKL    Format = "ckl"    // STIG Viewer 2 checklist, XML
	FormatCKLB   Format = "cklb"   // STIG Viewer 3 checklist, JSON
	FormatXCCDF  Format = "xccdf"  // SCAP benchmark results, XML
	FormatNessus Format = "nessus" // Nessus / ACAS scan export, XML
	FormatCSV    Format = "csv"    // any spreadsheet export
)

// Label describes a format on the import page.
func (f Format) Label() string {
	switch f {
	case FormatCKL:
		return "STIG checklist (.ckl)"
	case FormatCKLB:
		return "STIG checklist (.cklb)"
	case FormatXCCDF:
		return "SCAP results (XCCDF or ARF)"
	case FormatNessus:
		return "Nessus or ACAS export (.nessus)"
	case FormatCSV:
		return "Spreadsheet export (.csv)"
	}
	return string(f)
}

// Kind is the broad category a format belongs to, recorded on the scan so that
// coverage can distinguish "we ran a benchmark" from "we ran a vuln scan".
func (f Format) Kind() string {
	switch f {
	case FormatCKL, FormatCKLB:
		return "stig"
	case FormatXCCDF:
		return "benchmark"
	case FormatNessus:
		return "vulnerability"
	}
	return "import"
}

// Detect identifies a file from its first bytes and its name. Extensions lie
// often enough that the content is checked first.
func Detect(data []byte, filename string) Format {
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	lower := bytes.ToLower(head)
	switch {
	case bytes.Contains(lower, []byte("<nessusclientdata")):
		return FormatNessus
	case bytes.Contains(lower, []byte("<checklist")):
		return FormatCKL
	case bytes.Contains(lower, []byte("<asset-report-collection")),
		bytes.Contains(lower, []byte("<benchmark")),
		bytes.Contains(lower, []byte("<testresult")),
		bytes.Contains(lower, []byte("xccdf")):
		return FormatXCCDF
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	trimmed = bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 byte order mark
	trimmed = bytes.TrimLeft(trimmed, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte("{")) {
		return FormatCKLB
	}
	name := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(name, ".ckl"):
		return FormatCKL
	case strings.HasSuffix(name, ".cklb"):
		return FormatCKLB
	case strings.HasSuffix(name, ".nessus"):
		return FormatNessus
	case strings.HasSuffix(name, ".xml"):
		return FormatXCCDF
	}
	return FormatCSV
}

// Parse reads a file in whichever format it turns out to be. opts carries the
// column mapping, which only the CSV reader uses.
func Parse(data []byte, filename string, opts CSVOptions) (*Result, error) {
	switch f := Detect(data, filename); f {
	case FormatCKL:
		return parseCKL(data, filename)
	case FormatCKLB:
		return parseCKLB(data, filename)
	case FormatXCCDF:
		return parseXCCDF(data, filename)
	case FormatNessus:
		return parseNessus(data, filename)
	default:
		return parseCSV(data, filename, opts)
	}
}

// Fingerprint is the identity of a finding across repeated imports: the same
// rule against the same asset. It deliberately excludes status, severity and
// dates, so that a re-scan updates one row rather than adding another.
func Fingerprint(assetID, ruleID, groupID, title string) string {
	key := ruleID
	if key == "" {
		key = groupID
	}
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(title))
	}
	sum := sha256.Sum256([]byte(assetID + "\x00" + strings.ToLower(strings.TrimSpace(key))))
	return hex.EncodeToString(sum[:16])
}

// clean collapses the whitespace that XML and CSV exports carry, without
// destroying the paragraph structure of check and fix text.
func clean(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	out := strings.Join(lines, "\n")
	for strings.Contains(out, "\n\n\n") {
		out = strings.ReplaceAll(out, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(out)
}

// oneLine is clean() for fields that must not wrap, such as titles.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// parseTime accepts the several timestamp shapes that scanners emit.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05",
		"2006/01/02 15:04:05", "Mon Jan 2 15:04:05 2006", "2006-01-02",
		"01/02/2006 15:04:05", "01/02/2006", "1/2/2006 15:04",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// splitList breaks the comma, semicolon or newline separated lists that
// exports use for CVEs, addresses and references.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '|' || r == ' '
	})
	return model.Dedup(fields)
}

// assetTypeFor guesses whether a target is a host or network gear from the
// text a scanner recorded about it. A wrong guess is correctable on the asset
// page; not guessing at all leaves every import needing hand classification.
func assetTypeFor(role, os, model_ string) model.AssetType {
	hay := strings.ToLower(role + " " + os + " " + model_)
	switch {
	case containsAny(hay, "ios-xe", "ios xe", "nx-os", "nxos", "junos", "cisco ios", "arista eos", "routeros", "switch", "router", "wlan controller"):
		return model.AssetNetwork
	case containsAny(hay, "firewall", "palo alto", "pan-os", "fortios", "fortigate", "asa", "checkpoint", "check point", "ids", "ips appliance"):
		return model.AssetSecurity
	case containsAny(hay, "esxi", "vsphere", "hypervisor"):
		return model.AssetVirtual
	case containsAny(hay, "workstation", "windows 10", "windows 11", "macos", "desktop"):
		return model.AssetWorkstation
	case containsAny(hay, "server", "windows server", "linux", "rhel", "ubuntu", "suse", "aix", "solaris"):
		return model.AssetServer
	}
	return model.AssetOther
}

func containsAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// errNoRecords is returned when a file parses but describes nothing, which is
// a different problem from a file that will not parse at all.
var errNoRecords = fmt.Errorf("the file parsed but contained no results")
