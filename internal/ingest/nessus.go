package ingest

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

type nessusItem struct {
	Port         string `xml:"port,attr"`
	Protocol     string `xml:"protocol,attr"`
	Service      string `xml:"svc_name,attr"`
	Severity     string `xml:"severity,attr"`
	PluginID     string `xml:"pluginID,attr"`
	PluginName   string `xml:"pluginName,attr"`
	PluginFamily string `xml:"pluginFamily,attr"`

	Synopsis      string   `xml:"synopsis"`
	Description   string   `xml:"description"`
	Solution      string   `xml:"solution"`
	RiskFactor    string   `xml:"risk_factor"`
	PluginOutput  string   `xml:"plugin_output"`
	CVEs          []string `xml:"cve"`
	BIDs          []string `xml:"bid"`
	Xrefs         []string `xml:"xref"`
	SeeAlso       string   `xml:"see_also"`
	CVSS2Score    string   `xml:"cvss_base_score"`
	CVSS2Vector   string   `xml:"cvss_vector"`
	CVSS3Score    string   `xml:"cvss3_base_score"`
	CVSS3Vector   string   `xml:"cvss3_vector"`
	CVSS4Score    string   `xml:"cvss4_base_score"`
	CVSS4Vector   string   `xml:"cvss4_vector"`
	STIGSeverity  string   `xml:"stig_severity"`
	IAVA          string   `xml:"iava"`
	PluginModDate string   `xml:"plugin_modification_date"`
	Compliance    string   `xml:"compliance"`

	// Nessus compliance audits carry their result in a parallel set of
	// elements rather than in severity, so they are read separately.
	ComplianceCheckName string `xml:"compliance-check-name"`
	ComplianceResult    string `xml:"compliance-result"`
	ComplianceActual    string `xml:"compliance-actual-value"`
	ComplianceInfo      string `xml:"compliance-info"`
	ComplianceSolution  string `xml:"compliance-solution"`
	ComplianceReference string `xml:"compliance-reference"`
	ComplianceAuditFile string `xml:"compliance-audit-file"`
	ComplianceCheckID   string `xml:"compliance-check-id"`
	ComplianceSeverity  string `xml:"compliance-severity"`
}

type nessusHostProps struct {
	Tags []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"tag"`
}

// parseNessus reads a .nessus export as a token stream. A single export from a
// large estate can be hundreds of megabytes, so hosts are decoded one at a time
// and the document is never held in memory as a tree.
func parseNessus(data []byte, filename string) (*Result, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	res := &Result{Scan: model.Scan{
		Format: string(FormatNessus), Kind: "vulnerability",
		Filename: filename, Tool: "Nessus",
	}}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "Report":
			for _, a := range se.Attr {
				if a.Name.Local == "name" && res.Scan.Title == "" {
					res.Scan.Title = oneLine(a.Value)
				}
			}
		case "policyName":
			var v string
			if err := dec.DecodeElement(&v, &se); err == nil && res.Scan.BenchmarkID == "" {
				res.Scan.BenchmarkID = oneLine(v)
			}
		case "ReportHost":
			name := ""
			for _, a := range se.Attr {
				if a.Name.Local == "name" {
					name = a.Value
				}
			}
			host, err := decodeNessusHost(dec, se, name, res)
			if err != nil {
				return nil, err
			}
			if host != nil {
				res.Hosts = append(res.Hosts, host)
			}
		}
	}
	if len(res.Hosts) == 0 {
		return nil, fmt.Errorf("no hosts were found; this does not look like a Nessus export")
	}
	if res.Total() == 0 {
		return nil, errNoRecords
	}
	if res.Scan.Title == "" {
		res.Scan.Title = "Vulnerability scan"
	}
	return res, nil
}

func decodeNessusHost(dec *xml.Decoder, start xml.StartElement, name string, res *Result) (*Host, error) {
	host := &Host{Name: name}
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("reading host %s: %w", name, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "HostProperties":
				var props nessusHostProps
				if err := dec.DecodeElement(&props, &t); err != nil {
					return nil, err
				}
				applyHostProperties(host, props, res)
			case "ReportItem":
				var it nessusItem
				if err := dec.DecodeElement(&it, &t); err != nil {
					return nil, err
				}
				host.Findings = append(host.Findings, nessusFinding(it))
			default:
				depth++
			}
		case xml.EndElement:
			depth--
		}
	}
	if host.Name == "" && len(host.IPs) > 0 {
		host.Name = host.IPs[0]
	}
	host.Type = assetTypeFor("", host.OS, host.Model)
	return host, nil
}

func applyHostProperties(host *Host, props nessusHostProps, res *Result) {
	for _, tag := range props.Tags {
		v := strings.TrimSpace(tag.Value)
		if v == "" {
			continue
		}
		switch tag.Name {
		case "host-ip":
			host.IPs = append(host.IPs, v)
		case "host-fqdn", "hostname":
			if host.FQDN == "" {
				host.FQDN = v
			}
		case "netbios-name":
			if host.Name == "" || strings.Count(host.Name, ".") == 3 {
				host.Name = v
			}
		case "operating-system", "os":
			if host.OS == "" {
				host.OS = oneLine(v)
			}
		case "mac-address":
			host.MACs = append(host.MACs, splitList(v)...)
		case "system-type":
			host.Role = v
		case "bios-uuid", "host-uuid":
			if host.Serial == "" {
				host.Serial = v
			}
		case "HOST_START", "HOST_START_TIMESTAMP":
			if res.Scan.ScanDate.IsZero() {
				if t, ok := parseTime(v); ok {
					res.Scan.ScanDate = t
				} else if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
					res.Scan.ScanDate = unixUTC(secs)
				}
			}
		}
	}
	host.IPs = model.Dedup(host.IPs)
	host.MACs = model.Dedup(host.MACs)
}

func nessusFinding(it nessusItem) *model.Finding {
	f := &model.Finding{
		RuleID:      it.PluginID,
		GroupID:     it.PluginID,
		Title:       oneLine(it.PluginName),
		Description: clean(firstNonEmpty(it.Description, it.Synopsis)),
		FixText:     clean(firstNonEmpty(it.Solution, it.ComplianceSolution)),
		CheckText:   clean(it.ComplianceInfo),
		Protocol:    it.Protocol,
		Service:     it.Service,
		CVEs:        model.Dedup(it.CVEs),
	}
	if p, err := strconv.Atoi(strings.TrimSpace(it.Port)); err == nil {
		f.Port = p
	}
	for _, ref := range append(append([]string{}, it.BIDs...), it.Xrefs...) {
		if ref = strings.TrimSpace(ref); ref != "" {
			f.References = append(f.References, ref)
		}
	}
	if it.IAVA != "" {
		f.References = append(f.References, "IAVA "+strings.TrimSpace(it.IAVA))
	}
	if it.ComplianceReference != "" {
		f.References = append(f.References, splitList(it.ComplianceReference)...)
	}
	f.References = model.Dedup(f.References)

	// A compliance audit result is a configuration check, not a vulnerability,
	// so its pass/fail and its own severity are authoritative.
	if strings.EqualFold(strings.TrimSpace(it.Compliance), "true") || it.ComplianceCheckName != "" {
		f.Title = oneLine(firstNonEmpty(it.ComplianceCheckName, it.PluginName))
		f.GroupID = firstNonEmpty(it.ComplianceCheckID, it.PluginID)
		f.Status = complianceStatus(it.ComplianceResult)
		f.RawSeverity = firstNonEmpty(it.ComplianceSeverity, it.RiskFactor, it.Severity)
		f.Severity = model.Severity(f.RawSeverity).Normalise()
		f.FindingDetails = clean(it.ComplianceActual)
		if it.ComplianceAuditFile != "" {
			f.References = append(f.References, "audit file: "+it.ComplianceAuditFile)
		}
		return f
	}

	f.FindingDetails = clean(it.PluginOutput)
	score, vector := bestCVSS(it)
	f.CVSS, f.CVSSVector = score, vector
	f.RawSeverity = firstNonEmpty(it.RiskFactor, it.Severity)
	switch {
	case strings.EqualFold(strings.TrimSpace(it.RiskFactor), "none"):
		// Nessus informational plugins describe the host rather than a
		// weakness. They are kept, because they are the best evidence an
		// inventory has, but they never count as open.
		f.Severity = model.SeverityInfo
		f.Status = model.StatusNotAFinding
		return f
	case it.STIGSeverity != "":
		f.Severity = model.SeverityFromCategory(it.STIGSeverity)
	case score > 0:
		f.Severity = model.SeverityFromCVSS(score)
	default:
		f.Severity = model.Severity(f.RawSeverity).Normalise()
	}
	f.Status = model.StatusOpen
	return f
}

// bestCVSS prefers the newest scoring system the plugin carries, because that
// is the one the organisation's remediation deadlines are written against.
func bestCVSS(it nessusItem) (float64, string) {
	for _, pair := range [][2]string{
		{it.CVSS4Score, it.CVSS4Vector},
		{it.CVSS3Score, it.CVSS3Vector},
		{it.CVSS2Score, it.CVSS2Vector},
	} {
		if v, err := strconv.ParseFloat(strings.TrimSpace(pair[0]), 64); err == nil && v > 0 {
			return v, strings.TrimSpace(pair[1])
		}
	}
	return 0, ""
}

func unixUTC(secs int64) time.Time { return time.Unix(secs, 0).UTC() }

func complianceStatus(v string) model.FindingStatus {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "PASSED", "PASS":
		return model.StatusNotAFinding
	case "FAILED", "FAIL":
		return model.StatusOpen
	case "WARNING", "ERROR":
		return model.StatusNotReviewed
	}
	return model.FindingStatus(v).Normalise()
}
