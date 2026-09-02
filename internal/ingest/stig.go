package ingest

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// ---------- STIG Viewer 2 checklists (.ckl) ----------

type cklDoc struct {
	Asset struct {
		Role      string `xml:"ROLE"`
		AssetType string `xml:"ASSET_TYPE"`
		HostName  string `xml:"HOST_NAME"`
		HostIP    string `xml:"HOST_IP"`
		HostMAC   string `xml:"HOST_MAC"`
		HostFQDN  string `xml:"HOST_FQDN"`
		TechArea  string `xml:"TECH_AREA"`
		Comment   string `xml:"TARGET_COMMENT"`
	} `xml:"ASSET"`
	IStigs []struct {
		Info struct {
			Data []struct {
				Name  string `xml:"SID_NAME"`
				Value string `xml:"SID_DATA"`
			} `xml:"SI_DATA"`
		} `xml:"STIG_INFO"`
		Vulns []struct {
			Data []struct {
				Attribute string `xml:"VULN_ATTRIBUTE"`
				Value     string `xml:"ATTRIBUTE_DATA"`
			} `xml:"STIG_DATA"`
			Status                string `xml:"STATUS"`
			FindingDetails        string `xml:"FINDING_DETAILS"`
			Comments              string `xml:"COMMENTS"`
			SeverityOverride      string `xml:"SEVERITY_OVERRIDE"`
			SeverityJustification string `xml:"SEVERITY_JUSTIFICATION"`
		} `xml:"VULN"`
	} `xml:"STIGS>iSTIG"`
}

func parseCKL(data []byte, filename string) (*Result, error) {
	var doc cklDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("reading the checklist: %w", err)
	}
	host := &Host{
		Name: strings.TrimSpace(doc.Asset.HostName),
		FQDN: strings.TrimSpace(doc.Asset.HostFQDN),
		Role: strings.TrimSpace(doc.Asset.Role),
		IPs:  splitList(doc.Asset.HostIP),
		MACs: splitList(doc.Asset.HostMAC),
	}
	if strings.EqualFold(strings.TrimSpace(doc.Asset.AssetType), "Non-Computing") {
		host.Type = model.AssetNetwork
	}

	res := &Result{Scan: model.Scan{Format: string(FormatCKL), Kind: "stig", Filename: filename, Tool: "STIG Viewer"}}
	titles := []string{}

	for _, istig := range doc.IStigs {
		info := map[string]string{}
		for _, d := range istig.Info.Data {
			info[strings.ToLower(strings.TrimSpace(d.Name))] = strings.TrimSpace(d.Value)
		}
		benchTitle := firstNonEmpty(info["title"], info["stigid"], "STIG")
		titles = append(titles, benchTitle)
		if res.Scan.BenchmarkID == "" {
			res.Scan.BenchmarkID = info["stigid"]
			res.Scan.Version = strings.TrimSpace(info["version"] + " " + info["releaseinfo"])
		}
		if host.OS == "" {
			host.OS = benchTitle
		}
		for _, v := range istig.Vulns {
			attr := map[string]string{}
			var ccis, refs []string
			for _, d := range v.Data {
				name := strings.TrimSpace(d.Attribute)
				val := strings.TrimSpace(d.Value)
				switch name {
				case "CCI_REF":
					if val != "" {
						ccis = append(ccis, val)
					}
				case "LEGACY_ID":
					if val != "" {
						refs = append(refs, val)
					}
				default:
					// Repeated attributes are joined rather than overwritten so
					// that multi-valued IA controls survive.
					if prev, ok := attr[name]; ok && prev != "" && val != "" {
						attr[name] = prev + ", " + val
					} else {
						attr[name] = val
					}
				}
			}
			sev := attr["Severity"]
			if o := strings.TrimSpace(v.SeverityOverride); o != "" && !strings.EqualFold(o, "none") {
				sev = o
			}
			f := &model.Finding{
				GroupID:        attr["Vuln_Num"],
				RuleID:         firstNonEmpty(attr["Rule_ID"], attr["Rule_Ver"]),
				Title:          oneLine(firstNonEmpty(attr["Rule_Title"], attr["Group_Title"])),
				Severity:       model.Severity(sev).Normalise(),
				RawSeverity:    sev,
				Status:         model.FindingStatus(v.Status).Normalise(),
				Description:    clean(attr["Vuln_Discuss"]),
				CheckText:      clean(attr["Check_Content"]),
				FixText:        clean(attr["Fix_Text"]),
				FindingDetails: clean(v.FindingDetails),
				Comments:       clean(v.Comments),
				CCIs:           model.Dedup(ccis),
				References:     model.Dedup(append(refs, splitList(attr["STIGRef"])...)),
			}
			if ctl := strings.TrimSpace(attr["IA_Controls"]); ctl != "" {
				f.References = append(f.References, "IA controls: "+ctl)
			}
			host.Findings = append(host.Findings, f)
		}
	}
	if len(host.Findings) == 0 {
		return nil, errNoRecords
	}
	res.Scan.Title = strings.Join(model.Dedup(titles), "; ")
	if host.Type == "" {
		host.Type = assetTypeFor(host.Role, host.OS, "")
	}
	res.Hosts = []*Host{host}
	return res, nil
}

// ---------- STIG Viewer 3 checklists (.cklb) ----------

type cklbDoc struct {
	Title      string `json:"title"`
	ID         string `json:"id"`
	TargetData struct {
		TargetType     string `json:"target_type"`
		HostName       string `json:"host_name"`
		IPAddress      string `json:"ip_address"`
		MACAddress     string `json:"mac_address"`
		FQDN           string `json:"fqdn"`
		Role           string `json:"role"`
		Comments       string `json:"comments"`
		TechnologyArea string `json:"technology_area"`
	} `json:"target_data"`
	Stigs []struct {
		StigName    string `json:"stig_name"`
		DisplayName string `json:"display_name"`
		StigID      string `json:"stig_id"`
		ReleaseInfo string `json:"release_info"`
		Version     string `json:"version"`
		Rules       []struct {
			GroupID        string   `json:"group_id"`
			RuleID         string   `json:"rule_id"`
			RuleVersion    string   `json:"rule_version"`
			GroupTitle     string   `json:"group_title"`
			RuleTitle      string   `json:"rule_title"`
			Severity       string   `json:"severity"`
			Discussion     string   `json:"discussion"`
			CheckContent   string   `json:"check_content"`
			FixText        string   `json:"fix_text"`
			Status         string   `json:"status"`
			Comments       string   `json:"comments"`
			FindingDetails string   `json:"finding_details"`
			CCIs           []string `json:"ccis"`
			LegacyIDs      []string `json:"legacy_ids"`
			References     string   `json:"references"`
			Overrides      struct {
				Severity struct {
					Severity string `json:"severity"`
					Reason   string `json:"reason"`
				} `json:"severity"`
			} `json:"overrides"`
		} `json:"rules"`
	} `json:"stigs"`
}

func parseCKLB(data []byte, filename string) (*Result, error) {
	var doc cklbDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("reading the checklist: %w", err)
	}
	if len(doc.Stigs) == 0 {
		return nil, fmt.Errorf("this JSON file is not a STIG checklist: it has no stigs section")
	}
	host := &Host{
		Name: strings.TrimSpace(doc.TargetData.HostName),
		FQDN: strings.TrimSpace(doc.TargetData.FQDN),
		Role: strings.TrimSpace(doc.TargetData.Role),
		IPs:  splitList(doc.TargetData.IPAddress),
		MACs: splitList(doc.TargetData.MACAddress),
	}
	if strings.EqualFold(strings.TrimSpace(doc.TargetData.TargetType), "Non-Computing") {
		host.Type = model.AssetNetwork
	}
	res := &Result{Scan: model.Scan{
		Format: string(FormatCKLB), Kind: "stig", Filename: filename,
		Tool: "STIG Viewer 3", Title: oneLine(doc.Title),
	}}
	titles := []string{}
	for _, st := range doc.Stigs {
		name := firstNonEmpty(st.DisplayName, st.StigName, st.StigID)
		titles = append(titles, name)
		if res.Scan.BenchmarkID == "" {
			res.Scan.BenchmarkID = st.StigID
			res.Scan.Version = strings.TrimSpace(st.Version + " " + st.ReleaseInfo)
		}
		if host.OS == "" {
			host.OS = name
		}
		for _, r := range st.Rules {
			sev := r.Severity
			if o := strings.TrimSpace(r.Overrides.Severity.Severity); o != "" {
				sev = o
			}
			host.Findings = append(host.Findings, &model.Finding{
				GroupID:        r.GroupID,
				RuleID:         firstNonEmpty(r.RuleID, r.RuleVersion),
				Title:          oneLine(firstNonEmpty(r.RuleTitle, r.GroupTitle)),
				Severity:       model.Severity(sev).Normalise(),
				RawSeverity:    sev,
				Status:         model.FindingStatus(r.Status).Normalise(),
				Description:    clean(r.Discussion),
				CheckText:      clean(r.CheckContent),
				FixText:        clean(r.FixText),
				FindingDetails: clean(r.FindingDetails),
				Comments:       clean(r.Comments),
				CCIs:           model.Dedup(r.CCIs),
				References:     model.Dedup(append(append([]string{}, r.LegacyIDs...), splitList(r.References)...)),
			})
		}
	}
	if len(host.Findings) == 0 {
		return nil, errNoRecords
	}
	if res.Scan.Title == "" {
		res.Scan.Title = strings.Join(model.Dedup(titles), "; ")
	}
	if host.Type == "" {
		host.Type = assetTypeFor(host.Role, host.OS, "")
	}
	res.Hosts = []*Host{host}
	return res, nil
}

// ---------- SCAP results: XCCDF and ARF ----------

type xccdfIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

type xccdfRule struct {
	ID          string       `xml:"id,attr"`
	Severity    string       `xml:"severity,attr"`
	Title       string       `xml:"title"`
	Description string       `xml:"description"`
	Fixtext     string       `xml:"fixtext"`
	Idents      []xccdfIdent `xml:"ident"`
	Check       struct {
		Content string `xml:"check-content"`
	} `xml:"check"`
}

type xccdfRuleResult struct {
	IDRef    string       `xml:"idref,attr"`
	Severity string       `xml:"severity,attr"`
	Time     string       `xml:"time,attr"`
	Result   string       `xml:"result"`
	Idents   []xccdfIdent `xml:"ident"`
	Message  string       `xml:"message"`
}

// parseXCCDF walks the document as a token stream so that a large ARF file, in
// which one XCCDF result set can be tens of megabytes, does not have to be
// materialised twice. Rule definitions are collected as they are met and joined
// to the results afterwards.
func parseXCCDF(data []byte, filename string) (*Result, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	rules := map[string]xccdfRule{}
	var (
		results   []xccdfRuleResult
		benchID   string
		benchName string
		version   string
		target    string
		addresses []string
		facts     = map[string]string{}
		startTime time.Time
	)
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
		case "Benchmark":
			for _, a := range se.Attr {
				if a.Name.Local == "id" && benchID == "" {
					benchID = a.Value
				}
			}
		case "Rule":
			var r xccdfRule
			if err := dec.DecodeElement(&r, &se); err == nil && r.ID != "" {
				rules[shortRuleID(r.ID)] = r
			}
		case "TestResult":
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "start-time", "end-time":
					if t, ok := parseTime(a.Value); ok && startTime.IsZero() {
						startTime = t
					}
				case "id":
					if benchID == "" {
						benchID = a.Value
					}
				}
			}
		case "rule-result":
			var rr xccdfRuleResult
			if err := dec.DecodeElement(&rr, &se); err == nil {
				results = append(results, rr)
			}
		case "target":
			var v string
			if err := dec.DecodeElement(&v, &se); err == nil && target == "" {
				target = strings.TrimSpace(v)
			}
		case "target-address":
			var v string
			if err := dec.DecodeElement(&v, &se); err == nil {
				addresses = append(addresses, strings.TrimSpace(v))
			}
		case "fact":
			name := ""
			for _, a := range se.Attr {
				if a.Name.Local == "name" {
					name = a.Value
				}
			}
			var v string
			if err := dec.DecodeElement(&v, &se); err == nil && name != "" {
				facts[name] = strings.TrimSpace(v)
			}
		case "title":
			if benchName == "" {
				var v string
				if err := dec.DecodeElement(&v, &se); err == nil {
					benchName = oneLine(v)
				}
			}
		case "version":
			if version == "" {
				var v string
				if err := dec.DecodeElement(&v, &se); err == nil {
					version = strings.TrimSpace(v)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no rule results were found; this looks like a benchmark definition rather than a scan result")
	}

	host := &Host{Name: target, IPs: model.Dedup(addresses)}
	for k, v := range facts {
		switch {
		case strings.HasSuffix(k, "fqdn"):
			host.FQDN = v
		case strings.HasSuffix(k, "mac"), strings.Contains(k, "mac_address"):
			host.MACs = append(host.MACs, v)
		case strings.Contains(k, "ipv4"), strings.Contains(k, "ip_address"):
			host.IPs = append(host.IPs, v)
		}
	}
	host.IPs = model.Dedup(host.IPs)
	host.MACs = model.Dedup(host.MACs)
	host.OS = benchName

	for _, rr := range results {
		short := shortRuleID(rr.IDRef)
		rule := rules[short]
		sev := firstNonEmpty(rr.Severity, rule.Severity)
		f := &model.Finding{
			RuleID:      short,
			GroupID:     short,
			Title:       oneLine(firstNonEmpty(rule.Title, short)),
			Severity:    model.Severity(sev).Normalise(),
			RawSeverity: sev,
			Status:      model.FindingStatus(rr.Result).Normalise(),
			Description: clean(rule.Description),
			CheckText:   clean(rule.Check.Content),
			FixText:     clean(rule.Fixtext),
			Comments:    clean(rr.Message),
		}
		for _, id := range append(append([]xccdfIdent{}, rule.Idents...), rr.Idents...) {
			v := strings.TrimSpace(id.Value)
			switch {
			case strings.HasPrefix(strings.ToUpper(v), "CCI-"):
				f.CCIs = append(f.CCIs, v)
			case strings.HasPrefix(strings.ToUpper(v), "CVE-"):
				f.CVEs = append(f.CVEs, v)
			case v != "":
				f.References = append(f.References, v)
			}
		}
		f.CCIs, f.CVEs, f.References = model.Dedup(f.CCIs), model.Dedup(f.CVEs), model.Dedup(f.References)
		host.Findings = append(host.Findings, f)
	}
	host.Type = assetTypeFor("", benchName, "")

	res := &Result{
		Scan: model.Scan{
			Format: string(FormatXCCDF), Kind: "benchmark", Filename: filename,
			Title: benchName, BenchmarkID: benchID, Version: version,
			Tool: "SCAP", ScanDate: startTime,
		},
		Hosts: []*Host{host},
	}
	return res, nil
}

// shortRuleID strips the xccdf_ prefix chain that SCAP content wraps rule
// identifiers in, leaving the SV- identifier a person would recognise.
func shortRuleID(id string) string {
	id = strings.TrimSpace(id)
	if i := strings.LastIndex(id, "_rule_"); i >= 0 {
		return id[i+len("_rule_"):]
	}
	if i := strings.LastIndex(id, "_"); i >= 0 && strings.HasPrefix(id, "xccdf_") {
		return id[i+1:]
	}
	return id
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
