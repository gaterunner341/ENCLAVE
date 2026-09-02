package catalog

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ParseText reads the line-oriented catalogue format used for the built-in
// catalogues and for hand-maintained organisation frameworks. It was chosen
// over JSON so that a control baseline stored in a repository reviews as a
// readable diff rather than as a wall of braces.
//
//	# a comment
//	@id       acme-secure-build
//	@name     ACME Secure Build Standard
//	@version  2026.1
//	@profile  core = Core Requirements
//	@family   HD  = Hardening
//	HD-1 | Approved base image | core,extended
//	HD-1(1) | Image is rebuilt monthly | extended
//
// The three fields of a control line are identifier, title and the profiles it
// belongs to. A trailing fourth field, if present, is the statement text.
func ParseText(r io.Reader) (*Catalog, error) {
	cat := &Catalog{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, "@") {
			if err := parseDirective(cat, raw); err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			continue
		}
		ctl, err := parseControlLine(cat, raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		cat.Controls = append(cat.Controls, ctl)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	cat.Index()
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	return cat, nil
}

func parseDirective(cat *Catalog, raw string) error {
	body := strings.TrimPrefix(raw, "@")
	key, rest, _ := strings.Cut(body, " ")
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(key) {
	case "id":
		cat.ID = rest
	case "name":
		cat.Name = rest
	case "version":
		cat.Version = rest
	case "publisher":
		cat.Publisher = rest
	case "description":
		cat.Description = rest
	case "source":
		cat.Source = rest
	case "profile":
		id, name, ok := strings.Cut(rest, "=")
		if !ok {
			return fmt.Errorf("@profile needs id = name")
		}
		p := Profile{ID: strings.TrimSpace(id), Name: strings.TrimSpace(name)}
		if n, d, ok := strings.Cut(p.Name, "|"); ok {
			p.Name, p.Description = strings.TrimSpace(n), strings.TrimSpace(d)
		}
		cat.Profiles = append(cat.Profiles, p)
	case "family":
		id, name, ok := strings.Cut(rest, "=")
		if !ok {
			return fmt.Errorf("@family needs id = name")
		}
		cat.Families = append(cat.Families, Family{ID: strings.TrimSpace(id), Name: strings.TrimSpace(name)})
	default:
		return fmt.Errorf("unknown directive @%s", key)
	}
	return nil
}

func parseControlLine(cat *Catalog, raw string) (Control, error) {
	parts := strings.Split(raw, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 2 || parts[0] == "" {
		return Control{}, fmt.Errorf("a control line needs at least `id | title`")
	}
	ctl := Control{ID: parts[0], Title: parts[1], Class: "control"}
	if len(parts) > 2 && parts[2] != "" {
		for _, p := range strings.Split(parts[2], ",") {
			if p = strings.TrimSpace(p); p != "" {
				ctl.Profiles = append(ctl.Profiles, p)
			}
		}
	}
	if len(parts) > 3 {
		ctl.Statement = parts[3]
	}
	if base := BaseID(ctl.ID); base != ctl.ID {
		ctl.Parent = base
		ctl.Class = "enhancement"
	}
	ctl.FamilyID = familyOf(cat, ctl.ID)
	return ctl, nil
}

// familyOf derives a family identifier from the control identifier: the part
// before the first dash or dot ("AC-2" -> AC, "5.1" -> 5). If that yields no
// declared family, the whole identifier's leading token is used, which keeps
// ad-hoc catalogues working without a family map.
func familyOf(cat *Catalog, id string) string {
	cut := strings.IndexAny(id, "-.")
	fam := id
	if cut > 0 {
		fam = id[:cut]
	}
	fam = strings.TrimSpace(fam)
	for _, f := range cat.Families {
		if strings.EqualFold(f.ID, fam) {
			return f.ID
		}
	}
	return fam
}

// ParseOSCAL reads an OSCAL catalog or profile-resolved catalog in JSON, which
// is how NIST publishes 800-53 and how a growing number of organisations
// publish their own. Only the parts ENCLAVE needs are decoded.
func ParseOSCAL(r io.Reader) (*Catalog, error) {
	var doc struct {
		Catalog struct {
			UUID     string `json:"uuid"`
			Metadata struct {
				Title   string `json:"title"`
				Version string `json:"version"`
			} `json:"metadata"`
			Groups   []oscalGroup   `json:"groups"`
			Controls []oscalControl `json:"controls"`
		} `json:"catalog"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("not an OSCAL catalog: %w", err)
	}
	c := doc.Catalog
	if c.Metadata.Title == "" && len(c.Groups) == 0 && len(c.Controls) == 0 {
		return nil, fmt.Errorf("no OSCAL catalog found in the document")
	}
	cat := &Catalog{
		Name:    c.Metadata.Title,
		Version: c.Metadata.Version,
		Source:  "OSCAL import",
	}
	cat.ID = slug(c.Metadata.Title)
	for _, g := range c.Groups {
		fid := strings.ToUpper(g.ID)
		cat.Families = append(cat.Families, Family{ID: fid, Name: g.Title})
		for _, ctl := range g.Controls {
			collectOSCAL(cat, fid, "", ctl)
		}
	}
	for _, ctl := range c.Controls {
		collectOSCAL(cat, familyOf(cat, ctl.ID), "", ctl)
	}
	cat.Index()
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	return cat, nil
}

type oscalGroup struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Controls []oscalControl `json:"controls"`
	Groups   []oscalGroup   `json:"groups"`
}

type oscalControl struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Class    string         `json:"class"`
	Controls []oscalControl `json:"controls"`
	Parts    []struct {
		Name  string `json:"name"`
		Prose string `json:"prose"`
	} `json:"parts"`
}

func collectOSCAL(cat *Catalog, familyID, parent string, oc oscalControl) {
	id := oscalID(oc.ID)
	ctl := Control{
		ID: id, Title: oc.Title, FamilyID: familyID,
		Parent: parent, Class: "control",
	}
	if parent != "" {
		ctl.Class = "enhancement"
	}
	for _, p := range oc.Parts {
		switch p.Name {
		case "statement":
			ctl.Statement = strings.TrimSpace(p.Prose)
		case "guidance":
			ctl.Discussion = strings.TrimSpace(p.Prose)
		}
	}
	cat.Controls = append(cat.Controls, ctl)
	for _, child := range oc.Controls {
		collectOSCAL(cat, familyID, id, child)
	}
}

// oscalID turns the OSCAL identifier style (ac-2.1) into the printed style
// (AC-2(1)) that scan results and assessors use.
func oscalID(id string) string {
	id = strings.TrimSpace(id)
	base, enh, ok := strings.Cut(id, ".")
	if !ok {
		return strings.ToUpper(id)
	}
	return strings.ToUpper(base) + "(" + enh + ")"
}

// ParseCSV reads a catalogue from a spreadsheet export. The header row names
// the columns; id and title are required, family, profiles, statement,
// discussion and parent are optional. This is the path for an organisation
// whose framework lives in Excel, which is most of them.
func ParseCSV(r io.Reader, id, name string) (*Catalog, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("the file needs a header row and at least one control")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	pick := func(row []string, names ...string) string {
		for _, n := range names {
			if i, ok := col[n]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
		}
		return ""
	}
	if _, ok := col["id"]; !ok {
		if _, ok := col["control id"]; !ok {
			return nil, fmt.Errorf("the header row needs an `id` or `control id` column")
		}
	}
	cat := &Catalog{ID: slug(id), Name: name, Source: "CSV import"}
	if cat.ID == "" {
		cat.ID = slug(name)
	}
	fams := map[string]bool{}
	for _, row := range rows[1:] {
		cid := pick(row, "id", "control id", "control")
		if cid == "" {
			continue
		}
		ctl := Control{
			ID:         cid,
			Title:      pick(row, "title", "name", "control name"),
			Statement:  pick(row, "statement", "description", "requirement"),
			Discussion: pick(row, "discussion", "guidance", "supplemental guidance"),
			Parent:     pick(row, "parent"),
			Class:      "control",
		}
		if ctl.Title == "" {
			ctl.Title = ctl.ID
		}
		famName := pick(row, "family", "family name", "group", "domain")
		ctl.FamilyID = pick(row, "family id", "family_id")
		if ctl.FamilyID == "" {
			ctl.FamilyID = familyOf(cat, ctl.ID)
		}
		if famName != "" && !fams[ctl.FamilyID] {
			cat.Families = append(cat.Families, Family{ID: ctl.FamilyID, Name: famName})
			fams[ctl.FamilyID] = true
		}
		if p := pick(row, "profiles", "baselines", "baseline", "implementation group"); p != "" {
			for _, v := range strings.FieldsFunc(p, func(r rune) bool { return r == ',' || r == ';' || r == '/' }) {
				if v = strings.TrimSpace(v); v != "" {
					ctl.Profiles = append(ctl.Profiles, v)
				}
			}
		}
		if ctl.Parent == "" {
			if base := BaseID(ctl.ID); base != ctl.ID {
				ctl.Parent, ctl.Class = base, "enhancement"
			}
		}
		cat.Controls = append(cat.Controls, ctl)
	}
	seenProfile := map[string]bool{}
	for _, ctl := range cat.Controls {
		for _, p := range ctl.Profiles {
			if !seenProfile[p] {
				seenProfile[p] = true
				cat.Profiles = append(cat.Profiles, Profile{ID: p, Name: p})
			}
		}
	}
	cat.Index()
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	return cat, nil
}

func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// Slug is the exported identifier normaliser, used when a person names a
// catalogue on the import form.
func Slug(s string) string { return slug(s) }
