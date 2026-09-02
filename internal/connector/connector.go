// Package connector turns a CSV export from somebody else's tool into
// observations. It is deliberately the only place that knows about file
// formats: everything downstream sees observations and nothing else.
package connector

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pkittelson/enclave/internal/model"
)

// ColumnMap says which column in a file holds which piece of information.
// Keys are identifier kinds and field names; values are column headers.
type ColumnMap struct {
	Identifiers map[string]string `json:"identifiers"`
	Fields      map[string]string `json:"fields"`
	// TimeLayout overrides the layouts tried when parsing dates. Most exports
	// need no override; some regional ones do.
	TimeLayout string `json:"time_layout,omitempty"`
}

// BoolFields are stored as booleans rather than text, because a control test
// asks whether a thing is true, not what a tool called it.
var BoolFields = map[string]bool{
	model.FieldDiskEncrypted: true,
}

// TimeFields are parsed into timestamps so staleness can be measured.
var TimeFields = map[string]bool{
	model.FieldLastVulnScan:      true,
	model.FieldLastBenchmarkScan: true,
}

// CSV reads one export from one tool.
type CSV struct {
	SourceID   string
	SourceKind string
	Map        ColumnMap
	// CollectedAt is when the export was taken. It defaults to the time of
	// import, which is right for a file downloaded the same day and near
	// enough for one that was not.
	CollectedAt time.Time
	// Batch groups the observations of a single import together.
	Batch string
}

// Parse reads the whole file and returns one observation per row that carried
// at least one usable identifier. Rows without one are counted, not merged:
// there is nothing to attach them to.
func (c *CSV) Parse(r io.Reader) ([]model.Observation, error) {
	rd := csv.NewReader(r)
	rd.FieldsPerRecord = -1
	rd.LazyQuotes = true
	rd.TrimLeadingSpace = true

	header, err := rd.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("the file is empty")
		}
		return nil, err
	}
	header = stripBOM(header)

	index := map[string]int{}
	for i, h := range header {
		index[normHeader(h)] = i
	}
	// column returns the value of a mapped column for the current row.
	column := func(row []string, name string) string {
		if name == "" {
			return ""
		}
		i, ok := index[normHeader(name)]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	collected := c.CollectedAt
	if collected.IsZero() {
		collected = time.Now()
	}
	ingested := time.Now()

	var out []model.Observation
	for line := 2; ; line++ {
		row, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", line, err)
		}

		obs := model.Observation{
			SourceID:    c.SourceID,
			SourceKind:  c.SourceKind,
			CollectedAt: collected,
			IngestedAt:  ingested,
			Batch:       c.Batch,
			Fields:      map[string]string{},
		}
		for kind, col := range c.Map.Identifiers {
			v := column(row, col)
			if v == "" {
				continue
			}
			id := model.Identifier{Kind: kind, Value: v}
			if !id.Valid() {
				continue
			}
			obs.Identifiers = append(obs.Identifiers, id)
		}
		if len(obs.Identifiers) == 0 {
			continue
		}

		for name, col := range c.Map.Fields {
			v := column(row, col)
			if v == "" {
				continue
			}
			switch {
			case BoolFields[name]:
				if obs.BoolFields == nil {
					obs.BoolFields = map[string]bool{}
				}
				b := truthy(v)
				obs.BoolFields[name] = b
				obs.Fields[name] = boolWord(b)
			case TimeFields[name]:
				t, ok := parseTime(v, c.Map.TimeLayout)
				if !ok {
					// Keep the text. A date nobody can parse is still a
					// disagreement worth showing rather than losing.
					obs.Fields[name] = v
					continue
				}
				if obs.TimeFields == nil {
					obs.TimeFields = map[string]time.Time{}
				}
				obs.TimeFields[name] = t
				obs.Fields[name] = t.Format("2006-01-02")
			default:
				obs.Fields[name] = v
			}
		}
		out = append(out, obs)
	}
	return out, nil
}

// normHeader reduces a column header to the form headers are compared in, so
// "Host Name", "host_name" and "HOSTNAME" are the same column.
func normHeader(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truthy reads the many ways a tool writes "yes".
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "t", "yes", "y", "1", "on", "enabled", "encrypted",
		"protected", "compliant", "pass", "passed", "ok", "healthy", "active":
		return true
	}
	return false
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// layouts are tried in order. Anything a spreadsheet is likely to produce is
// here; anything else needs an explicit layout on the mapping.
var layouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006-01-02",
	"2006/01/02",
	"01/02/2006 15:04:05",
	"01/02/2006 15:04",
	"01/02/2006",
	"1/2/2006",
	"02/01/2006",
	"02-Jan-2006",
	"Jan 2, 2006",
	"20060102",
}

// parseTime reads a date written in any of the usual ways.
func parseTime(s, layout string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if layout != "" {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// stripBOM removes the byte order mark Excel writes at the head of a UTF-8
// CSV, which would otherwise make the first column unmatchable.
func stripBOM(header []string) []string {
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\ufeff")
	}
	return header
}
