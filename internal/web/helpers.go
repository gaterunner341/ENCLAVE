package web

import (
	"fmt"
	"html/template"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/model"
	"github.com/gaterunner341/enclave/internal/risk"
)

func urlEscape(s string) string { return url.QueryEscape(s) }

// funcs are the template helpers. They exist so that the templates can stay
// declarative: no arithmetic, no string building, no branching on magic values.
func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"severityClass": func(sev model.Severity) string { return "sev-" + string(sev.Normalise()) },
		"stateClass":    func(st risk.GapState) string { return "gap-" + string(st) },
		"bandClass": func(band string) string {
			return "band-" + strings.ToLower(strings.ReplaceAll(band, " ", "-"))
		},
		"dispositionClass": func(d model.Disposition) string { return "disp-" + string(d) },

		"pct": func(v float64) string {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return "0%"
			}
			return strconv.FormatFloat(v, 'f', 1, 64) + "%"
		},
		"pctOf": func(n, total int) string {
			if total == 0 {
				return "0%"
			}
			return strconv.FormatFloat(float64(n)/float64(total)*100, 'f', 0, 64) + "%"
		},
		"ratio": func(n, total int) float64 {
			if total == 0 {
				return 0
			}
			return float64(n) / float64(total) * 100
		},
		"num": func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) },
		// kb rounds a byte count up, so a small file never reads as 0 KB.
		"kb": func(bytes int64) int {
			if bytes <= 0 {
				return 0
			}
			return int((bytes + 1023) / 1024)
		},
		"comma": func(n int) string {
			s := strconv.Itoa(n)
			if n < 0 {
				return "-" + commas(s[1:])
			}
			return commas(s)
		},

		"date": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Local().Format("2 Jan 2006")
		},
		"datetime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Local().Format("2 Jan 2006 15:04")
		},
		"dateP": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "—"
			}
			return t.Local().Format("2 Jan 2006")
		},
		"dateInput": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return ""
			}
			return t.Format("2006-01-02")
		},
		"since": humanSince,
		"days": func(t time.Time) int {
			if t.IsZero() {
				return 0
			}
			return int(time.Since(t).Hours() / 24)
		},

		"truncate": func(n int, s string) string {
			s = strings.TrimSpace(s)
			if len(s) <= n {
				return s
			}
			cut := s[:n]
			if i := strings.LastIndexAny(cut, " \n\t"); i > n/2 {
				cut = cut[:i]
			}
			return cut + "…"
		},
		"join":  func(sep string, in []string) string { return strings.Join(in, sep) },
		"lower": strings.ToLower,
		"title": func(s string) string {
			if s == "" {
				return ""
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
		"humanise": func(s string) string {
			s = strings.ReplaceAll(s, "_", " ")
			if s == "" {
				return ""
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
		"nl2br": func(s string) template.HTML {
			esc := template.HTMLEscapeString(s)
			return template.HTML(strings.ReplaceAll(esc, "\n", "<br>"))
		},

		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b float64) float64 { return a * b },
		"divf": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i
			}
			return out
		},
		"dict": dict,
		"query": func(base string, kv ...string) string {
			q := url.Values{}
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i+1] != "" {
					q.Set(kv[i], kv[i+1])
				}
			}
			if len(q) == 0 {
				return base
			}
			return base + "?" + q.Encode()
		},

		"severities": func() []model.Severity { return model.Severities },
		"gapStates":  func() []risk.GapState { return risk.States },
		// countState reads one state out of an analysis by name, which a
		// template cannot do itself because the map is typed.
		"countState": func(counts map[risk.GapState]int, name string) int {
			return counts[risk.GapState(name)]
		},
		"implStatuses":  func() []model.ImplStatus { return model.ImplStatuses },
		"dispositions":  func() []model.Disposition { return model.Dispositions },
		"assetTypes":    func() []model.AssetType { return model.AssetTypes },
		"criticalities": func() []model.Criticality { return model.Criticalities },
		"impacts":       func() []model.Impact { return model.Impacts },
		"environments":  func() []string { return model.Environments },
		"enclaveStates": func() []string { return model.EnclaveStatus },
		"authStatuses":  func() []string { return model.AuthStatuses },
		"assetStates":   func() []string { return model.AssetStatuses },
		"riskStatuses":  func() []string { return model.RiskStatuses },
		"originations":  func() []string { return model.Originations },
		"riskSources":   func() []string { return model.RiskSources },
		"catalogs":      s.Catalogs.All,

		"donut":     donut,
		"barRow":    barRow,
		"sparkPath": sparkPath,

		"controlOf": func(cat *catalog.Catalog, id string) catalog.Control {
			c, _ := cat.Control(id)
			return c
		},
		"remediationTarget": func(sev model.Severity) int { return risk.RemediationTarget[sev.Normalise()] },
		"due":               risk.Due,
	}
}

func commas(s string) string {
	if len(s) <= 3 {
		return s
	}
	return commas(s[:len(s)-3]) + "," + s[len(s)-3:]
}

func humanSince(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hr ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
	return fmt.Sprintf("%.1f years ago", d.Hours()/24/365)
}

// dict builds a map inside a template, which is how a partial is given more
// than one value.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, fmt.Errorf("dict needs an even number of arguments")
	}
	out := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		out[k] = kv[i+1]
	}
	return out, nil
}

// Segment is one slice of a donut chart.
type Segment struct {
	Label  string
	Count  int
	Class  string
	Offset float64
	Length float64
	Pct    float64
}

// Donut is a ring chart described in numbers, drawn by the template as SVG
// stroke offsets. Keeping the geometry here keeps the markup readable.
type Donut struct {
	Segments []Segment
	Total    int
	Circ     float64
}

const donutRadius = 54.0

func donut(counts map[string]int, order []string, classes map[string]string) Donut {
	circ := 2 * math.Pi * donutRadius
	d := Donut{Circ: circ}
	for _, k := range order {
		d.Total += counts[k]
	}
	pos := 0.0
	for _, k := range order {
		n := counts[k]
		if n == 0 {
			continue
		}
		frac := float64(n) / float64(d.Total)
		seg := Segment{
			Label: k, Count: n, Class: classes[k],
			Length: frac * circ, Offset: -pos,
			Pct: frac * 100,
		}
		pos += seg.Length
		d.Segments = append(d.Segments, seg)
	}
	return d
}

// Bar is one row of a horizontal bar chart.
type Bar struct {
	Label string
	Count int
	Pct   float64
	Class string
}

func barRow(label string, count, max int, class string) Bar {
	pct := 0.0
	if max > 0 {
		pct = float64(count) / float64(max) * 100
	}
	return Bar{Label: label, Count: count, Pct: pct, Class: class}
}

// sparkPath renders a series as an SVG polyline over a 100x30 box.
func sparkPath(values []int) string {
	if len(values) < 2 {
		return ""
	}
	max := 1
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for i, v := range values {
		x := float64(i) / float64(len(values)-1) * 100
		y := 30 - float64(v)/float64(max)*28
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}

// severityClasses maps the severity vocabulary onto stylesheet classes for the
// donut helper.
var severityClasses = map[string]string{
	"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
	"low": "sev-low", "info": "sev-info",
}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// countsBySeverity converts the typed map the risk package produces into the
// string-keyed one the donut helper takes.
func countsBySeverity(in map[model.Severity]int) map[string]int {
	out := map[string]int{}
	for k, v := range in {
		out[string(k)] = v
	}
	return out
}

var gapStateClasses = func() map[string]string {
	out := map[string]string{}
	for _, st := range risk.States {
		out[string(st)] = "gap-" + string(st)
	}
	return out
}()

func gapStateOrder() []string {
	out := make([]string, 0, len(risk.States))
	for _, st := range risk.States {
		out = append(out, string(st))
	}
	return out
}

func countsByState(in map[risk.GapState]int) map[string]int {
	out := map[string]int{}
	for k, v := range in {
		out[string(k)] = v
	}
	return out
}

// sortedKeys is used wherever a map has to render in a stable order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
