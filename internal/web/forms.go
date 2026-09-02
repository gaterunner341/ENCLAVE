package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// form wraps the request's parsed values with the small conversions every
// handler would otherwise repeat.
type form struct{ r *http.Request }

func newForm(r *http.Request) (*form, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return &form{r: r}, nil
}

func (f *form) str(name string) string { return strings.TrimSpace(f.r.FormValue(name)) }
func (f *form) bool(name string) bool  { v := f.str(name); return v == "on" || v == "true" || v == "1" }
func (f *form) list(name string) []string {
	return model.Dedup(f.r.Form[name])
}

// lines reads a textarea into a list, one entry per line, so that address
// ranges and evidence references can be edited as text.
func (f *form) lines(name string) []string {
	raw := f.r.FormValue(name)
	out := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if v := strings.TrimSpace(line); v != "" {
			out = append(out, v)
		}
	}
	return model.Dedup(out)
}

// csv reads a comma or space separated field.
func (f *form) csv(name string) []string {
	return model.Dedup(strings.FieldsFunc(f.r.FormValue(name), func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}))
}

func (f *form) int(name string, def int) int {
	if v, err := strconv.Atoi(f.str(name)); err == nil {
		return v
	}
	return def
}

// date reads a date input, returning nil when the field is blank.
func (f *form) date(name string) *time.Time {
	v := f.str(name)
	if v == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}
