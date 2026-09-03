package risk

import (
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/model"
)

// CVERollup is one CVE seen across the estate: what it affects, how badly, and
// how long it has been there.
//
// Findings are recorded per host, which is the right shape for remediation but
// the wrong one for the question a vulnerability manager actually asks, which
// is "where is CVE-2024-1086 and how bad is it for us". This turns one into the
// other.
type CVERollup struct {
	CVE      string
	Severity model.Severity
	CVSS     float64
	Title    string

	Findings []*model.Finding
	AssetIDs []string
	Enclaves []string

	Open       int
	Closed     int
	Accepted   int
	Oldest     int // days
	PastTarget int
	Score      float64
}

// Assets is the number of distinct hosts the CVE was found on.
func (c CVERollup) Assets() int { return len(c.AssetIDs) }

// Live reports whether anything about this CVE is still outstanding.
func (c CVERollup) Live() bool { return c.Open > 0 }

// CVEs rolls findings up by CVE, worst first.
//
// A finding naming several CVEs counts under each of them, because a host is
// exposed to all of them until the finding is fixed.
func CVEs(findings []*model.Finding, assets map[string]*model.Asset, now time.Time) []CVERollup {
	byCVE := map[string]*CVERollup{}
	for _, f := range findings {
		for _, raw := range f.CVEs {
			id := NormaliseCVE(raw)
			if id == "" {
				continue
			}
			c, ok := byCVE[id]
			if !ok {
				c = &CVERollup{CVE: id, Severity: model.SeverityInfo}
				byCVE[id] = c
			}
			c.Findings = append(c.Findings, f)
			if f.Severity.Rank() > c.Severity.Rank() {
				c.Severity = f.Severity.Normalise()
				c.Title = f.Title
			}
			if f.CVSS > c.CVSS {
				c.CVSS = f.CVSS
			}
			switch {
			case f.Live():
				c.Open++
				c.Score += FindingScore(f, assets[f.AssetID], now)
				if f.Disposition == model.DispositionRiskAccepted {
					c.Accepted++
				}
				if PastTarget(f, now) {
					c.PastTarget++
				}
				if d := f.AgeDays(now); d > c.Oldest {
					c.Oldest = d
				}
			default:
				c.Closed++
			}
			c.AssetIDs = appendUnique(c.AssetIDs, f.AssetID)
			c.Enclaves = appendUnique(c.Enclaves, f.EnclaveID)
		}
	}
	out := make([]CVERollup, 0, len(byCVE))
	for _, c := range byCVE {
		sort.Slice(c.Findings, func(i, j int) bool {
			a, b := c.Findings[i], c.Findings[j]
			if a.Live() != b.Live() {
				return a.Live()
			}
			return a.FirstSeen.Before(b.FirstSeen)
		})
		sort.Strings(c.AssetIDs)
		sort.Strings(c.Enclaves)
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Live() != b.Live() {
			return a.Live()
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.CVE > b.CVE
	})
	return out
}

// FindCVE returns the rollup for one identifier.
func FindCVE(findings []*model.Finding, assets map[string]*model.Asset, cve string, now time.Time) (CVERollup, bool) {
	want := NormaliseCVE(cve)
	for _, c := range CVEs(findings, assets, now) {
		if c.CVE == want {
			return c, true
		}
	}
	return CVERollup{}, false
}

// NormaliseCVE puts an identifier into the canonical upper-case form, and
// rejects anything that is not shaped like a CVE so that a stray reference in a
// spreadsheet column does not become an entry of its own.
func NormaliseCVE(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.TrimSuffix(strings.TrimPrefix(s, "("), ")")
	if !strings.HasPrefix(s, "CVE-") {
		return ""
	}
	rest := s[len("CVE-"):]
	year, num, ok := strings.Cut(rest, "-")
	if !ok || len(year) != 4 || len(num) < 4 {
		return ""
	}
	for _, part := range []string{year, num} {
		for _, r := range part {
			if r < '0' || r > '9' {
				return ""
			}
		}
	}
	return "CVE-" + year + "-" + num
}

func appendUnique(in []string, v string) []string {
	if v == "" {
		return in
	}
	for _, existing := range in {
		if existing == v {
			return in
		}
	}
	return append(in, v)
}

// CVESummary is the headline for the vulnerabilities page.
type CVESummary struct {
	Total      int
	Open       int
	Critical   int
	High       int
	PastTarget int
	Accepted   int
	Assets     int
}

// Summarise counts a set of rollups.
func Summarise(rollups []CVERollup) CVESummary {
	s := CVESummary{}
	assets := map[string]bool{}
	for _, c := range rollups {
		s.Total++
		if !c.Live() {
			continue
		}
		s.Open++
		switch c.Severity.Normalise() {
		case model.SeverityCritical:
			s.Critical++
		case model.SeverityHigh:
			s.High++
		}
		if c.PastTarget > 0 {
			s.PastTarget++
		}
		if c.Accepted > 0 {
			s.Accepted++
		}
		for _, id := range c.AssetIDs {
			assets[id] = true
		}
	}
	s.Assets = len(assets)
	return s
}
