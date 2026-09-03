// Package risk turns inventory, findings and assessments into the numbers the
// tool exists to produce: how exposed each enclave is, and where its control
// baseline is not being met.
//
// Two ideas run through it. First, a finding's weight depends on more than its
// severity: an unpatched critical on a mission-critical host in a high-impact
// enclave is not the same risk as the same plugin firing on a lab workstation.
// Second, a control is only satisfied when both halves agree: somebody has
// claimed it is implemented, and no scan result contradicts them.
package risk

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/gaterunner341/enclave/internal/catalog"
	"github.com/gaterunner341/enclave/internal/model"
)

// SeverityWeight is the base contribution of one open finding. The gaps
// between the bands are deliberately wide: ten low findings should not read as
// worse than one critical.
var SeverityWeight = map[model.Severity]float64{
	model.SeverityCritical: 40,
	model.SeverityHigh:     20,
	model.SeverityMedium:   6,
	model.SeverityLow:      1.5,
	model.SeverityInfo:     0,
}

// RemediationTarget is how long a finding of each severity may stay open
// before it starts ageing the score. The defaults follow the shape most
// organisations use; they are configurable per deployment.
var RemediationTarget = map[model.Severity]int{
	model.SeverityCritical: 15,
	model.SeverityHigh:     30,
	model.SeverityMedium:   90,
	model.SeverityLow:      180,
	model.SeverityInfo:     0,
}

// FindingScore is the weight one finding contributes.
//
//	severity band  ×  asset criticality  ×  disposition residual  ×  age factor
//
// A finding that is closed, remediated or a false positive scores zero. One
// that is past its remediation target grows, to a ceiling of double weight, so
// that an ageing backlog is visible without letting it dominate the number.
func FindingScore(f *model.Finding, a *model.Asset, now time.Time) float64 {
	if !f.Live() {
		return 0
	}
	w := SeverityWeight[f.Severity.Normalise()]
	if w == 0 {
		return 0
	}
	if a != nil {
		w *= a.Criticality.Weight()
	}
	w *= f.Disposition.Residual()
	return w * ageFactor(f, now)
}

func ageFactor(f *model.Finding, now time.Time) float64 {
	target := RemediationTarget[f.Severity.Normalise()]
	if target <= 0 {
		return 1
	}
	over := f.AgeDays(now) - target
	if over <= 0 {
		return 1
	}
	// One extra target period overdue adds half again; growth stops at double.
	return math.Min(2, 1+float64(over)/float64(2*target))
}

// AssetRisk is the rolled-up risk position of one asset.
type AssetRisk struct {
	Asset    *model.Asset
	Score    float64
	Open     int
	Accepted int
	BySev    map[model.Severity]int
	Overdue  int
	Oldest   int // days
	LastScan *time.Time
}

// EnclaveRisk is the rolled-up risk position of one enclave.
type EnclaveRisk struct {
	Enclave *model.Enclave
	Score   float64
	// Index is Score normalised to 0-100 against the enclave's asset count, so
	// that a small enclave and a large one can be compared.
	Index    float64
	Band     string
	Assets   int
	Assessed int
	// Open is work outstanding. Accepted is live but deliberately accepted, and
	// is counted apart from it rather than inside it.
	Open        int
	Accepted    int
	BySev       map[model.Severity]int
	Overdue     int
	Unmapped    int
	StaleAssets int
	LastScan    *time.Time
	TopAssets   []AssetRisk
}

// Bands names an index value.
func Band(index float64) string {
	switch {
	case index >= 75:
		return "Critical"
	case index >= 50:
		return "High"
	case index >= 25:
		return "Moderate"
	case index > 0:
		return "Low"
	}
	return "Clean"
}

// StaleAfter is how long an asset may go unseen before it is reported as
// stale. An inventory nobody is scanning is a control gap in itself.
const StaleAfter = 45 * 24 * time.Hour

// ScoreEnclave rolls findings up to an enclave. impactMultiplier reflects the
// enclave's categorisation: the same weakness matters more on a high-impact
// system than on a low one.
func ScoreEnclave(e *model.Enclave, assets []*model.Asset, findings []*model.Finding, now time.Time) EnclaveRisk {
	byAsset := map[string][]*model.Finding{}
	for _, f := range findings {
		byAsset[f.AssetID] = append(byAsset[f.AssetID], f)
	}
	out := EnclaveRisk{
		Enclave: e, Assets: len(assets),
		BySev: map[model.Severity]int{},
	}
	assetRisks := make([]AssetRisk, 0, len(assets))
	for _, a := range assets {
		ar := AssetRisk{Asset: a, BySev: map[model.Severity]int{}}
		for _, f := range byAsset[a.ID] {
			if !f.Live() {
				continue
			}
			ar.Score += FindingScore(f, a, now)
			if f.Accepted() {
				ar.Accepted++
			} else {
				ar.Open++
			}
			ar.BySev[f.Severity.Normalise()]++
			if PastTarget(f, now) {
				ar.Overdue++
			}
			if d := f.AgeDays(now); d > ar.Oldest {
				ar.Oldest = d
			}
		}
		ar.LastScan = a.LastSeen
		if a.Stale(now, StaleAfter) {
			out.StaleAssets++
		}
		if ar.Open+ar.Accepted > 0 {
			out.Assessed++
		}
		out.Score += ar.Score
		out.Open += ar.Open
		out.Accepted += ar.Accepted
		out.Overdue += ar.Overdue
		for sev, n := range ar.BySev {
			out.BySev[sev] += n
		}
		if ar.LastScan != nil && (out.LastScan == nil || ar.LastScan.After(*out.LastScan)) {
			out.LastScan = ar.LastScan
		}
		assetRisks = append(assetRisks, ar)
	}
	for _, f := range findings {
		if f.Live() && len(f.ControlRefs) == 0 {
			out.Unmapped++
		}
	}
	out.Score *= impactMultiplier(e)
	out.Index = normalise(out.Score, len(assets))
	out.Band = Band(out.Index)

	sort.Slice(assetRisks, func(i, j int) bool { return assetRisks[i].Score > assetRisks[j].Score })
	if len(assetRisks) > 10 {
		assetRisks = assetRisks[:10]
	}
	out.TopAssets = assetRisks
	return out
}

// PastTarget reports whether a finding is somebody's outstanding work and has
// passed either its own due date or the default remediation target for its
// severity. A closed finding is never past target, however old it is, and
// neither is an accepted risk: accepting it is the decision about when it gets
// fixed, so there is no deadline left to miss.
func PastTarget(f *model.Finding, now time.Time) bool {
	if !f.NeedsWork() {
		return false
	}
	if f.DueDate != nil {
		return now.After(*f.DueDate)
	}
	t := RemediationTarget[f.Severity.Normalise()]
	return t > 0 && f.AgeDays(now) > t
}

// impactMultiplier scales an enclave's raw score by its categorisation.
func impactMultiplier(e *model.Enclave) float64 {
	if e == nil {
		return 1
	}
	switch e.Categorization() {
	case model.ImpactHigh:
		return 1.5
	case model.ImpactModerate:
		return 1.2
	case model.ImpactLow:
		return 1.0
	}
	return 1.0
}

// normalise maps a raw score onto 0-100. The curve is logarithmic because raw
// scores span orders of magnitude across estates, and a linear index would put
// every enclave with a real backlog at 100.
func normalise(score float64, assets int) float64 {
	if score <= 0 {
		return 0
	}
	per := score
	if assets > 0 {
		per = score / float64(assets)
	}
	// 20 points per asset, the weight of a single unaged high finding on a
	// moderate-criticality host, lands at roughly 50.
	idx := 50 * math.Log1p(per) / math.Log1p(20)
	return math.Min(100, math.Round(idx*10)/10)
}

// Matrix is the likelihood-by-impact grid the risk register renders.
type Matrix [5][5]int

// BuildMatrix counts risk entries into the grid, with likelihood on one axis
// and impact on the other.
func BuildMatrix(entries []*model.RiskEntry) Matrix {
	var m Matrix
	for _, r := range entries {
		if !r.Open() {
			continue
		}
		l := clamp(r.Likelihood, 1, 5) - 1
		i := clamp(r.Impact, 1, 5) - 1
		m[l][i]++
	}
	return m
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// SeverityCounts tallies live findings by severity.
func SeverityCounts(findings []*model.Finding) map[model.Severity]int {
	out := map[model.Severity]int{}
	for _, f := range findings {
		if f.Live() {
			out[f.Severity.Normalise()]++
		}
	}
	return out
}

// AgeBuckets groups live findings by how long they have been open, which is
// the view that shows whether a remediation programme is keeping up.
type AgeBucket struct {
	Label string
	Count int
}

// AgeProfile buckets findings by age.
func AgeProfile(findings []*model.Finding, now time.Time) []AgeBucket {
	buckets := []AgeBucket{
		{Label: "Under 30 days"}, {Label: "30 to 90 days"},
		{Label: "90 to 180 days"}, {Label: "Over 180 days"},
	}
	for _, f := range findings {
		if !f.Live() {
			continue
		}
		switch d := f.AgeDays(now); {
		case d < 30:
			buckets[0].Count++
		case d < 90:
			buckets[1].Count++
		case d < 180:
			buckets[2].Count++
		default:
			buckets[3].Count++
		}
	}
	return buckets
}

// OverdueFindings returns live findings past the remediation target for their
// severity, worst and oldest first.
func OverdueFindings(findings []*model.Finding, now time.Time) []*model.Finding {
	out := []*model.Finding{}
	for _, f := range findings {
		if PastTarget(f, now) {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}

// Due is the date a finding of this severity, first seen then, should be
// closed by.
func Due(f *model.Finding) *time.Time {
	if f.DueDate != nil {
		return f.DueDate
	}
	t := RemediationTarget[f.Severity.Normalise()]
	if t <= 0 {
		return nil
	}
	d := f.FirstSeen.AddDate(0, 0, t)
	return &d
}

// FamilyOf is a small helper the templates use to group findings without
// reaching into the catalogue.
func FamilyOf(cat *catalog.Catalog, controlID string) string {
	if cat == nil {
		return ""
	}
	if c, ok := cat.Control(controlID); ok {
		return c.FamilyID
	}
	return strings.SplitN(controlID, "-", 2)[0]
}

// MatrixCell is one square of the likelihood-by-impact grid, precomputed so
// that the template does no arithmetic.
type MatrixCell struct {
	Likelihood int
	Impact     int
	Count      int
	Score      int
	// Tier is 1 to 4, used to shade the square by how serious that square is.
	Tier int
}

// MatrixRows lays the risk entries out as a grid, highest likelihood first so
// that it reads the way a risk matrix is drawn.
func MatrixRows(entries []*model.RiskEntry) [][]MatrixCell {
	m := BuildMatrix(entries)
	rows := make([][]MatrixCell, 0, 5)
	for l := 5; l >= 1; l-- {
		row := make([]MatrixCell, 0, 5)
		for i := 1; i <= 5; i++ {
			score := l * i
			row = append(row, MatrixCell{
				Likelihood: l, Impact: i, Count: m[l-1][i-1],
				Score: score, Tier: tierFor(score),
			})
		}
		rows = append(rows, row)
	}
	return rows
}

func tierFor(score int) int {
	switch {
	case score >= 20:
		return 4
	case score >= 12:
		return 3
	case score >= 6:
		return 2
	}
	return 1
}
