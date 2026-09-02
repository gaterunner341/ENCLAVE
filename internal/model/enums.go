package model

import "strings"

// Impact is the FIPS 199 style categorisation used for confidentiality,
// integrity and availability. It is deliberately generic: organisations that
// do not use FIPS 199 can read Low/Moderate/High as any three-tier scale.
type Impact string

const (
	ImpactNone     Impact = "none"
	ImpactLow      Impact = "low"
	ImpactModerate Impact = "moderate"
	ImpactHigh     Impact = "high"
)

var impactRank = map[Impact]int{ImpactNone: 0, ImpactLow: 1, ImpactModerate: 2, ImpactHigh: 3}

// Rank orders impacts so a high-water mark can be taken across C, I and A.
func (i Impact) Rank() int { return impactRank[i.Normalise()] }

// Normalise maps loose spellings ("Med", "MODERATE", "3") onto a known value.
func (i Impact) Normalise() Impact {
	switch strings.ToLower(strings.TrimSpace(string(i))) {
	case "high", "h", "3":
		return ImpactHigh
	case "moderate", "medium", "med", "m", "2":
		return ImpactModerate
	case "low", "l", "1":
		return ImpactLow
	default:
		return ImpactNone
	}
}

func (i Impact) Label() string {
	switch i.Normalise() {
	case ImpactHigh:
		return "High"
	case ImpactModerate:
		return "Moderate"
	case ImpactLow:
		return "Low"
	}
	return "Not categorised"
}

// Impacts is the selectable set, ordered low to high.
var Impacts = []Impact{ImpactNone, ImpactLow, ImpactModerate, ImpactHigh}

// HighWater returns the greatest of the supplied impacts, which is how an
// overall system categorisation is derived from its C, I and A ratings.
func HighWater(vals ...Impact) Impact {
	out := ImpactNone
	for _, v := range vals {
		if v.Rank() > out.Rank() {
			out = v.Normalise()
		}
	}
	return out
}

// Severity is the normalised severity of a finding. Scanner-specific scales
// (DISA CAT I/II/III, Nessus 0-4, CVSS bands) are mapped onto it at ingest so
// that risk can be compared across tools.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Severities is ordered most to least severe.
var Severities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

var severityRank = map[Severity]int{
	SeverityCritical: 5, SeverityHigh: 4, SeverityMedium: 3, SeverityLow: 2, SeverityInfo: 1,
}

func (s Severity) Rank() int { return severityRank[s.Normalise()] }

func (s Severity) Label() string {
	switch s.Normalise() {
	case SeverityCritical:
		return "Critical"
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	}
	return "Informational"
}

// Normalise accepts the severity vocabularies of the scanners ENCLAVE reads.
func (s Severity) Normalise() Severity {
	v := strings.ToLower(strings.TrimSpace(string(s)))
	v = strings.TrimPrefix(v, "cat ")
	switch v {
	case "critical", "crit", "4", "iv", "very high":
		return SeverityCritical
	case "high", "3", "i", "cat i", "cati":
		return SeverityHigh
	case "medium", "moderate", "med", "2", "ii", "cat ii", "catii":
		return SeverityMedium
	case "low", "1", "iii", "cat iii", "catiii":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// SeverityFromCategory maps a DISA severity category onto the common scale.
// CAT I is treated as High rather than Critical so that a CVSS 9.8 remote code
// execution and a CAT I configuration item are not scored identically.
func SeverityFromCategory(cat string) Severity {
	switch strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(cat)), "CAT"))) {
	case "I":
		return SeverityHigh
	case "II":
		return SeverityMedium
	case "III":
		return SeverityLow
	}
	return Severity(cat).Normalise()
}

// SeverityFromCVSS bands a CVSS base score using the FIRST qualitative scale.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityInfo
}

// FindingStatus is the assessment result recorded by the scanner or reviewer.
type FindingStatus string

const (
	StatusOpen          FindingStatus = "open"
	StatusNotAFinding   FindingStatus = "not_a_finding"
	StatusNotApplicable FindingStatus = "not_applicable"
	StatusNotReviewed   FindingStatus = "not_reviewed"
)

var FindingStatuses = []FindingStatus{StatusOpen, StatusNotAFinding, StatusNotApplicable, StatusNotReviewed}

func (f FindingStatus) Label() string {
	switch f.Normalise() {
	case StatusOpen:
		return "Open"
	case StatusNotAFinding:
		return "Not a finding"
	case StatusNotApplicable:
		return "Not applicable"
	}
	return "Not reviewed"
}

// Normalise accepts CKL, XCCDF and CSV spellings of a result.
func (f FindingStatus) Normalise() FindingStatus {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(f)), " ", "_")) {
	case "open", "fail", "failed", "noncompliant", "non-compliant", "error":
		return StatusOpen
	case "notafinding", "not_a_finding", "pass", "passed", "compliant", "fixed":
		return StatusNotAFinding
	case "not_applicable", "notapplicable", "na", "n/a":
		return StatusNotApplicable
	default:
		return StatusNotReviewed
	}
}

// Counts returns true when a finding contributes to risk.
func (f FindingStatus) Counts() bool { return f.Normalise() == StatusOpen }

// Disposition is the organisation's decision about an open finding. It is kept
// separate from FindingStatus so that a re-import of a scan never overwrites a
// human decision.
type Disposition string

const (
	DispositionOpen          Disposition = "open"
	DispositionInProgress    Disposition = "in_progress"
	DispositionRemediated    Disposition = "remediated"
	DispositionMitigated     Disposition = "mitigated"
	DispositionRiskAccepted  Disposition = "risk_accepted"
	DispositionFalsePositive Disposition = "false_positive"
)

var Dispositions = []Disposition{
	DispositionOpen, DispositionInProgress, DispositionRemediated,
	DispositionMitigated, DispositionRiskAccepted, DispositionFalsePositive,
}

func (d Disposition) Label() string {
	switch d {
	case DispositionInProgress:
		return "In progress"
	case DispositionRemediated:
		return "Remediated"
	case DispositionMitigated:
		return "Mitigated"
	case DispositionRiskAccepted:
		return "Risk accepted"
	case DispositionFalsePositive:
		return "False positive"
	}
	return "Open"
}

// Residual reports whether the disposition leaves risk on the books. A
// mitigated finding still carries reduced risk; an accepted one is tracked but
// deliberately not counted as a gap.
func (d Disposition) Residual() float64 {
	switch d {
	case DispositionRemediated, DispositionFalsePositive:
		return 0
	case DispositionMitigated:
		return 0.3
	case DispositionRiskAccepted:
		return 0.15
	case DispositionInProgress:
		return 0.75
	}
	return 1
}

// ImplStatus is the implementation state of a control within an enclave.
type ImplStatus string

const (
	ImplNotAssessed    ImplStatus = "not_assessed"
	ImplImplemented    ImplStatus = "implemented"
	ImplPartial        ImplStatus = "partial"
	ImplPlanned        ImplStatus = "planned"
	ImplNotImplemented ImplStatus = "not_implemented"
	ImplNotApplicable  ImplStatus = "not_applicable"
	ImplInherited      ImplStatus = "inherited"
)

var ImplStatuses = []ImplStatus{
	ImplNotAssessed, ImplImplemented, ImplPartial, ImplPlanned,
	ImplNotImplemented, ImplNotApplicable, ImplInherited,
}

func (s ImplStatus) Label() string {
	switch s {
	case ImplImplemented:
		return "Implemented"
	case ImplPartial:
		return "Partially implemented"
	case ImplPlanned:
		return "Planned"
	case ImplNotImplemented:
		return "Not implemented"
	case ImplNotApplicable:
		return "Not applicable"
	case ImplInherited:
		return "Inherited"
	}
	return "Not assessed"
}

// Satisfied reports whether the claimed status would, on its own, close a gap.
func (s ImplStatus) Satisfied() bool {
	return s == ImplImplemented || s == ImplInherited || s == ImplNotApplicable
}

// AssetType distinguishes hosts from network devices so that controls are only
// measured against assets that can meet them.
type AssetType string

const (
	AssetServer      AssetType = "server"
	AssetWorkstation AssetType = "workstation"
	AssetNetwork     AssetType = "network_device"
	AssetSecurity    AssetType = "security_appliance"
	AssetVirtual     AssetType = "virtual_machine"
	AssetContainer   AssetType = "container"
	AssetStorage     AssetType = "storage"
	AssetPrinter     AssetType = "peripheral"
	AssetMobile      AssetType = "mobile"
	AssetCloud       AssetType = "cloud_service"
	AssetOther       AssetType = "other"
)

var AssetTypes = []AssetType{
	AssetServer, AssetWorkstation, AssetVirtual, AssetContainer, AssetNetwork,
	AssetSecurity, AssetStorage, AssetPrinter, AssetMobile, AssetCloud, AssetOther,
}

func (a AssetType) Label() string {
	switch a {
	case AssetServer:
		return "Server"
	case AssetWorkstation:
		return "Workstation"
	case AssetNetwork:
		return "Network device"
	case AssetSecurity:
		return "Security appliance"
	case AssetVirtual:
		return "Virtual machine"
	case AssetContainer:
		return "Container"
	case AssetStorage:
		return "Storage"
	case AssetPrinter:
		return "Peripheral"
	case AssetMobile:
		return "Mobile device"
	case AssetCloud:
		return "Cloud service"
	}
	return "Other"
}

// IsNetworkGear reports whether the asset is infrastructure rather than a host.
func (a AssetType) IsNetworkGear() bool {
	return a == AssetNetwork || a == AssetSecurity || a == AssetStorage
}

// Criticality is the operational importance of a single asset, used to weight
// its findings when rolling risk up to the enclave.
type Criticality string

const (
	CritLow      Criticality = "low"
	CritModerate Criticality = "moderate"
	CritHigh     Criticality = "high"
	CritMission  Criticality = "mission_critical"
)

var Criticalities = []Criticality{CritLow, CritModerate, CritHigh, CritMission}

func (c Criticality) Label() string {
	switch c {
	case CritMission:
		return "Mission critical"
	case CritHigh:
		return "High"
	case CritLow:
		return "Low"
	}
	return "Moderate"
}

// Weight multiplies an asset's finding scores.
func (c Criticality) Weight() float64 {
	switch c {
	case CritMission:
		return 1.6
	case CritHigh:
		return 1.3
	case CritLow:
		return 0.7
	}
	return 1.0
}
