package opes

import (
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// difficulty (E) — how hard is the exploit in the abstract? Higher = harder.
//
// Inputs: reconciled CVSS AC, attacker capability, # of blocker
// preconditions, exploit complexity, presence of nuclei template, PoC
// availability.
//
// E contributes inversely (10-E) to the OPES sum, so harder exploits
// reduce the score.
func difficulty(in Input) float64 {
	if in.Intrinsic == nil {
		return 5.0
	}
	base := 5.0

	_, ac := parseAVAC(in.Intrinsic.CVSSReconciliation.CorrectVector)
	switch ac {
	case "L":
		base = 4.0
	case "H":
		base = 7.0
	}

	switch in.Intrinsic.AttackerCapability {
	case schema.AttackerUnauthenticatedNetwork:
		base -= 2.0
	case schema.AttackerAuthenticatedLowPriv:
		base -= 0.5
	case schema.AttackerAuthenticatedHighPriv:
		base += 1.0
	case schema.AttackerLocalUser:
		base += 1.5
	case schema.AttackerCodeExecution:
		base += 3.0
	case schema.AttackerPhysical:
		base += 4.0
	}

	blockers := 0
	for _, p := range in.Intrinsic.Preconditions {
		if p.Severity == schema.PreconditionBlocker {
			blockers++
		}
	}
	base += float64(blockers) * 0.5

	if hasNucleiTemplate(in) {
		base -= 1.5
	}
	if hasWeaponizedPOC(in) {
		base -= 1.0
	}

	switch in.Intrinsic.ExploitComplexity {
	case schema.ComplexityLow:
		base -= 0.5
	case schema.ComplexityHigh:
		base += 1.0
	}

	return clamp(base, 0, 10)
}

// reachability (R) — can the relevant attacker class even reach this asset?
//
// Inputs: reconciled CVSS AV, asset exposure, auth required, WAF.
//
// R == 0 short-circuits to "not exploitable" via the override in combine.go.
func reachability(in Input, _ Config) float64 {
	if in.Asset == nil {
		return 5.0
	}
	if in.Asset.Exposure == schema.ExposureIsolated {
		return 0.0
	}

	av, _ := parseAVAC(intrinsicVector(in))
	base := map[string]float64{
		"N": 10.0,
		"A": 7.0,
		"L": 3.0,
		"P": 1.0,
		"":  5.0,
	}[av]

	if in.Asset.Exposure == schema.ExposureInternal && av == "N" {
		base = 6.0
	}

	// Auth penalty applies only when the attacker is supposed to come in
	// over the network unauthenticated. For local/code-execution exploits,
	// the asset's HTTP auth doesn't gate anything.
	if in.Asset.Signals.Auth != nil &&
		in.Asset.Signals.Auth.Required != nil && *in.Asset.Signals.Auth.Required &&
		in.Intrinsic != nil &&
		in.Intrinsic.AttackerCapability == schema.AttackerUnauthenticatedNetwork {
		base *= 0.6
	}

	// WAF penalty for unauthenticated network attacks.
	if in.Asset.Signals.Network != nil && in.Asset.Signals.Network.WAF != "" {
		if in.Intrinsic != nil &&
			in.Intrinsic.AttackerCapability == schema.AttackerUnauthenticatedNetwork {
			base *= 0.7
		}
	}

	return clamp(base, 0, 10)
}

// preconditionScore (P) — fraction of preconditions actually satisfied.
//
// Per-evaluation values: Satisfied=10, Unknown=5 (neutral, signals no
// information), Unsatisfied=2 (contradicts; full-block handled by
// override). Average across all preconditions, weighted equally.
//
// The Unknown=5 value is intentional: we don't penalize for not yet
// knowing. The unknown-blocker dampener (in combine.go) handles the
// "we don't know, so don't be confident" case at the score level.
func preconditionScore(set schema.PreconditionEvalSet) float64 {
	if len(set) == 0 {
		return 5.0
	}
	total := 0.0
	for _, e := range set {
		var v float64
		switch e.Status {
		case schema.PreconditionSatisfied:
			v = 10.0
		case schema.PreconditionUnknown:
			v = 5.0
		case schema.PreconditionUnsatisfied:
			v = 2.0
		}
		total += v
	}
	return clamp(total/float64(len(set)), 0, 10)
}

// exploitation (X) — is this CVE being exploited in the wild right now?
//
// Scoring hierarchy (highest wins, applied independently then max taken):
//
//	CISA KEV or ransomware-associated       → 9.5  (KEV-floor P0 trigger)
//	VulnCheck KEV or ENISA EUVD KEV         → 9.0
//	VCDB breach confirmation                → 9.0  (real financial loss)
//	Observation feeds (inthewild.io, etc.)  → 8.0
//	Google Project Zero pre-patch 0day      → 8.5
//	AttackerKB attacker_value = 5           → 7.5
//	AttackerKB attacker_value = 4           → 7.0
//	AttackerKB attacker_value = 3           → 5.5
//	Recent PoC (≤30 days)                  → 3.0
//
// X ≥ KEVFloorThreshold (default 9.0) triggers the KEV floor override:
// the finding lands at P0 regardless of other components.
func exploitation(e schema.ExploitationEvidence) float64 {
	score := 0.0

	// KEV source signals.
	for _, src := range e.InKEVSources {
		switch src {
		case "cisa_kev":
			score = max(score, 9.5)
		case "vulncheck_kev":
			score = max(score, 9.0)
		case "enisa_euvd_kev":
			score = max(score, 9.0)
		}
	}

	// Ransomware association — treat equivalent to CISA KEV.
	if e.RansomwareAssociated {
		score = max(score, 9.5)
	}

	// VCDB breach confirmation — CVE caused a real, documented breach.
	if e.BreachConfirmed {
		score = max(score, 9.0)
	}

	// ENISA EUVD direct exploitation flag (also sets InKEVSources above,
	// but guard here in case Apply wasn't called).
	if e.ENISAExploited {
		score = max(score, 9.0)
	}

	// In-the-wild observation feeds.
	if len(e.ObservationSources) > 0 {
		score = max(score, 8.0)
	}

	// Google Project Zero — exploited before a patch existed.
	if e.ZeroDayConfirmed {
		score = max(score, 8.5)
	}

	// AttackerKB community practitioner value (0–5 scale).
	switch {
	case e.AttackerKBValue >= 5:
		score = max(score, 7.5)
	case e.AttackerKBValue >= 4:
		score = max(score, 7.0)
	case e.AttackerKBValue >= 3:
		score = max(score, 5.5)
	}

	// Metasploit exploit module — reliable, GUI-accessible weaponized exploit.
	// This is a stronger signal than a raw PoC; Metasploit lowers the skill
	// bar for attackers to near-zero. Score above AttackerKB.
	if e.MetasploitAvailable {
		modBoost := 8.0
		if e.MetasploitModCount >= 2 {
			modBoost = 8.5 // multiple modules = several attack surfaces weaponized
		}
		score = max(score, modBoost)
	}

	// CISA SSVC "Immediate" means CISA independently assessed the issue as
	// requiring emergency patching — treat equivalently to KEV-adjacent.
	switch e.CISASSVCDecision {
	case "Immediate":
		score = max(score, 9.0)
	case "Out-of-Cycle":
		score = max(score, 7.0)
	case "Scheduled":
		score = max(score, 3.5)
	}

	// Recent public PoC — weakest standalone signal.
	if e.RecentPOCDays > 0 && e.RecentPOCDays <= 30 {
		score = max(score, 3.0)
	}

	return clamp(score, 0, 10)
}

// criticality (C) — blast radius if compromised.
//
// Sourced from the asset's Criticality classification. Adapters can
// extend this to factor in data sensitivity / lateral-movement potential
// once those signals are available.
func criticality(a *schema.Asset) float64 {
	if a == nil {
		return 5.0
	}
	switch a.Criticality {
	case schema.CriticalityCritical:
		return 9.5
	case schema.CriticalityHigh:
		return 7.5
	case schema.CriticalityMedium:
		return 5.0
	case schema.CriticalityLow:
		return 2.5
	default:
		return 5.0
	}
}

// timePressure (T) — how urgent is action, given disclosure age?
//
// Newer CVEs without yet-deployed patches get a temporary boost. As
// time passes without patching, T plateaus rather than continuing to
// rise — the existence of a long-unpatched system is its own
// independent issue, captured elsewhere.
func timePressure(in Input, now time.Time) float64 {
	if in.CVE == nil || in.CVE.PublishedAt.IsZero() {
		return 5.0
	}
	days := int(now.Sub(in.CVE.PublishedAt).Hours() / 24)
	switch {
	case days < 7:
		return 7.0
	case days < 30:
		return 5.0
	case days < 90:
		return 4.0
	default:
		return 3.0
	}
}

func parseAVAC(vector string) (av, ac string) {
	for _, p := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		switch k {
		case "AV":
			av = v
		case "AC":
			ac = v
		}
	}
	return
}

func intrinsicVector(in Input) string {
	if in.Intrinsic == nil {
		return ""
	}
	return in.Intrinsic.CVSSReconciliation.CorrectVector
}

func hasNucleiTemplate(in Input) bool {
	return in.CVE != nil && in.CVE.NucleiTemplate != ""
}

func hasWeaponizedPOC(in Input) bool {
	return in.CVE != nil && in.CVE.POCCount > 0
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
