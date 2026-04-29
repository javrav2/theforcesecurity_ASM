// Package contextual implements Phase B: take an IntrinsicAnalysis and an
// Asset, evaluate each precondition against the asset's signals, and
// emit a PreconditionEvalSet usable by OPES.
//
// Phase B is rule-based and cheap. The LLM is not in the loop here —
// upstream Phase A produced structured preconditions with verification_signal
// paths, so resolving them is a deterministic signal lookup + match check.
//
// When a signal is missing the precondition is Unknown (not Unsatisfied).
// We never assume the absence of a signal means the precondition fails;
// that's how false-negative findings hide and how the bot would lose
// trust. The unknown-blocker dampener in OPES handles uncertainty.
package contextual

import (
	"regexp"
	"strings"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Evaluate walks the intrinsic preconditions and produces an evaluation
// per precondition against the asset's signals. The result feeds OPES.
//
// Match kinds:
//
//	regex       — match_value as Go regexp against signal value
//	equals      — case-insensitive string equality
//	contains    — case-insensitive substring
//	present     — signal exists and is non-empty (match_value ignored)
//	version_lte — string compare assuming semver-like tokens (best-effort)
func Evaluate(intrinsic *schema.IntrinsicAnalysis, asset *schema.Asset) schema.PreconditionEvalSet {
	if intrinsic == nil || asset == nil {
		return nil
	}
	out := make(schema.PreconditionEvalSet, 0, len(intrinsic.Preconditions))
	for _, p := range intrinsic.Preconditions {
		out = append(out, evaluateOne(p, asset.Signals))
	}
	return out
}

func evaluateOne(p schema.Precondition, signals schema.AssetSignals) schema.PreconditionEval {
	signalVal, present := signals.Lookup(p.VerificationSignal)
	if !present {
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionUnknown,
			Reason:       "asset signal `" + p.VerificationSignal + "` not populated",
		}
	}
	matched, why := matches(p, signalVal)
	switch matched {
	case true:
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionSatisfied,
			Reason:       "signal matched: " + why,
			SignalValue:  signalVal,
		}
	default:
		return schema.PreconditionEval{
			Precondition: p,
			Status:       schema.PreconditionUnsatisfied,
			Reason:       "signal contradicts precondition: " + why,
			SignalValue:  signalVal,
		}
	}
}

func matches(p schema.Precondition, value string) (bool, string) {
	switch p.MatchKind {
	case "regex":
		re, err := regexp.Compile(p.MatchValue)
		if err != nil {
			return false, "invalid regex: " + err.Error()
		}
		if re.MatchString(value) {
			return true, "matched regex /" + p.MatchValue + "/"
		}
		return false, "did not match regex /" + p.MatchValue + "/"
	case "equals":
		if strings.EqualFold(value, p.MatchValue) {
			return true, "equal to " + p.MatchValue
		}
		return false, "value " + value + " != " + p.MatchValue
	case "contains":
		if strings.Contains(strings.ToLower(value), strings.ToLower(p.MatchValue)) {
			return true, "contains " + p.MatchValue
		}
		return false, "does not contain " + p.MatchValue
	case "present":
		if value != "" {
			return true, "signal present"
		}
		return false, "signal empty"
	case "version_lte":
		if compareVersions(value, p.MatchValue) <= 0 {
			return true, "version " + value + " <= " + p.MatchValue
		}
		return false, "version " + value + " > " + p.MatchValue
	default:
		// Conservative default: unknown match_kind → don't claim either
		// satisfied or unsatisfied; treat as unsatisfied with explanation.
		return false, "unsupported match_kind: " + p.MatchKind
	}
}

// compareVersions does a loose dotted-number comparison: "1.2.3" vs "1.2.10".
// Non-numeric tokens compare lexicographically. Returns -1 / 0 / 1.
//
// Good enough for the version_lte preconditions we expect (e.g. "node <=
// 24.10.0"); for serious version semantics, swap in github.com/Masterminds/semver
// behind this function.
func compareVersions(a, b string) int {
	ap := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bp := strings.Split(strings.TrimPrefix(b, "v"), ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var ai, bi string
		if i < len(ap) {
			ai = ap[i]
		}
		if i < len(bp) {
			bi = bp[i]
		}
		if ai == bi {
			continue
		}
		ax, ok1 := atoi(ai)
		bx, ok2 := atoi(bi)
		if ok1 && ok2 {
			if ax < bx {
				return -1
			}
			return 1
		}
		if ai < bi {
			return -1
		}
		return 1
	}
	return 0
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
