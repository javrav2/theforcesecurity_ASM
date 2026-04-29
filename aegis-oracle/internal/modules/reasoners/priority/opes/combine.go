package opes

import (
	"fmt"
	"math"
	"sort"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// combine takes the six component scores and produces the final OPESScore,
// applying overrides and dampeners in this order:
//
//  1. Blocker-unsatisfied override → score 0, P4 "Not Exploitable"
//  2. Reachability-zero override   → score 0, P4 "Not Reachable"
//  3. Weighted sum                 → raw 0–10
//  4. KEV-floor override (X high)  → floor at KEVFloorScore, P0
//  5. Unknown-blocker dampener     → cap at UnknownBlockerCap (P3-territory)
//
// Order matters: an unsatisfied blocker beats KEV listing (the exploit
// genuinely cannot happen), but KEV beats unknown blockers (we know
// someone is exploiting it; verify fast).
func combine(in Input, c schema.OPESComponents, cfg Config) schema.OPESScore {
	if in.Preconditions.AnyBlocker(schema.PreconditionUnsatisfied) {
		return schema.OPESScore{
			Value:            0.0,
			Category:         schema.PriorityP4,
			Label:            "Not Exploitable",
			Confidence:       schema.ConfidenceHigh,
			Components:       c,
			TopContributors:  []string{"At least one blocker precondition is unsatisfied — exploit is impossible on this asset"},
			Override:         "blocker_unsatisfied",
			EvaluatorVersion: Version,
		}
	}

	if c.R == 0 {
		return schema.OPESScore{
			Value:            0.0,
			Category:         schema.PriorityP4,
			Label:            "Not Reachable",
			Confidence:       schema.ConfidenceHigh,
			Components:       c,
			TopContributors:  []string{"Asset is isolated or otherwise unreachable by the required attacker class"},
			Override:         "unreachable",
			EvaluatorVersion: Version,
		}
	}

	raw := cfg.Weights.X*c.X +
		cfg.Weights.P*c.P +
		cfg.Weights.R*c.R +
		cfg.Weights.E*(10-c.E) +
		cfg.Weights.C*c.C +
		cfg.Weights.T*c.T

	if c.X >= cfg.Dampeners.KEVFloorThreshold {
		if raw < cfg.Dampeners.KEVFloorScore {
			raw = cfg.Dampeners.KEVFloorScore
		}
		score := buildScore(raw, c, in, cfg)
		score.Category = schema.PriorityP0
		score.Label = "Actively Exploited"
		score.Override = "kev_floor"
		return score
	}

	dampener := ""
	if in.Preconditions.AnyBlocker(schema.PreconditionUnknown) {
		if raw > cfg.Dampeners.UnknownBlockerCap {
			raw = cfg.Dampeners.UnknownBlockerCap
			dampener = fmt.Sprintf(
				"Unknown-blocker dampener applied: %d blocker precondition(s) unverifiable from current asset signals; capped at P3 until verified",
				in.Preconditions.CountBlockers(schema.PreconditionUnknown),
			)
		}
	}

	score := buildScore(raw, c, in, cfg)
	if dampener != "" {
		score.Dampener = dampener
	}
	return score
}

func buildScore(raw float64, c schema.OPESComponents, in Input, cfg Config) schema.OPESScore {
	raw = clamp(raw, 0, 10)
	rounded := math.Round(raw*10) / 10
	cat, label := bucketize(rounded, cfg)
	return schema.OPESScore{
		Value:            rounded,
		Category:         cat,
		Label:            label,
		Confidence:       deriveConfidence(in),
		Components:       c,
		TopContributors:  explain(c, cfg),
		EvaluatorVersion: Version,
	}
}

func bucketize(v float64, cfg Config) (schema.Priority, string) {
	switch {
	case v >= cfg.Bucketing.P0:
		return schema.PriorityP0, "Critical - Actively Exploitable"
	case v >= cfg.Bucketing.P1:
		return schema.PriorityP1, "High - Likely Exploitable"
	case v >= cfg.Bucketing.P2:
		return schema.PriorityP2, "Medium - Conditionally Exploitable"
	case v >= cfg.Bucketing.P3:
		return schema.PriorityP3, "Conditional - Verification Required"
	default:
		return schema.PriorityP4, "Low - Unlikely to be Exploited"
	}
}

func deriveConfidence(in Input) schema.Confidence {
	if in.Intrinsic == nil {
		return schema.ConfidenceLow
	}
	if in.Preconditions.AnyBlocker(schema.PreconditionUnknown) {
		return schema.ConfidenceMedium
	}
	if in.Intrinsic.Confidence == "" {
		return schema.ConfidenceMedium
	}
	return in.Intrinsic.Confidence
}

// explain ranks the components by their weighted contribution and returns
// human-readable lines for the top three. This is what shows up in
// findings.opes.top_contributors and feeds the recommendation paragraph.
func explain(c schema.OPESComponents, cfg Config) []string {
	type contrib struct {
		Name  string
		Code  string
		Value float64
		Raw   float64
	}
	contribs := []contrib{
		{Name: "Active exploitation evidence", Code: "X", Value: cfg.Weights.X * c.X, Raw: c.X},
		{Name: "Precondition satisfaction", Code: "P", Value: cfg.Weights.P * c.P, Raw: c.P},
		{Name: "Reachability", Code: "R", Value: cfg.Weights.R * c.R, Raw: c.R},
		{Name: "Exploit difficulty (inverted)", Code: "E", Value: cfg.Weights.E * (10 - c.E), Raw: c.E},
		{Name: "Asset criticality", Code: "C", Value: cfg.Weights.C * c.C, Raw: c.C},
		{Name: "Time pressure", Code: "T", Value: cfg.Weights.T * c.T, Raw: c.T},
	}
	// Rank by distance from neutral contribution (~1.5 if all weights equal).
	// This surfaces the most-influential factors regardless of direction.
	sort.Slice(contribs, func(i, j int) bool {
		return math.Abs(contribs[i].Value-1.5) > math.Abs(contribs[j].Value-1.5)
	})
	out := make([]string, 0, 3)
	for i := 0; i < 3 && i < len(contribs); i++ {
		out = append(out, fmt.Sprintf(
			"%s (%s=%.1f, contribution %+.2f)",
			contribs[i].Name, contribs[i].Code, contribs[i].Raw, contribs[i].Value,
		))
	}
	return out
}
