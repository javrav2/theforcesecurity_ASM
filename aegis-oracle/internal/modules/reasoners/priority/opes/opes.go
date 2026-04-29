// Package opes implements the Oracle Practical Exploitability Score —
// Aegis Oracle's deterministic, auditable risk score for a (CVE, Asset)
// pair.
//
// The LLM extracts structured facts in upstream phases. This package
// converts those facts into a 0–10 score and a P0..P4 priority bucket
// using pure arithmetic. Same inputs always produce the same score,
// which is what makes findings defensible at scale.
//
// See ../../../../knowledgebase/ for the curated CWE profiles and dev
// patterns that feed the upstream intrinsic reasoner.
package opes

import (
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Version is the OPES evaluator version. Bump on any logic change so
// findings can be re-evaluated and old scores marked superseded.
const Version = "opes/v1"

// Input bundles everything OPES needs to compute a score. All fields
// are owned by upstream pipeline stages — OPES does not fetch anything.
type Input struct {
	CVE           *schema.CVE
	Intrinsic     *schema.IntrinsicAnalysis
	Asset         *schema.Asset
	Preconditions schema.PreconditionEvalSet
	Exploitation  schema.ExploitationEvidence
	Now           time.Time
}

// Compute runs the OPES pipeline: components → overrides → weighted sum
// → dampeners → bucketize. Returns a fully-populated OPESScore ready to
// embed in a Finding.
//
// Compute never returns an error: bad inputs degrade gracefully (e.g. no
// intrinsic analysis → middle-of-range component values + low confidence)
// rather than panicking. This keeps the scoring path safe to call from
// anywhere in the pipeline.
func Compute(in Input, cfg Config) schema.OPESScore {
	cfg = cfg.WithDefaults()
	if in.Now.IsZero() {
		in.Now = time.Now()
	}

	components := schema.OPESComponents{
		E: difficulty(in),
		R: reachability(in, cfg),
		P: preconditionScore(in.Preconditions),
		X: exploitation(in.Exploitation),
		C: criticality(in.Asset),
		T: timePressure(in, in.Now),
	}

	return combine(in, components, cfg)
}
