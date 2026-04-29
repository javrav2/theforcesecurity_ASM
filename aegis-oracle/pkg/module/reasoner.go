package module

import (
	"context"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// ReasonerPhase identifies which step of the reasoning pipeline a
// reasoner participates in. Each phase has its own set of input/output
// shapes and may have multiple registered reasoners (the pipeline picks
// the configured default; alternates can be A/B'd).
type ReasonerPhase string

const (
	// PhaseIntrinsic operates on a CVE alone, producing structured facts
	// (preconditions, CVSS reconciliation, attack chain). Typically LLM-driven.
	PhaseIntrinsic ReasonerPhase = "intrinsic"

	// PhaseContextual evaluates each precondition against a specific
	// asset's signals. Mostly deterministic; may consult an LLM only
	// for ambiguous matches (e.g. fuzzy version comparisons).
	PhaseContextual ReasonerPhase = "contextual"

	// PhasePriority computes the OPES score and the action-oriented
	// priority bucket from intrinsic + contextual outputs. Pure math.
	PhasePriority ReasonerPhase = "priority"
)

// Reasoner produces an analysis of a (CVE, [Asset]) pair. The shape of
// the analysis depends on the phase.
type Reasoner interface {
	Module
	Phase() ReasonerPhase
	Analyze(ctx context.Context, in ReasonerInput) (ReasonerOutput, error)
}

type ReasonerInput struct {
	CVE        *schema.CVE
	Enrichment *schema.EnrichmentBundle
	Asset      *schema.Asset // nil for intrinsic phase
	Intrinsic  *schema.IntrinsicAnalysis
	Contextual schema.PreconditionEvalSet
}

// ReasonerOutput is a tagged union over the three phase output types.
// Exactly one field is populated per call, matching the reasoner's Phase().
type ReasonerOutput struct {
	Intrinsic  *schema.IntrinsicAnalysis
	Contextual schema.PreconditionEvalSet
	Priority   *schema.OPESScore
}
