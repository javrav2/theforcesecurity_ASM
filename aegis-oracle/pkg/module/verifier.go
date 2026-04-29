package module

import (
	"context"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Verifier closes the loop on Unknown preconditions. When Phase B can't
// determine a precondition's status from existing asset signals, it
// generates a VerificationTask. A registered Verifier that Supports() the
// task picks it up and either runs it (e.g. nuclei detection-only) or
// hands it to a human queue.
type Verifier interface {
	Module
	Supports(task *schema.VerificationTask) bool
	Verify(ctx context.Context, task *schema.VerificationTask) (*VerificationResult, error)
}

// VerificationResult is the answer that flows back into the asset's
// signals, triggering re-evaluation of any open findings whose
// preconditions reference the resolved signal path.
type VerificationResult struct {
	TaskID      string
	SignalPath  string
	SignalValue string
	Notes       string
	Confidence  schema.Confidence
}
