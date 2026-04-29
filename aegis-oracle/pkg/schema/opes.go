package schema

// Priority is the action-oriented bucket assigned by OPES. Renders to your
// existing P0..P4 conventions; remap in the priority sink if needed.
type Priority string

const (
	PriorityP0 Priority = "P0"
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
	PriorityP4 Priority = "P4"
)

// OPESScore is the Oracle Practical Exploitability Score: a 0–10 number
// plus a priority bucket, computed deterministically from intrinsic
// analysis + asset signals. The LLM never emits this — math does, so the
// score is reproducible and auditable.
type OPESScore struct {
	Value            float64        `json:"score"`
	Category         Priority       `json:"category"`
	Label            string         `json:"label"`
	Confidence       Confidence     `json:"confidence"`
	Components       OPESComponents `json:"components"`
	TopContributors  []string       `json:"top_contributors"`
	Dampener         string         `json:"dampener,omitempty"`
	Override         string         `json:"override,omitempty"`
	EvaluatorVersion string         `json:"evaluator_version"`
}

// OPESComponents are the six 0–10 sub-scores that combine into the final
// OPES value. Keeping them on the score lets reviewers see what drove it.
type OPESComponents struct {
	E float64 `json:"E"` // exploit difficulty (higher = harder); contributes inversely
	R float64 `json:"R"` // reachability (higher = more reachable)
	P float64 `json:"P"` // precondition satisfaction (higher = preconditions met)
	X float64 `json:"X"` // active exploitation evidence (higher = in-the-wild)
	C float64 `json:"C"` // asset criticality (higher = bigger blast radius)
	T float64 `json:"T"` // time pressure (higher = more urgent)
}
