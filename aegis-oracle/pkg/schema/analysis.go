package schema

type RemoteTriggerability string

const (
	TriggerYes         RemoteTriggerability = "yes"
	TriggerNo          RemoteTriggerability = "no"
	TriggerConditional RemoteTriggerability = "conditional"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// AttackerCapability captures the minimum capability an attacker must already
// possess to mount the exploit. Used by OPES difficulty and reachability.
type AttackerCapability string

const (
	AttackerUnauthenticatedNetwork AttackerCapability = "unauthenticated_network"
	AttackerAuthenticatedLowPriv   AttackerCapability = "authenticated_low_priv"
	AttackerAuthenticatedHighPriv  AttackerCapability = "authenticated_high_priv"
	AttackerLocalUser              AttackerCapability = "local_user"
	AttackerAdjacentNetwork        AttackerCapability = "adjacent_network"
	AttackerPhysical               AttackerCapability = "physical"
	AttackerCodeExecution          AttackerCapability = "code_execution_required"
)

type ExploitComplexity string

const (
	ComplexityLow    ExploitComplexity = "low"
	ComplexityMedium ExploitComplexity = "medium"
	ComplexityHigh   ExploitComplexity = "high"
)

// CVSSReconciliation is the LLM's judgment about which CVSS source to trust
// when sources disagree. Driven by the description, references, and PoC
// content. The corrected vector — not the NVD vector — flows into OPES.
type CVSSReconciliation struct {
	CorrectVector  string                   `json:"correct_vector"`
	CorrectScore   float64                  `json:"correct_score"`
	CorrectVersion string                   `json:"correct_version"`
	Rationale      string                   `json:"rationale"`
	Disagreements  []CVSSSourceDisagreement `json:"disagreements,omitempty"`
}

type CVSSSourceDisagreement struct {
	Source       string `json:"source"`
	TheirVector  string `json:"their_vector"`
	Disagreement string `json:"disagreement"`
}

// IntrinsicAnalysis is the Phase A reasoner's structured output.
// Same input → same output (deterministic via prompt versioning + caching).
// Phase B and OPES consume this; humans audit it.
type IntrinsicAnalysis struct {
	CVEID                string               `json:"cve_id"`
	RemoteTriggerability RemoteTriggerability `json:"remote_triggerability"`
	ExploitComplexity    ExploitComplexity    `json:"exploit_complexity"`
	AttackerCapability   AttackerCapability   `json:"attacker_capability"`
	Preconditions        []Precondition       `json:"preconditions"`
	CVSSReconciliation   CVSSReconciliation   `json:"cvss_reconciliation"`
	AttackChainSummary   string               `json:"attack_chain_summary"`
	DetectionSignals     []string             `json:"detection_signals,omitempty"`
	Rationale            string               `json:"rationale"`
	Confidence           Confidence           `json:"confidence"`

	PromptVersion string `json:"prompt_version,omitempty"`
	LLMModel      string `json:"llm_model,omitempty"`
}
