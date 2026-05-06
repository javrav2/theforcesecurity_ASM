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

// AnalystBrief is the plain-language vulnerability intelligence section of
// an IntrinsicAnalysis. It is written for the human analyst reading the
// finding — not for downstream scoring. All fields are 2–5 sentences of
// prose, jargon-free enough for a developer or security engineer who is
// not a specialist in the vulnerability class.
type AnalystBrief struct {
	// Title is a single-line human-readable vulnerability name in the form
	// "<Product/Component>: <Impact> via <Root Cause>" — e.g.
	// "Marimo: Pre-Auth Remote Code Execution via Terminal WebSocket Auth Bypass"
	// or "Node.js http-proxy: SSRF via Unchecked Host Header Forwarding".
	// Used as the heading in the UI so analysts can understand the finding
	// at a glance without reading the CVE description.
	Title string `json:"title"`

	// WhatIsIt describes the bug in plain English: what code path is
	// vulnerable, what the root cause is, and what class of weakness it
	// represents (e.g. "buffer overflow in the AEAD crypto interface").
	WhatIsIt string `json:"what_is_it"`

	// AttackScenario is a realistic step-by-step narrative of how an
	// attacker would actually exploit this — what they send, what happens
	// internally, and what they gain. Written for an analyst who needs to
	// understand the realistic threat, not a textbook description.
	AttackScenario string `json:"attack_scenario"`

	// AttackVectorSummary is a single sentence distillation of the attack
	// surface: who the attacker is, where they sit, and what access they
	// need before exploitation can begin.
	AttackVectorSummary string `json:"attack_vector_summary"`

	// RealWorldLikelihood assesses how likely real-world exploitation is,
	// going beyond CVSS. Considers attacker motivation, prevalence of
	// the vulnerable pattern in real codebases, tooling availability
	// (Metasploit, Nuclei, Shodan-visible surface), and whether the bug
	// requires specialist knowledge or is push-button exploitable.
	RealWorldLikelihood string `json:"real_world_likelihood"`

	// AffectedIf describes the specific development practices,
	// configurations, or deployment patterns that make a target
	// exploitable — e.g. "uses express-fileupload with parseNested:true"
	// or "runs with --allow-env flag". Concrete enough to let a dev
	// self-assess in 30 seconds.
	AffectedIf string `json:"affected_if"`

	// NotAffectedIf describes mitigating configurations or patterns that
	// exclude the risk — e.g. "WAF with OWASP ruleset blocks the payload",
	// "no user-controlled input reaches the sink", or "kernel version ≥
	// 6.15 has the patch applied". Empty if there are no known mitigations
	// short of patching.
	NotAffectedIf string `json:"not_affected_if,omitempty"`
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
	// AnalystBrief is the human-readable vulnerability intelligence writeup
	// rendered in the UI to help analysts and developers understand the
	// vulnerability, attack vector, and real-world exploitation likelihood.
	AnalystBrief         AnalystBrief         `json:"analyst_brief"`
	DetectionSignals     []string             `json:"detection_signals,omitempty"`
	Rationale            string               `json:"rationale"`
	Confidence           Confidence           `json:"confidence"`

	PromptVersion string `json:"prompt_version,omitempty"`
	LLMModel      string `json:"llm_model,omitempty"`
}
