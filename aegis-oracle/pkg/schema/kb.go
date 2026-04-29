package schema

import "time"

// CWEProfile is a curated knowledge record per CWE class capturing how
// that weakness manifests as exploitable code in production. Authored in
// knowledgebase/cwe/<CWE-ID>.yaml and code-reviewed.
type CWEProfile struct {
	CWEID             string                   `yaml:"cwe_id" json:"cwe_id"`
	Name              string                   `yaml:"name" json:"name"`
	Abstraction       string                   `yaml:"abstraction" json:"abstraction"` // 'class' | 'base' | 'variant'
	ParentCWEs        []string                 `yaml:"parent_cwes,omitempty" json:"parent_cwes,omitempty"`
	ExploitArchetypes []ExploitArchetype       `yaml:"exploit_archetypes" json:"exploit_archetypes"`
	EcosystemNotes    map[string]EcosystemNote `yaml:"ecosystem_notes,omitempty" json:"ecosystem_notes,omitempty"`
	FrameworkNotes    map[string]FrameworkNote `yaml:"framework_notes,omitempty" json:"framework_notes,omitempty"`
	DetectionSignals  []string                 `yaml:"detection_signals,omitempty" json:"detection_signals,omitempty"`
	CuratorNotes      string                   `yaml:"curator_notes,omitempty" json:"curator_notes,omitempty"`
	SourceRefs        []string                 `yaml:"source_refs,omitempty" json:"source_refs,omitempty"`
	LastReviewedAt    *time.Time               `yaml:"last_reviewed_at,omitempty" json:"last_reviewed_at,omitempty"`
	ReviewedBy        string                   `yaml:"reviewed_by,omitempty" json:"reviewed_by,omitempty"`
}

type ExploitArchetype struct {
	ArchetypeID               string   `yaml:"archetype_id" json:"archetype_id"`
	Name                      string   `yaml:"name" json:"name"`
	Summary                   string   `yaml:"summary" json:"summary"`
	TypicalPreconditions      []string `yaml:"typical_preconditions,omitempty" json:"typical_preconditions,omitempty"`
	TypicalAttackerCapability string   `yaml:"typical_attacker_capability,omitempty" json:"typical_attacker_capability,omitempty"`
	CommonMisconceptions      []string `yaml:"common_misconceptions,omitempty" json:"common_misconceptions,omitempty"`
}

type EcosystemNote struct {
	Summary           string   `yaml:"summary" json:"summary"`
	CommonPatterns    []string `yaml:"common_patterns,omitempty" json:"common_patterns,omitempty"`
	CommonMitigations []string `yaml:"common_mitigations,omitempty" json:"common_mitigations,omitempty"`
}

type FrameworkNote struct {
	Summary           string   `yaml:"summary" json:"summary"`
	CommonPatterns    []string `yaml:"common_patterns,omitempty" json:"common_patterns,omitempty"`
	CommonMitigations []string `yaml:"common_mitigations,omitempty" json:"common_mitigations,omitempty"`
}

// DevPattern is a real-world exploitable code/config/runtime pattern,
// scoped to ecosystem + framework + library. Reused by the intrinsic
// reasoner as priors and by Phase B for consistent precondition signals
// across the whole CVE corpus.
type DevPattern struct {
	PatternID            string         `yaml:"pattern_id" json:"pattern_id"`
	CWEIDs               []string       `yaml:"cwe_ids" json:"cwe_ids"`
	Ecosystem            string         `yaml:"ecosystem" json:"ecosystem"`
	Framework            string         `yaml:"framework,omitempty" json:"framework,omitempty"`
	Library              string         `yaml:"library,omitempty" json:"library,omitempty"`
	PatternName          string         `yaml:"pattern_name" json:"pattern_name"`
	Summary              string         `yaml:"summary" json:"summary"`
	ExploitPreconditions []Precondition `yaml:"exploit_preconditions" json:"exploit_preconditions"`
	CodeIndicators       []string       `yaml:"code_indicators,omitempty" json:"code_indicators,omitempty"`
	ConfigIndicators     []string       `yaml:"config_indicators,omitempty" json:"config_indicators,omitempty"`
	RuntimeIndicators    []string       `yaml:"runtime_indicators,omitempty" json:"runtime_indicators,omitempty"`
	AttackerCapability   string         `yaml:"attacker_capability" json:"attacker_capability"`
	RemoteTriggerability string         `yaml:"remote_triggerability" json:"remote_triggerability"`
	VulnerableExample    string         `yaml:"vulnerable_example,omitempty" json:"vulnerable_example,omitempty"`
	SecureExample        string         `yaml:"secure_example,omitempty" json:"secure_example,omitempty"`
	RemediationSummary   string         `yaml:"remediation_summary" json:"remediation_summary"`
	References           []string       `yaml:"references,omitempty" json:"references,omitempty"`
	RelatedCVEs          []string       `yaml:"related_cves,omitempty" json:"related_cves,omitempty"`
	Curator              string         `yaml:"curator" json:"curator"`
	ReviewedAt           time.Time      `yaml:"reviewed_at" json:"reviewed_at"`
}
