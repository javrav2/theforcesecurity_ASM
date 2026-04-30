package schema

// EnrichmentBundle is the accumulated context that enricher modules
// produce for a CVE before reasoning. The intrinsic reasoner reads this
// and the CVE record together when calling the LLM.
type EnrichmentBundle struct {
	CWEProfiles []CWEProfile       `json:"cwe_profiles,omitempty"`
	DevPatterns []DevPattern       `json:"dev_patterns,omitempty"`
	References  []ReferenceContent `json:"references,omitempty"`
	POCs        []POCContent       `json:"pocs,omitempty"`
	Exploitation ExploitationEvidence `json:"exploitation"`

	// ── Regional NVD sources ────────────────────────────────────────────────
	// VulnrichmentSSVC is CISA's SSVC decision for this CVE (e.g. "Immediate",
	// "Out-of-Cycle", "Scheduled", "Defer"). Non-empty means CISA has
	// independently triage-classified the vulnerability.
	VulnrichmentSSVC   string   `json:"vulnrichment_ssvc,omitempty"`
	VulnrichmentCVSS4  string   `json:"vulnrichment_cvss4_vector,omitempty"`
	VulnrichmentCPEs   []string `json:"vulnrichment_cpes,omitempty"`

	// JVNEntries lists JVN iPedia (Japanese NVD) vulnerability records that
	// reference this CVE. Non-empty means Japan's IPA/JPCERT has catalogued it.
	JVNEntries []JVNEntry `json:"jvn_entries,omitempty"`

	// BDUEntries lists BDU FSTEC (Russian national DB) records that reference
	// this CVE. Non-empty means Russia's FSTEC has independently catalogued it.
	BDUEntries []BDUEntry `json:"bdu_entries,omitempty"`

	// ── Threat intelligence ─────────────────────────────────────────────────
	// ATTACKTechniques maps the CVE to MITRE ATT&CK techniques via the CTID
	// Mappings Explorer dataset. Each entry is a T#### or T####.### ID.
	ATTACKTechniques []ATTACKTactic `json:"attack_techniques,omitempty"`

	// MetasploitModules lists Metasploit exploit module paths in the
	// rapid7/metasploit-framework repository. Non-empty is a strong
	// weaponization signal — reliable exploit accessible via GUI tooling.
	MetasploitModules []string `json:"metasploit_modules,omitempty"`

	// NucleiTemplatePaths lists nuclei-template YAML paths for this CVE.
	// Non-empty means automated scanning tools can trivially probe assets.
	NucleiTemplatePaths []string `json:"nuclei_template_paths,omitempty"`

	// OWASPCategories maps CWE IDs to OWASP Top 10 2021 categories.
	OWASPCategories []OWASPCategory `json:"owasp_categories,omitempty"`
}

type ReferenceContent struct {
	URL        string `json:"url"`
	SourceKind string `json:"source_kind"`
	Excerpt    string `json:"excerpt,omitempty"`
}

type POCContent struct {
	URL           string `json:"url"`
	Source        string `json:"source"`
	Title         string `json:"title,omitempty"`
	ReadmeExcerpt string `json:"readme_excerpt,omitempty"`
	CodeExcerpt   string `json:"code_excerpt,omitempty"`
}

// ── Regional NVD result types (mirrors enrichers package, kept here for schema
//    independence so pkg/schema has no upstream import dependencies) ──────────

// JVNEntry is a Japanese NVD iPedia record.
type JVNEntry struct {
	JVNDBID  string `json:"jvndb_id"`
	Title    string `json:"title"`
	Link     string `json:"link"`
	Summary  string `json:"summary,omitempty"`
}

// BDUEntry is a Russian FSTEC national vulnerability database record reference.
type BDUEntry struct {
	BDUID   string `json:"bdu_id"`
	FileURL string `json:"file_url"`
}

// ATTACKTactic describes one MITRE ATT&CK technique mapping.
type ATTACKTactic struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name,omitempty"`
	Tactics       []string `json:"tactics,omitempty"`
	URL           string   `json:"url,omitempty"`
}

// OWASPCategory describes a matched OWASP Top 10 2021 category.
type OWASPCategory struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	MatchedCWEs []string `json:"matched_cwes"`
}
