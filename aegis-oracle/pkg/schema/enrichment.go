package schema

// EnrichmentBundle is the accumulated context that enricher modules
// produce for a CVE before reasoning. The intrinsic reasoner reads this
// and the CVE record together when calling the LLM.
type EnrichmentBundle struct {
	CWEProfiles  []CWEProfile         `json:"cwe_profiles,omitempty"`
	DevPatterns  []DevPattern         `json:"dev_patterns,omitempty"`
	References   []ReferenceContent   `json:"references,omitempty"`
	POCs         []POCContent         `json:"pocs,omitempty"`
	Exploitation ExploitationEvidence `json:"exploitation"`
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
