// Package schema defines the public types shared across Aegis Oracle modules.
//
// Types in this package are stable, JSON/YAML-serializable, and form the
// contract between sources, enrichers, reasoners, verifiers, and sinks.
// Module implementations should depend on this package only — never on
// internal/.
package schema

import "time"

// CVE is the canonical merged record produced by the ingest pipeline.
// It blends data from cvelistV5 (primary source), NVD, OSV, GHSA, KEV,
// EPSS, and others into a single record. Per-source raw data is kept in
// raw_* tables for audit; this struct is the working view.
type CVE struct {
	ID             string       `json:"id"`
	PublishedAt    time.Time    `json:"published_at"`
	ModifiedAt     time.Time    `json:"modified_at"`
	Description    string       `json:"description"`
	CWEs           []string     `json:"cwes"`
	CPEs           []CPEMatch   `json:"cpes,omitempty"`
	CVSSVectors    []CVSSVector `json:"cvss_vectors"`
	References     []Reference  `json:"references,omitempty"`
	EPSS           *EPSSScore   `json:"epss,omitempty"`
	InKEV          bool         `json:"in_kev"`
	KEVAddedOn     *time.Time   `json:"kev_added_on,omitempty"`
	NucleiTemplate string       `json:"nuclei_template,omitempty"`
	POCCount       int          `json:"poc_count"`
	PrimarySource  string       `json:"primary_source"`
}

// CVSSVector is a CVSS score from a single source. Multiple vectors per CVE
// are normal and expected; reconciliation happens in the intrinsic reasoner.
type CVSSVector struct {
	Source   string  `json:"source"`  // 'NVD' | 'vendor' | 'HackerOne' | 'CISA-ADP' | 'GHSA' | ...
	Version  string  `json:"version"` // '3.1' | '4.0'
	Vector   string  `json:"vector"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity,omitempty"`
}

// Reference points to off-record material that the analysis pipeline may
// fetch and feed to the LLM (vendor advisory, HackerOne report, etc.).
type Reference struct {
	URL        string   `json:"url"`
	SourceKind string   `json:"source_kind"` // 'vendor' | 'github' | 'hackerone' | 'mitre' | 'oss-security' | 'other'
	Tags       []string `json:"tags,omitempty"`
}

// CPEMatch is a CPE 2.3 URI describing affected configurations.
type CPEMatch struct {
	URI        string `json:"uri"`
	Vulnerable bool   `json:"vulnerable"`
}

// EPSSScore is the FIRST.org Exploit Prediction Scoring System output.
type EPSSScore struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	ScoredOn   time.Time `json:"scored_on"`
}
