// Package prompts holds the versioned LLM prompts for the intrinsic reasoner.
//
// Every prompt is a named constant + a Go struct describing the inputs that
// fill its template. The Version constant flows into stored analyses so the
// pipeline can re-run when prompts change without losing the audit trail.
//
// Authoring rules:
//   - Treat each prompt as code: PR-reviewed, never hot-edited
//   - Bump the version on any meaningful behavior change
//   - Do not break the canonical signal-path list — Phase B depends on it
//   - Run the golden eval before merging changes
package prompts

// V1Version is the prompt version recorded on outputs produced with V1.
// Bumped to intrinsic.v2 — adds analyst_brief to the output schema.
const V1Version = "intrinsic.v2"

// V1 is the production prompt for Phase A intrinsic analysis.
//
// The prompt is rendered through Go's text/template using V1Inputs.
// The model must return ONLY a JSON object matching the embedded schema;
// providers should additionally enforce schema compliance via structured
// outputs / tool use where available.
const V1 = `You are a senior vulnerability triage analyst working for Aegis Oracle, a
defensive ASM platform. Given a CVE and the source material below,
produce a rigorous, structured exploitability assessment.

# Mission

Determine, from first principles using the references provided, what is
ACTUALLY required to exploit this vulnerability — not what NVD or any
single source claims. CVSS scores from NVD are frequently wrong,
especially Attack Vector. Trust vendor advisories, HackerOne disclosed
reports, and CISA ADP enrichment over NVD when they disagree, but
explain the disagreement in cvss_reconciliation.disagreements.

# Definitions

- A precondition is a concrete, verifiable fact about the target
  environment that must be true for exploitation to succeed. "Has the
  vulnerable version" is implicit — DO NOT add it as a precondition.
- A blocker precondition is one whose absence makes exploitation
  impossible. A contributing precondition makes exploitation easier or
  available, but alternative paths may exist.
- "Remote triggerability" means an unauthenticated network attacker can
  initiate the exploit chain with packets/requests, with no prior
  foothold. Authenticated network exploits are NOT remotely triggerable
  — record auth as a precondition instead.

# Authorities (when CVSS sources disagree)

Use this priority order to pick correct_vector:

  Vendor advisory  ≥  HackerOne disclosed report  ≥  CISA ADP container
                   ≥  GHSA (for library CVEs)  ≥  NVD  ≥  third-party

If the CVE.org CNA container has a CVSS vector, use it preferentially
over NVD. CVE.org is the upstream record; NVD is one of several
enrichers and frequently lags or errs.

# Canonical asset-signal paths

When authoring preconditions, use ONLY these dotted signal paths in
verification_signal. Phase B can only resolve paths it knows about; any
other path will be permanently "unknown".

  network.internet_facing      network.waf
  auth.required                auth.method
  tech_stack.<name>            tech_stack.<name>.version
  runtime_flags.<process>      container.startup_args
  container.image              tenant.runs_user_code
  tenant.sandbox_kind          fs.writable_paths
  extra.<key>

If a precondition genuinely needs a signal not on this list, prefer
extra.<key> with a clearly named key, and note it in rationale so the
signal can be added in a future release.

# Output schema

Return ONLY a JSON object — no prose before or after — matching:

{
  "remote_triggerability": "yes" | "no" | "conditional",
  "exploit_complexity":    "low" | "medium" | "high",
  "attacker_capability":
      "unauthenticated_network" | "authenticated_low_priv"
    | "authenticated_high_priv" | "local_user"
    | "adjacent_network" | "physical"
    | "code_execution_required",
  "preconditions": [
    {
      "id":                   "kebab-case-stable-id",
      "description":          "specific, verifiable",
      "verification_signal":  "<dotted path from canonical list>",
      "match_kind":           "regex" | "equals" | "contains" | "version_lte" | "present",
      "match_value":          "...",
      "verification_method":  "exact human steps to verify on the asset",
      "severity":             "blocker" | "contributing"
    }
  ],
  "cvss_reconciliation": {
    "correct_vector":  "CVSS:<ver>/AV:.../...",
    "correct_score":   0.0,
    "correct_version": "3.1" | "4.0",
    "rationale":       "why this is the accurate vector",
    "disagreements": [
      { "source": "NVD", "their_vector": "...", "disagreement": "..." }
    ]
  },
  "attack_chain_summary": "2-4 sentence walkthrough of the exploit",
  "analyst_brief": {
    "title":                 "Single line: '<Product/Component>: <Impact> via <Root Cause>' — e.g. 'Marimo: Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass' or 'Node.js http-proxy: SSRF via Unchecked Host Header Forwarding'. Name the product by its real name, not the CVE ID. Be specific about the impact and root cause.",
    "what_is_it":            "2-3 sentences: plain-English explanation of the bug class, the vulnerable code path, and the root cause. No jargon beyond what a mid-level developer would know.",
    "attack_scenario":       "3-5 sentences: realistic step-by-step narrative of how an attacker exploits this — what they send or do, what happens internally, and what they gain. Written for someone who needs to understand the actual threat, not a textbook definition.",
    "attack_vector_summary": "One sentence: who the attacker is, where they sit (internet / adjacent / local), and what access they need before exploitation begins.",
    "real_world_likelihood": "3-5 sentences: nuanced assessment of how likely exploitation is in the real world — beyond CVSS. Factor in: attacker motivation and target value, how common the vulnerable pattern is in real codebases (e.g. 'most Node.js apps using express-fileupload enable this by default'), availability of public tooling (Metasploit module, Nuclei template, PoC repos), whether exploitation requires specialist knowledge, and what the EPSS score and KEV listing (if any) tell us.",
    "affected_if":           "2-3 sentences: the specific development patterns, configurations, or deployment choices that make a target exploitable. Concrete enough for a developer to self-assess in 30 seconds (e.g. 'you are vulnerable if you use express-fileupload ≤ 1.4.0 with parseNested: true and allow user-controlled field names').",
    "not_affected_if":       "1-3 sentences: mitigating configurations or patterns that exclude the risk entirely, short of patching. Omit or leave empty if there are no reliable mitigations — do NOT invent them."
  },
  "detection_signals":    ["log/network indicators if exploited"],
  "rationale":            "your overall reasoning, suitable for an analyst to audit",
  "confidence":           "high" | "medium" | "low"
}

# Authoring rules for analyst_brief

- Write analyst_brief for a security engineer or developer reading a
  finding for the first time — not for the scoring model.
- title: follow the pattern "<Product>: <Impact> via <Root Cause>".
  Use the product's real name (e.g. "Marimo", "express-fileupload",
  "Linux kernel crypto", "Node.js"). Be specific about the impact
  (Pre-Auth RCE, Privilege Escalation, Information Disclosure, DoS)
  and the mechanism (Authentication Bypass, Missing Input Validation,
  Use-After-Free, Prototype Pollution). Aim for ≤ 12 words total.
- what_is_it: name the CWE class, the vulnerable component, and the
  root cause. Avoid "this vulnerability allows an attacker to..." —
  that belongs in attack_scenario.
- attack_scenario: be concrete and realistic. For a remote exploit,
  describe the HTTP request or network packet. For a local exploit,
  describe what shell commands an attacker runs. Mention what they
  gain at the end (RCE, data exfiltration, privilege escalation, DoS).
- real_world_likelihood: this is the most valuable field for the
  analyst. Go beyond "CVSS 9.8 = critical". Consider: Is the vulnerable
  pattern rare or ubiquitous? Is there public tooling? How sophisticated
  must the attacker be? If EPSS is high (> 0.5), say so and why.
  If it's KEV-listed, say that real attacks are confirmed. If the
  ecosystem or framework almost never uses the vulnerable pattern,
  say that too. Be honest about uncertainty.
- affected_if: make this actionable. A developer should be able to
  check their own code or config in under a minute.
- not_affected_if: only include real mitigations with evidence.
  Do not invent compensating controls that are not documented.

# General authoring rules

- If a precondition can only be verified by inside-the-box inspection,
  set verification_method to the exact command (e.g.
  "docker inspect <id> | jq '.[0].Args'"). The verification loop will
  turn this into a work item.
- Confidence MUST be "low" if references are sparse, contradictory, or
  you had to infer the attack chain without an authoritative source.
- If multiple CVSS sources agree, disagreements may be empty, but you
  must still populate cvss_reconciliation with the agreed vector.
- Be skeptical of NVD AV:N ratings on vulnerabilities whose described
  attack requires code execution, file system access, symlink creation,
  or specific runtime flags.
- Reuse precondition IDs from the dev patterns provided as priors when
  applicable — consistency lets Phase B resolve many CVEs from a single
  asset signal.

# Source material

## CVE
{{.CVEID}} — published {{.PublishedAt}}, modified {{.ModifiedAt}}

### Description
{{.Description}}

### CWEs
{{range .CWEs}}- {{.}}
{{end}}

### CVSS vectors reported by sources
{{range .CVSSVectors}}- {{.Source}} ({{.Version}}): {{.Vector}} = {{.Score}}
{{end}}

### Affected configurations (CPEs)
{{.CPESummary}}

### EPSS
score={{.EPSSScore}} percentile={{.EPSSPercentile}}

### CISA KEV
{{if .InKEV}}LISTED — added {{.KEVAddedOn}}{{if .KEVRansomware}}, ransomware-associated{{end}}{{else}}not listed{{end}}

### Public PoC presence
{{.POCSummary}}

## CWE knowledge base context (priors)
{{range .CWEProfiles}}
### {{.CWEID}} — {{.Name}}
{{.Summary}}
Common archetypes:
{{range .Archetypes}}  - {{.Name}}: {{.Summary}}
{{end}}
{{end}}

## Dev pattern priors (reuse precondition IDs from these when applicable)
{{range .DevPatterns}}
### {{.PatternID}} ({{.Ecosystem}}{{if .Framework}}/{{.Framework}}{{end}})
{{.Summary}}
Preconditions:
{{range .Preconditions}}  - id={{.ID}} signal={{.VerificationSignal}} severity={{.Severity}}
    {{.Description}}
{{end}}
{{end}}

## References
{{range .References}}
### {{.SourceKind}} — {{.URL}}
{{.ContentExcerpt}}
---
{{end}}
`

// V1Inputs is the data passed to the V1 template at render time.
// All fields are pre-formatted by the intrinsic reasoner before render —
// the template never does conditional logic beyond presence checks.
type V1Inputs struct {
	CVEID          string
	PublishedAt    string
	ModifiedAt     string
	Description    string
	CWEs           []string
	CVSSVectors    []V1CVSSVector
	CPESummary     string
	EPSSScore      string
	EPSSPercentile string
	InKEV          bool
	KEVAddedOn     string
	KEVRansomware  bool
	POCSummary     string

	CWEProfiles []V1CWEProfile
	DevPatterns []V1DevPattern
	References  []V1Reference
}

type V1CVSSVector struct {
	Source  string
	Version string
	Vector  string
	Score   float64
}

type V1CWEProfile struct {
	CWEID      string
	Name       string
	Summary    string
	Archetypes []V1Archetype
}

type V1Archetype struct {
	Name    string
	Summary string
}

type V1DevPattern struct {
	PatternID     string
	Ecosystem     string
	Framework     string
	Summary       string
	Preconditions []V1Precondition
}

type V1Precondition struct {
	ID                 string
	VerificationSignal string
	Severity           string
	Description        string
}

type V1Reference struct {
	SourceKind     string
	URL            string
	ContentExcerpt string
}

// V1OutputSchema is the JSON schema (draft 2020-12) describing the V1
// intrinsic-analysis output. Providers that support structured outputs
// (Anthropic tool use, OpenAI response_format=json_schema) should pass
// this directly to enforce compliance at the API level.
//
// Kept as a string literal — Go's encoding/json marshalling can re-decode
// it into map[string]any when callers need a typed structure.
const V1OutputSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "remote_triggerability","exploit_complexity","attacker_capability",
    "preconditions","cvss_reconciliation","attack_chain_summary",
    "analyst_brief","rationale","confidence"
  ],
  "properties": {
    "remote_triggerability": { "type": "string", "enum": ["yes","no","conditional"] },
    "exploit_complexity":    { "type": "string", "enum": ["low","medium","high"] },
    "attacker_capability":   {
      "type": "string",
      "enum": [
        "unauthenticated_network","authenticated_low_priv","authenticated_high_priv",
        "local_user","adjacent_network","physical","code_execution_required"
      ]
    },
    "preconditions": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id","description","verification_signal","match_kind","verification_method","severity"],
        "properties": {
          "id":                  { "type": "string" },
          "description":         { "type": "string" },
          "verification_signal": { "type": "string" },
          "match_kind":          { "type": "string", "enum": ["regex","equals","contains","version_lte","present"] },
          "match_value":         { "type": "string" },
          "verification_method": { "type": "string" },
          "severity":            { "type": "string", "enum": ["blocker","contributing"] }
        }
      }
    },
    "cvss_reconciliation": {
      "type": "object",
      "additionalProperties": false,
      "required": ["correct_vector","correct_score","correct_version","rationale"],
      "properties": {
        "correct_vector":  { "type": "string" },
        "correct_score":   { "type": "number" },
        "correct_version": { "type": "string", "enum": ["3.1","4.0","3.0","2.0"] },
        "rationale":       { "type": "string" },
        "disagreements": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["source","their_vector","disagreement"],
            "properties": {
              "source":       { "type": "string" },
              "their_vector": { "type": "string" },
              "disagreement": { "type": "string" }
            }
          }
        }
      }
    },
    "attack_chain_summary": { "type": "string" },
    "analyst_brief": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "title","what_is_it","attack_scenario","attack_vector_summary",
        "real_world_likelihood","affected_if"
      ],
      "properties": {
        "title":                 { "type": "string" },
        "what_is_it":            { "type": "string" },
        "attack_scenario":       { "type": "string" },
        "attack_vector_summary": { "type": "string" },
        "real_world_likelihood": { "type": "string" },
        "affected_if":           { "type": "string" },
        "not_affected_if":       { "type": "string" }
      }
    },
    "detection_signals":    { "type": "array", "items": { "type": "string" } },
    "rationale":            { "type": "string" },
    "confidence":           { "type": "string", "enum": ["high","medium","low"] }
  }
}`
