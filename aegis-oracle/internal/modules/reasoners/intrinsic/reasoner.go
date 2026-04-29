// Package intrinsic implements Phase A: given a CVE + enrichment bundle,
// call the LLM with prompt v1 and return a structured IntrinsicAnalysis.
//
// This is the only package that invokes the LLM. Everything downstream
// (contextual evaluation, OPES scoring) is deterministic.
//
// Caching: if a cached analysis exists in Postgres for the same
// (cve_id, input_hash, prompt_version), it is returned without an LLM
// call. input_hash = sha256(description + cvss_vectors + reference_texts).
package intrinsic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/your-org/aegis-oracle/internal/knowledgebase"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/intrinsic/prompts"
	"github.com/your-org/aegis-oracle/pkg/module"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Store is the persistence interface required by the reasoner.
type Store interface {
	GetIntrinsicAnalysis(ctx context.Context, cveID string) (*schema.IntrinsicAnalysis, error)
	UpsertIntrinsicAnalysis(ctx context.Context, cveID, inputHash string, a *schema.IntrinsicAnalysis, costUSD float64) error
}

// Reasoner runs Phase A analysis for a single CVE.
type Reasoner struct {
	llm    module.LLMProvider
	store  Store
	kb     *knowledgebase.KB
	tmpl   *template.Template
	schema any // parsed JSON schema for structured output
}

// New constructs a Reasoner. kb may be nil (priors are skipped).
func New(llm module.LLMProvider, store Store, kb *knowledgebase.KB) (*Reasoner, error) {
	tmpl, err := template.New("v1").Parse(prompts.V1)
	if err != nil {
		return nil, fmt.Errorf("parse prompt template: %w", err)
	}
	var outputSchema any
	if err := json.Unmarshal([]byte(prompts.V1OutputSchema), &outputSchema); err != nil {
		return nil, fmt.Errorf("parse output schema: %w", err)
	}
	return &Reasoner{llm: llm, store: store, kb: kb, tmpl: tmpl, schema: outputSchema}, nil
}

// Analyze returns an IntrinsicAnalysis for the given CVE.
// If a cached analysis exists with the same input hash and prompt version
// it is returned without an LLM call.
func (r *Reasoner) Analyze(ctx context.Context, cve *schema.CVE, refs []ResolvedRef) (*schema.IntrinsicAnalysis, error) {
	inputHash := computeInputHash(cve, refs)

	// Cache check.
	if r.store != nil {
		cached, err := r.store.GetIntrinsicAnalysis(ctx, cve.ID)
		if err == nil && cached != nil && cached.PromptVersion == prompts.V1Version {
			return cached, nil
		}
	}

	inputs := r.buildInputs(cve, refs)
	rendered, err := r.renderPrompt(inputs)
	if err != nil {
		return nil, fmt.Errorf("render prompt: %w", err)
	}

	resp, err := r.llm.CompleteJSON(ctx, module.JSONRequest{
		System:    "You are a senior vulnerability triage analyst. Respond only with the JSON analysis tool call.",
		User:      rendered,
		Schema:    r.schema,
		MaxTokens: 4096,
	})
	if err != nil {
		return nil, fmt.Errorf("llm: %w", err)
	}

	var analysis schema.IntrinsicAnalysis
	if err := json.Unmarshal([]byte(resp.Content), &analysis); err != nil {
		return nil, fmt.Errorf("decode analysis: %w\nraw: %s", err, resp.Content)
	}
	analysis.CVEID = cve.ID
	analysis.PromptVersion = prompts.V1Version
	analysis.LLMModel = resp.Model

	// Estimate cost (rough: $3/$15 per M input/output tokens for Sonnet).
	costUSD := float64(resp.TokenUsage.Input)*3.0/1_000_000 + float64(resp.TokenUsage.Output)*15.0/1_000_000

	if r.store != nil {
		if err := r.store.UpsertIntrinsicAnalysis(ctx, cve.ID, inputHash, &analysis, costUSD); err != nil {
			// Non-fatal — log but continue; analysis is correct.
			_ = err
		}
	}

	return &analysis, nil
}

// ResolvedRef is a reference URL with its fetched text content.
type ResolvedRef struct {
	URL        string
	SourceKind string
	Excerpt    string // trimmed text, ≤ 8000 chars
}

// ─────────────────────────── internals ─────────────────────────────────

func (r *Reasoner) buildInputs(cve *schema.CVE, refs []ResolvedRef) prompts.V1Inputs {
	in := prompts.V1Inputs{
		CVEID:       cve.ID,
		PublishedAt: cve.PublishedAt.Format(time.DateOnly),
		ModifiedAt:  cve.ModifiedAt.Format(time.DateOnly),
		Description: cve.Description,
		CWEs:        cve.CWEs,
	}

	for _, v := range cve.CVSSVectors {
		in.CVSSVectors = append(in.CVSSVectors, prompts.V1CVSSVector{
			Source:  v.Source,
			Version: v.Version,
			Vector:  v.Vector,
			Score:   v.Score,
		})
	}

	// CPE summary: first 5 URIs.
	cpeSummary := make([]string, 0, 5)
	for i, c := range cve.CPEs {
		if i >= 5 {
			break
		}
		cpeSummary = append(cpeSummary, c.URI)
	}
	in.CPESummary = strings.Join(cpeSummary, ", ")
	if in.CPESummary == "" {
		in.CPESummary = "(none)"
	}

	if cve.EPSS != nil {
		in.EPSSScore = fmt.Sprintf("%.4f", cve.EPSS.Score)
		in.EPSSPercentile = fmt.Sprintf("%.2f%%", cve.EPSS.Percentile*100)
	} else {
		in.EPSSScore = "unknown"
		in.EPSSPercentile = "unknown"
	}

	in.InKEV = cve.InKEV
	if cve.KEVAddedOn != nil {
		in.KEVAddedOn = cve.KEVAddedOn.Format(time.DateOnly)
	}

	if cve.POCCount == 0 {
		in.POCSummary = "no public PoCs indexed"
	} else {
		in.POCSummary = fmt.Sprintf("%d public PoC(s) indexed", cve.POCCount)
	}
	if cve.NucleiTemplate != "" {
		in.POCSummary += fmt.Sprintf("; nuclei template: %s", cve.NucleiTemplate)
	}

	// KB priors.
	if r.kb != nil {
		for _, p := range r.kb.CWEsByID(cve.CWEs) {
			prof := prompts.V1CWEProfile{
				CWEID:   p.CWEID,
				Name:    p.Name,
				Summary: p.CuratorNotes,
			}
			for _, a := range p.ExploitArchetypes {
				prof.Archetypes = append(prof.Archetypes, prompts.V1Archetype{
					Name:    a.Name,
					Summary: a.Summary,
				})
			}
			in.CWEProfiles = append(in.CWEProfiles, prof)
		}

		// Detect ecosystem from CPEs / description for pattern matching.
		ecosystem := detectEcosystem(cve)
		for _, dp := range r.kb.PatternsForCWEs(cve.CWEs, ecosystem, "") {
			pat := prompts.V1DevPattern{
				PatternID: dp.PatternID,
				Ecosystem: dp.Ecosystem,
				Framework: dp.Framework,
				Summary:   dp.Summary,
			}
			for _, p := range dp.ExploitPreconditions {
				pat.Preconditions = append(pat.Preconditions, prompts.V1Precondition{
					ID:                 p.ID,
					VerificationSignal: p.VerificationSignal,
					Severity:           string(p.Severity),
					Description:        p.Description,
				})
			}
			in.DevPatterns = append(in.DevPatterns, pat)
		}
	}

	for _, ref := range refs {
		in.References = append(in.References, prompts.V1Reference{
			SourceKind:     ref.SourceKind,
			URL:            ref.URL,
			ContentExcerpt: truncate(ref.Excerpt, 8000),
		})
	}

	return in
}

func (r *Reasoner) renderPrompt(in prompts.V1Inputs) (string, error) {
	var buf bytes.Buffer
	if err := r.tmpl.Execute(&buf, in); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func computeInputHash(cve *schema.CVE, refs []ResolvedRef) string {
	h := sha256.New()
	h.Write([]byte(cve.ID))
	h.Write([]byte(cve.Description))
	for _, v := range cve.CVSSVectors {
		h.Write([]byte(v.Source + v.Vector))
	}
	for _, ref := range refs {
		h.Write([]byte(ref.URL + ref.Excerpt[:min(len(ref.Excerpt), 512)]))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func detectEcosystem(cve *schema.CVE) string {
	desc := strings.ToLower(cve.Description)
	for _, cpe := range cve.CPEs {
		uri := strings.ToLower(cpe.URI)
		switch {
		case strings.Contains(uri, "node.js") || strings.Contains(uri, "node_js"):
			return "nodejs"
		case strings.Contains(uri, "python"):
			return "python"
		case strings.Contains(uri, "java"):
			return "java"
		case strings.Contains(uri, "go_lang") || strings.Contains(uri, "golang"):
			return "go"
		}
	}
	switch {
	case strings.Contains(desc, "node.js") || strings.Contains(desc, "nodejs"):
		return "nodejs"
	case strings.Contains(desc, "python"):
		return "python"
	case strings.Contains(desc, "java"):
		return "java"
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n[...truncated]"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
