// Package pipeline ties the phases together for a single CVE+Asset pair:
//
//  1. Load CVE from store (or accept one directly)
//  2. Fetch/cache intrinsic analysis (Phase A — LLM or cache)
//  3. Load asset from inventory
//  4. Evaluate preconditions against asset signals (Phase B — deterministic)
//  5. Compute OPES score
//  6. Build finding + verification tasks
//  7. Write finding to store (visible to ASM UI)
//
// The runner is intentionally single-CVE-single-asset. Concurrency and
// job dispatch live above this layer (queue workers call Run in goroutines).
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/internal/modules/reasoners/contextual"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/intrinsic"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/priority/opes"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Store is the persistence surface the runner needs.
type Store interface {
	GetCVE(ctx context.Context, cveID string) (*schema.CVE, error)
	GetAsset(ctx context.Context, assetID string) (*schema.Asset, error)
	GetIntrinsicAnalysis(ctx context.Context, cveID string) (*schema.IntrinsicAnalysis, error)
	UpsertIntrinsicAnalysis(ctx context.Context, cveID, inputHash string, a *schema.IntrinsicAnalysis, cost float64) error
	UpsertFinding(ctx context.Context, f *schema.Finding) error
}

// Runner executes the full analysis pipeline.
type Runner struct {
	store     Store
	intrinsic *intrinsic.Reasoner
	opesConf  opes.Config
}

// New constructs a Runner.
func New(store Store, intrinsicReasoner *intrinsic.Reasoner, opesConf opes.Config) *Runner {
	return &Runner{
		store:     store,
		intrinsic: intrinsicReasoner,
		opesConf:  opesConf.WithDefaults(),
	}
}

// RunResult is the output of a single pipeline execution.
type RunResult struct {
	Finding   *schema.Finding
	Cached    bool   // true if intrinsic analysis was served from cache
	LLMModel  string
	CostUSD   float64
	ElapsedMS int64
}

// Run executes the full pipeline for a (CVE, asset) pair.
// refs are pre-fetched reference texts passed to Phase A.
func (r *Runner) Run(ctx context.Context, cveID, assetID string, refs []intrinsic.ResolvedRef, exploitation schema.ExploitationEvidence) (*RunResult, error) {
	start := time.Now()

	cve, err := r.store.GetCVE(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("get cve %s: %w", cveID, err)
	}
	if cve == nil {
		return nil, fmt.Errorf("cve %s not found", cveID)
	}

	asset, err := r.store.GetAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("get asset %s: %w", assetID, err)
	}
	if asset == nil {
		return nil, fmt.Errorf("asset %s not found", assetID)
	}

	// Phase A — intrinsic analysis (LLM or cache).
	analysis, err := r.intrinsic.Analyze(ctx, cve, refs)
	if err != nil {
		return nil, fmt.Errorf("intrinsic analysis: %w", err)
	}

	// Phase B — contextual evaluation.
	preconditions := contextual.Evaluate(analysis, asset)

	// OPES scoring.
	score := opes.Compute(opes.Input{
		CVE:           cve,
		Intrinsic:     analysis,
		Asset:         asset,
		Preconditions: preconditions,
		Exploitation:  exploitation,
		Now:           time.Now().UTC(),
	}, r.opesConf)

	// Build finding.
	finding := buildFinding(cve, asset, analysis, preconditions, score, exploitation)

	// Persist.
	if err := r.store.UpsertFinding(ctx, finding); err != nil {
		return nil, fmt.Errorf("upsert finding: %w", err)
	}

	return &RunResult{
		Finding:   finding,
		LLMModel:  analysis.LLMModel,
		ElapsedMS: time.Since(start).Milliseconds(),
	}, nil
}

// RunWithObjects is like Run but accepts pre-loaded CVE and asset objects,
// useful for the CLI and tests where objects are provided from JSON files.
func (r *Runner) RunWithObjects(
	ctx context.Context,
	cve *schema.CVE,
	asset *schema.Asset,
	refs []intrinsic.ResolvedRef,
	exploitation schema.ExploitationEvidence,
) (*RunResult, error) {
	start := time.Now()

	analysis, err := r.intrinsic.Analyze(ctx, cve, refs)
	if err != nil {
		return nil, fmt.Errorf("intrinsic analysis: %w", err)
	}

	preconditions := contextual.Evaluate(analysis, asset)

	score := opes.Compute(opes.Input{
		CVE:           cve,
		Intrinsic:     analysis,
		Asset:         asset,
		Preconditions: preconditions,
		Exploitation:  exploitation,
		Now:           time.Now().UTC(),
	}, r.opesConf)

	finding := buildFinding(cve, asset, analysis, preconditions, score, exploitation)

	if r.store != nil {
		_ = r.store.UpsertFinding(ctx, finding)
	}

	return &RunResult{
		Finding:   finding,
		LLMModel:  analysis.LLMModel,
		ElapsedMS: time.Since(start).Milliseconds(),
	}, nil
}

// ─────────────────────────── internals ─────────────────────────────────

func buildFinding(
	cve *schema.CVE,
	asset *schema.Asset,
	analysis *schema.IntrinsicAnalysis,
	preconditions schema.PreconditionEvalSet,
	score schema.OPESScore,
	exploitation schema.ExploitationEvidence,
) *schema.Finding {
	signalsHash := hashSignals(asset.Signals)
	inputHash := shortHash(cve.ID + analysis.PromptVersion)

	f := &schema.Finding{
		ID:                     newFindingID(cve.ID, asset.ID, inputHash, signalsHash),
		CVEID:                  cve.ID,
		AssetID:                asset.ID,
		IntrinsicInputHash:     inputHash,
		AssetSignalsHash:       signalsHash,
		EvaluatorVersion:       opes.Version,
		PreconditionsEvaluated: preconditions,
		OPES:                   score,
		CVSSReconciliation:     analysis.CVSSReconciliation,
		RecommendationText:     buildRecommendation(cve, analysis, score, preconditions),
		Status:                 schema.StatusOpen,
		CreatedAt:              time.Now().UTC(),
		UpdatedAt:              time.Now().UTC(),
	}

	// Attach verification tasks for unknown blocker preconditions.
	for _, e := range preconditions {
		if e.Status != schema.PreconditionUnknown {
			continue
		}
		kind := "manual"
		sig := e.Precondition.VerificationSignal
		if strings.HasPrefix(sig, "runtime_flags.") || strings.HasPrefix(sig, "container.") {
			kind = "container_inspect"
		}
		f.VerificationTasks = append(f.VerificationTasks, schema.VerificationTask{
			ID:                    "ver-" + f.ID[:8] + "-" + e.Precondition.ID,
			PreconditionID:        e.Precondition.ID,
			Summary:               "Verify: " + e.Precondition.Description,
			TaskKind:              kind,
			Command:               e.Precondition.VerificationMethod,
			ExpectedSignalPath:    e.Precondition.VerificationSignal,
			ExpectedMatch:         e.Precondition.MatchValue,
			ResolvesPreconditions: []string{e.Precondition.ID},
			Status:                "open",
			CreatedAt:             time.Now().UTC(),
		})
	}

	return f
}

func buildRecommendation(
	cve *schema.CVE,
	analysis *schema.IntrinsicAnalysis,
	score schema.OPESScore,
	preconditions schema.PreconditionEvalSet,
) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "OPES %.1f / %s — %s (confidence: %s).\n",
		score.Value, score.Category, score.Label, score.Confidence)

	if score.Override == "blocker_unsatisfied" {
		sb.WriteString("A blocker precondition is confirmed unsatisfied — exploit is not possible on this asset. Finding can be suppressed.\n")
	} else if score.Override == "unreachable" {
		sb.WriteString("Asset is isolated or unreachable by the required attacker class. Finding can be suppressed.\n")
	} else if score.Override == "kev_floor" {
		sb.WriteString("CISA/VulnCheck KEV: this CVE is confirmed exploited in the wild. Treat as P0 regardless of precondition status — verify and patch urgently.\n")
	} else if score.Dampener != "" {
		fmt.Fprintf(&sb, "%s\n", score.Dampener)
	}

	if len(analysis.CVSSReconciliation.Disagreements) > 0 {
		fmt.Fprintf(&sb, "CVSS reconciled to %.1f (%s); NVD/other source disagreement: %s\n",
			analysis.CVSSReconciliation.CorrectScore,
			analysis.CVSSReconciliation.CorrectVector,
			analysis.CVSSReconciliation.Rationale,
		)
	}

	unknown := preconditions.CountBlockers(schema.PreconditionUnknown)
	if unknown > 0 {
		fmt.Fprintf(&sb, "%d blocker precondition(s) cannot be verified from external signals — open verification tasks are attached.\n", unknown)
	}

	return strings.TrimRight(sb.String(), "\n")
}

func hashSignals(s schema.AssetSignals) string {
	b, _ := json.Marshal(s)
	return shortHash(string(b))
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func newFindingID(cveID, assetID, inputHash, signalsHash string) string {
	return shortHash(cveID + "|" + assetID + "|" + inputHash + "|" + signalsHash)
}
