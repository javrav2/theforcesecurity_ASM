// aegis-oracle is the Aegis Oracle daemon.
//
// Usage:
//
//	aegis-oracle -config config.yaml
//
// On startup it:
//  1. Loads and validates the knowledge base
//  2. Opens the Postgres connection (shared ASM database)
//  3. Applies pending migrations (oracle schema only)
//  4. Initialises the LLM provider
//  5. Starts the analysis HTTP API on :8742 (configurable)
//
// The HTTP API exposes:
//
//	POST /analyze          — run the full pipeline for a (cve_id, asset_id) pair
//	GET  /cve/:id          — Phase-A intrinsic analysis for a CVE (no asset required;
//	                         ad-hoc lookups, "what is this CVE?" questions, ASM batch
//	                         enrichment when an asset isn't yet known)
//	GET  /findings         — list open findings (queryable by cve_id, asset_id, category)
//	GET  /findings/:id     — single finding detail
//	POST /findings/:id/suppress  — suppress a finding
//	GET  /health           — liveness probe
//	GET  /kb/stats         — knowledge base summary
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/your-org/aegis-oracle/internal/knowledgebase"
	"github.com/your-org/aegis-oracle/internal/llm"
	"github.com/your-org/aegis-oracle/internal/modules/enrichers"
	"github.com/your-org/aegis-oracle/internal/modules/ingest"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/contextual"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/intrinsic"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/priority/opes"
	"github.com/your-org/aegis-oracle/internal/pipeline"
	"github.com/your-org/aegis-oracle/internal/react"
	reacttools "github.com/your-org/aegis-oracle/internal/react/tools"
	"github.com/your-org/aegis-oracle/internal/store/pg"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

type Config struct {
	DB            pg.Config  `yaml:"db"`
	LLM           llm.Config `yaml:"llm"`
	Knowledgebase struct {
		Root string `yaml:"root"`
	} `yaml:"knowledgebase"`
	OPES           opes.Config `yaml:"opes"`
	PDCPKey        string      `yaml:"pdcp_api_key"`        // ProjectDiscovery Cloud Platform key (optional)
	VulnCheckToken string      `yaml:"vulncheck_api_token"` // optional; enables VulnCheck Exploit Intelligence/XDB
	NVDKey         string      `yaml:"nvd_api_key"`         // optional; raises NVD rate limit for on-demand ingest
	Log            struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"log"`
	Addr string `yaml:"addr"`
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "Path to config YAML")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg)
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Knowledge base.
	kbRoot := cfg.Knowledgebase.Root
	if kbRoot == "" {
		kbRoot = "knowledgebase"
	}
	kb, err := knowledgebase.Load(kbRoot)
	if err != nil {
		slog.Error("failed to load knowledge base", "error", err)
		os.Exit(1)
	}
	if err := kb.Validate(); err != nil {
		slog.Error("knowledge base validation failed", "error", err)
		os.Exit(1)
	}
	stats := kb.Stats()
	slog.Info("knowledge base loaded",
		"cwe_profiles", stats.CWEProfiles,
		"dev_patterns", stats.DevPatterns)

	// Postgres.
	store, err := pg.New(ctx, cfg.DB)
	if err != nil {
		slog.Error("postgres connection failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	slog.Info("postgres connected", "dsn_prefix", safeDSN(cfg.DB.DSN))

	// LLM provider — optional at process start: without API keys the daemon
	// still binds :8742 and /health returns 200 with llm_ready=false so
	// docker-compose curl checks stop failing with "connection reset"
	// (formerly we os.Exit(1) before ListenAndServe).
	llmReady := true
	provider, err := llm.New(cfg.LLM)
	if err != nil {
		slog.Warn("oracle starting without a working LLM — set ANTHROPIC_API_KEY or OPENAI_API_KEY in the environment; /cve and /chat need a key", "error", err)
		provider = llm.Disabled(err)
		llmReady = false
	} else {
		slog.Info("llm provider ready", "provider", cfg.LLM.Provider)
	}

	// Phase A reasoner.
	reasoner, err := intrinsic.New(provider, store, kb)
	if err != nil {
		slog.Error("intrinsic reasoner init failed", "error", err)
		os.Exit(1)
	}

	// Pipeline runner.
	runner := pipeline.New(store, reasoner, cfg.OPES)

	// On-demand CVE ingester. Backs both the /cve/{id} lookup and the
	// /analyze endpoint so a brand-new CVE id (one never seen by the
	// nightly merge pipeline) is fetched from vulnx/NVD on first use,
	// persisted to oracle.cves, and analysed without manual seeding.
	ingester := ingest.New(store, cfg.PDCPKey, cfg.NVDKey)

	// ReAct loop — wires Oracle tools to the LLM for iterative reasoning.
	toolRegistry := reacttools.BuildRegistry(reacttools.Deps{
		Store:          store,
		Runner:         runner,
		KB:             kb,
		PDCPKey:        cfg.PDCPKey, // optional; higher vulnx rate limits
		VulnCheckToken: cfg.VulnCheckToken,
	})
	reactLoop := react.New(react.Config{
		LLM:           provider,
		Tools:         toolRegistry,
		MaxIterations: 10,
		MaxTokens:     2048,
	})

	// HTTP API.
	addr := cfg.Addr
	if addr == "" {
		addr = ":8742"
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      buildMux(runner, reasoner, store, kb, reactLoop, ingester, cfg.VulnCheckToken, cfg.OPES, llmReady),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 180 * time.Second,
	}

	go func() {
		slog.Info("aegis-oracle listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
}

// ─────────────────────────── HTTP handlers ──────────────────────────────

func buildMux(
	runner *pipeline.Runner,
	reasoner *intrinsic.Reasoner,
	store *pg.Store,
	kb *knowledgebase.KB,
	loop *react.Loop,
	ingester *ingest.Ingester,
	vulnCheckToken string,
	opesCfg opes.Config,
	llmReady bool,
) http.Handler {
	mux := http.NewServeMux()

	// POST /chat  body: {"question":"..."}
	//
	// Runs the ReAct loop: the LLM iteratively selects tools (lookup_cve,
	// get_asset, check_epss_kev, search_exploit_evidence, lookup_kb_pattern,
	// get_open_findings, run_analysis) until it produces a final answer.
	// This is the natural-language entry point — use /analyze for direct calls.
	mux.HandleFunc("POST /chat", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Question string `json:"question"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		if req.Question == "" {
			writeError(w, http.StatusBadRequest, "question is required")
			return
		}

		result, err := loop.Run(r.Context(), req.Question)
		if err != nil {
			slog.Error("react loop failed", "error", err)
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"answer":     result.Answer,
			"finding":    result.Finding,
			"iterations": result.Iterations,
			"elapsed_ms": result.ElapsedMS,
			"trace":      result.Trace,
		})
	})

	// POST /analyze
	//
	// Body shapes (the endpoint accepts either):
	//
	//   1. {"cve_id":"CVE-...","asset_id":"asset-..."}
	//      The asset is loaded from Oracle's own assets table. Use when
	//      the asset is already known to Oracle (asset sync done elsewhere).
	//
	//   2. {"cve_id":"CVE-...","asset":{...full schema.Asset...}}
	//      The asset is supplied inline. Use this from external systems
	//      (the ASM platform) that own asset state and don't want to mirror
	//      it into Oracle's DB. The asset is passed straight to the pipeline
	//      via RunWithObjects — no Oracle-side write.
	//
	// If the CVE is not in oracle.cves, it is fetched on demand from vulnx
	// (preferred) or NVD (fallback), persisted, and analysed. Subsequent
	// calls hit the cached row.
	mux.HandleFunc("POST /analyze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CVEID   string        `json:"cve_id"`
			AssetID string        `json:"asset_id"`
			Asset   *schema.Asset `json:"asset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		req.CVEID = strings.ToUpper(strings.TrimSpace(req.CVEID))
		if req.CVEID == "" {
			writeError(w, http.StatusBadRequest, "cve_id is required")
			return
		}
		if req.AssetID == "" && req.Asset == nil {
			writeError(w, http.StatusBadRequest, "either asset_id or asset is required")
			return
		}

		// Ensure the CVE record exists in our store before running analysis.
		// This auto-ingests if missing.
		cve, _, err := ingester.EnsureCVE(r.Context(), req.CVEID)
		if err != nil {
			slog.Error("ensure cve", "cve", req.CVEID, "error", err)
			writeError(w, http.StatusBadGateway, "cve ingest failed: "+err.Error())
			return
		}
		if cve == nil {
			writeError(w, http.StatusNotFound, "cve not found upstream (vulnx/nvd)")
			return
		}

		exploitation := buildExploitationEvidence(r.Context(), req.CVEID, vulnCheckToken)

		var result *pipeline.RunResult
		if req.Asset != nil {
			// Inline asset path: feed the analysis directly without writing
			// the asset to Oracle's DB. The caller (ASM) is the source of
			// truth for asset state.
			if req.Asset.ID == "" {
				writeError(w, http.StatusBadRequest, "asset.asset_id is required when sending inline asset")
				return
			}
			result, err = runner.RunWithObjects(r.Context(), cve, req.Asset, nil, exploitation)
		} else {
			result, err = runner.Run(r.Context(), req.CVEID, req.AssetID, nil, exploitation)
		}
		if err != nil {
			slog.Error("pipeline run failed",
				"cve", req.CVEID, "asset_id", req.AssetID,
				"asset_inline", req.Asset != nil, "error", err)
			// Surface "asset not found" as 404 so the caller can decide
			// whether to retry with an inline payload.
			if strings.Contains(err.Error(), "not found") {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"finding":    result.Finding,
			"llm_model":  result.LLMModel,
			"elapsed_ms": result.ElapsedMS,
		})
	})

	// POST /analyze-finding
	//
	// ASM-native vulnerability analysis for findings that may not have a CVE:
	// exposed datastores, leaked secrets, cloud misconfigurations, debug
	// endpoints, and other scanner/manual findings. The current implementation
	// uses deterministic classifiers to produce an intrinsic analysis, then
	// runs the same contextual evaluator and OPES scorer used by CVE findings.
	mux.HandleFunc("POST /analyze-finding", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Vulnerability schema.GenericVulnerability `json:"vulnerability"`
			Asset         *schema.Asset               `json:"asset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		req.Vulnerability.Title = strings.TrimSpace(req.Vulnerability.Title)
		if req.Vulnerability.Title == "" {
			writeError(w, http.StatusBadRequest, "vulnerability.title is required")
			return
		}
		if req.Asset == nil || req.Asset.ID == "" {
			writeError(w, http.StatusBadRequest, "asset.asset_id is required")
			return
		}

		result := analyzeGenericFinding(req.Vulnerability, req.Asset, opesCfg)
		writeJSON(w, http.StatusOK, map[string]any{
			"finding":         result,
			"analysis_status": "complete",
		})
	})

	// GET /cve/{id}
	//
	// Phase-A-only CVE analysis. Returns the IntrinsicAnalysis (analyst brief,
	// attack path class, preconditions, CVSS reconciliation) plus the canonical
	// CVE record and observed exploitation evidence. No asset required.
	//
	// Intended for:
	//   • ad-hoc analyst questions ("what is CVE-X?") — fast, deterministic,
	//     and cached on the (cve_id, prompt_version) pair
	//   • ASM batch enrichment when the asset graph isn't yet linked
	//   • a CVE-only "Quick Lookup" UI
	//
	// Uses the same Phase A reasoner as /analyze — cached output is reused
	// across endpoints so the first /analyze call after a /cve lookup is
	// effectively free.
	mux.HandleFunc("GET /cve/{id}", func(w http.ResponseWriter, r *http.Request) {
		cveID := strings.ToUpper(r.PathValue("id"))
		if cveID == "" {
			writeError(w, http.StatusBadRequest, "cve id is required")
			return
		}

		// Auto-ingest if the CVE isn't in the store yet. First call for a
		// fresh id pays a ~1-3s upstream fetch; subsequent calls are cached.
		cve, ingested, err := ingester.EnsureCVE(r.Context(), cveID)
		if err != nil {
			slog.Error("ensure cve", "cve", cveID, "error", err)
			writeError(w, http.StatusBadGateway, "cve ingest failed: "+err.Error())
			return
		}
		if cve == nil {
			writeError(w, http.StatusNotFound, "cve not found in oracle store or upstream (vulnx/nvd)")
			return
		}
		if ingested {
			slog.Info("cve served via on-demand ingest", "cve", cveID,
				"primary_source", cve.PrimarySource)
		}

		// Exploitation evidence: same enrichment path as /analyze. This is
		// observed evidence (KEV, VulnCheck XDB, Metasploit, etc.), not asset
		// reachability. Build it before Phase A so an LLM/provider failure can
		// still return useful deterministic intelligence.
		exploitation := buildExploitationEvidence(r.Context(), cveID, vulnCheckToken)

		// Phase A — intrinsic analysis. Cached when available.
		analysis, err := reasoner.Analyze(r.Context(), cve, nil)
		if err != nil {
			slog.Error("intrinsic analyze", "cve", cveID, "error", err)
			writeJSON(w, http.StatusOK, map[string]any{
				"cve":             cve,
				"analysis":        nil,
				"analysis_status": "failed",
				"analysis_error":  "CVE intelligence was found, but LLM analysis could not be completed: " + err.Error(),
				"exploitation":    exploitation,
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"cve":             cve,
			"analysis":        analysis,
			"analysis_status": "complete",
			"exploitation":    exploitation,
		})
	})

	// GET /findings?cve_id=...&asset_id=...&category=P0
	mux.HandleFunc("GET /findings", func(w http.ResponseWriter, r *http.Request) {
		cveID := r.URL.Query().Get("cve_id")
		assetID := r.URL.Query().Get("asset_id")
		findings, err := store.GetOpenFindings(r.Context(), cveID, assetID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "count": len(findings)})
	})

	// GET /health
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if llmReady {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "llm_ready": true})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "degraded",
			"llm_ready": false,
			"detail":    "Set ANTHROPIC_API_KEY or OPENAI_API_KEY (and rebuild/restart) for Phase A analysis and /chat",
		})
	})

	// GET /kb/stats
	mux.HandleFunc("GET /kb/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, kb.Stats())
	})

	return mux
}

// ─────────────────────────── helpers ────────────────────────────────────

func loadConfig(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return cfg, err
	}
	// Allow env var overrides for secrets.
	if v := os.Getenv("ORACLE_DB_DSN"); v != "" {
		cfg.DB.DSN = v
	}
	if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" {
		cfg.LLM.Anthropic.APIKey = v
	}
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		cfg.LLM.OpenAI.APIKey = v
	}
	if v := os.Getenv("PDCP_API_KEY"); v != "" {
		cfg.PDCPKey = v
	}
	if v := os.Getenv("VULNCHECK_API_TOKEN"); v != "" {
		cfg.VulnCheckToken = v
	}
	if v := os.Getenv("NVD_API_KEY"); v != "" {
		cfg.NVDKey = v
	}
	return cfg, nil
}

func buildExploitationEvidence(ctx context.Context, cveID, vulnCheckToken string) schema.ExploitationEvidence {
	ev := schema.ExploitationEvidence{}
	ext := enrichers.FetchAllWithVulnCheck(ctx, cveID, vulnCheckToken)
	enrichers.Apply(ext, &ev)
	return ev
}

func analyzeGenericFinding(v schema.GenericVulnerability, asset *schema.Asset, cfg opes.Config) schema.GenericFindingAnalysis {
	class, analysis, exploitation, detectionSignals := classifyGenericFinding(v)
	preconditions := contextual.Evaluate(analysis, asset)
	score := opes.Compute(opes.Input{
		Intrinsic:     analysis,
		Asset:         asset,
		Preconditions: preconditions,
		Exploitation:  exploitation,
		Now:           time.Now().UTC(),
	}, cfg)
	return schema.GenericFindingAnalysis{
		ID:                       genericFindingID(v, asset),
		VulnerabilityID:          v.ID,
		AssetID:                  asset.ID,
		FindingClass:             class,
		OPES:                     score,
		AnalystBrief:             analysis.AnalystBrief,
		AttackPathClass:          analysis.AttackPathClass,
		LateralMovementPotential: analysis.LateralMovementPotential,
		PreconditionsEvaluated:   preconditions,
		RecommendationText:       buildGenericRecommendation(v, asset, analysis, score, preconditions),
		DetectionSignals:         detectionSignals,
	}
}

func classifyGenericFinding(v schema.GenericVulnerability) (string, *schema.IntrinsicAnalysis, schema.ExploitationEvidence, []string) {
	text := strings.ToLower(strings.Join([]string{
		v.Title, v.Description, v.Evidence, v.ProofOfConcept, v.DetectedBy,
		v.TemplateID, strings.Join(v.Tags, " "),
	}, " "))
	for k, val := range v.Metadata {
		text += " " + strings.ToLower(k) + " " + strings.ToLower(fmt.Sprint(val))
	}

	base := &schema.IntrinsicAnalysis{
		CVEID:                    v.CVEID,
		RemoteTriggerability:     schema.TriggerYes,
		ExploitComplexity:        schema.ComplexityLow,
		AttackerCapability:       schema.AttackerUnauthenticatedNetwork,
		AttackPathClass:          schema.AttackPathExploitPublicFacing,
		LateralMovementPotential: schema.LateralMovementLow,
		Confidence:               schema.ConfidenceMedium,
		PromptVersion:            "generic/deterministic/v1",
		LLMModel:                 "deterministic",
		CVSSReconciliation: schema.CVSSReconciliation{
			CorrectVector:  genericVector(v),
			CorrectScore:   genericScore(v),
			CorrectVersion: "3.1",
			Rationale:      "Derived from ASM finding evidence and asset exposure rather than a CVE-specific advisory.",
		},
	}
	ev := schema.ExploitationEvidence{}
	signals := []string{}

	switch {
	case containsAny(text, "mongodb", "redis", "elasticsearch", "postgres", "mysql", "mssql", "couchdb", "cassandra", "database", "datastore"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Internet-Exposed Datastore: Unauthenticated or Risky Data-Service Exposure",
			WhatIsIt:            "The finding indicates a datastore or database service is reachable where direct internet exposure is dangerous and often exploitable without application-layer controls.",
			AttackScenario:      "An attacker scans for the exposed port, connects with a native client, enumerates metadata, and, when authentication is absent or weak, reads or modifies data directly.",
			AttackVectorSummary: "Remote network attacker reaches the datastore service directly.",
			RealWorldLikelihood: "High when the port is internet-facing; exposed datastores are heavily scanned and frequently abused for theft or extortion.",
			AffectedIf:          "Affected when the database port is reachable from untrusted networks or anonymous/default authentication is accepted.",
			NotAffectedIf:       "Not affected if firewall rules restrict access to trusted application hosts and authentication is enforced.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.LateralMovementPotential = schema.LateralMovementMedium
		base.Preconditions = []schema.Precondition{internetFacingPrecondition(), portPresentPrecondition()}
		if containsAny(text, "read_me_to_recover", "ransom", "bitcoin", "onionmail", "recover your data") {
			ev.RansomwareAssociated = true
			ev.ObservationSources = append(ev.ObservationSources, "asm_ransom_marker")
			signals = append(signals, "ransomware/extortion marker in datastore evidence")
		}
	case containsAny(text, "secret", "token", "credential", "api key", "accountkey", "client_secret", "azurewebjobsstorage", "cosmos", "storage key"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Leaked Credential: Downstream Service Access from Exposed Secret",
			WhatIsIt:            "The finding contains credential material or secret-shaped evidence that may authenticate to a downstream cloud, identity, source-code, or data service.",
			AttackScenario:      "An attacker retrieves the exposed secret, validates it with a read-only or metadata request, then uses the granted permissions to enumerate data or pivot into related services.",
			AttackVectorSummary: "Remote attacker obtains a secret from exposed application, repository, or artifact content.",
			RealWorldLikelihood: "High when the secret is verified or appears in public content; automated secret hunters continuously scan these sources.",
			AffectedIf:          "Affected when the secret is live and grants access beyond a single low-value test resource.",
			NotAffectedIf:       "Not affected if the secret is revoked, scoped to harmless test data, and all dependent sessions/keys have been rotated.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.AttackPathClass = schema.AttackPathValidCredentials
		base.AttackerCapability = schema.AttackerUnauthenticatedNetwork
		base.LateralMovementPotential = schema.LateralMovementHigh
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
		if !containsAny(text, "verified true", "live true", "secret_verified true", "confirmed live") {
			base.Preconditions = append(base.Preconditions, secretLivePrecondition())
		}
	case containsAny(text, "blob", "bucket", "public storage", "publicaccess", "s3", "gcs", "azure storage"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Public Storage Exposure: Anonymous Access to Cloud Object Data",
			WhatIsIt:            "The finding indicates cloud object storage can be accessed anonymously or with overly broad credentials.",
			AttackScenario:      "An attacker discovers the storage endpoint, lists or retrieves exposed objects, and extracts sensitive documents, packages, or embedded credentials.",
			AttackVectorSummary: "Remote unauthenticated attacker reaches a public storage endpoint.",
			RealWorldLikelihood: "High for public containers and buckets because they are easy to enumerate and commonly indexed by scanners.",
			AffectedIf:          "Affected when public read/list is enabled or a leaked key grants broad storage permissions.",
			NotAffectedIf:       "Not affected when anonymous access is disabled and access is limited by identity, network, and least privilege.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.LateralMovementPotential = schema.LateralMovementMedium
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
	case containsAny(text, "debug", "tester", "environment", "env", "config", "settings", "function app", "azurewebsites"):
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "Public Debug Endpoint: Runtime Configuration Disclosure",
			WhatIsIt:            "The finding indicates an endpoint discloses runtime configuration, environment variables, or parsed application settings.",
			AttackScenario:      "An attacker requests the endpoint anonymously, extracts credentials and service endpoints, then validates downstream access or chains through cloud identity.",
			AttackVectorSummary: "Remote unauthenticated attacker accesses a public diagnostic or test endpoint.",
			RealWorldLikelihood: "High when the endpoint is internet-facing and returns secrets or cloud configuration.",
			AffectedIf:          "Affected when debug/test routes are deployed in production or unauthenticated function routes expose environment data.",
			NotAffectedIf:       "Not affected when diagnostic routes are removed or protected and all previously disclosed secrets are rotated.",
			ExploitabilityScore: 4.0,
			ExploitabilityTier:  "opportunistic",
		}
		base.LateralMovementPotential = schema.LateralMovementHigh
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
	default:
		base.AnalystBrief = schema.AnalystBrief{
			Title:               "ASM Finding: Practical Exploitability Requires Context Review",
			WhatIsIt:            "This is an ASM-native security finding without a CVE identifier. Oracle can still evaluate it using detector evidence and asset exposure.",
			AttackScenario:      "An attacker follows the detected exposure path and attempts to turn the observed condition into access, data exposure, or service disruption.",
			AttackVectorSummary: "Attacker path depends on the detected finding class and reachable asset surface.",
			RealWorldLikelihood: "Medium until the finding is classified with stronger evidence or validated by a scanner/operator.",
			AffectedIf:          "Affected when the detector evidence accurately reflects a reachable, exploitable condition on this asset.",
			NotAffectedIf:       "Not affected when the evidence is stale, unreachable, or blocked by compensating controls.",
			ExploitabilityScore: 3.0,
			ExploitabilityTier:  "moderate",
		}
		base.RemoteTriggerability = schema.TriggerConditional
		base.ExploitComplexity = schema.ComplexityMedium
		base.AttackPathClass = schema.AttackPathUnknown
		base.Preconditions = []schema.Precondition{internetFacingPrecondition()}
	}
	if v.CWEID != "" {
		base.Rationale = "Classified from ASM finding evidence and CWE " + v.CWEID + "."
	} else {
		base.Rationale = "Classified from ASM finding evidence."
	}
	if v.Evidence != "" {
		signals = append(signals, "finding evidence present")
	}
	if v.DetectedBy != "" {
		signals = append(signals, "detected_by="+v.DetectedBy)
	}
	return genericClass(text), base, ev, signals
}

func genericClass(text string) string {
	switch {
	case containsAny(text, "mongodb", "redis", "elasticsearch", "postgres", "mysql", "mssql", "database", "datastore"):
		return "exposed_datastore"
	case containsAny(text, "secret", "token", "credential", "api key", "client_secret", "accountkey"):
		return "leaked_secret"
	case containsAny(text, "blob", "bucket", "public storage", "s3", "gcs", "azure storage"):
		return "public_storage"
	case containsAny(text, "debug", "tester", "environment", "config", "settings", "function app"):
		return "public_debug_endpoint"
	default:
		return "generic_asm_finding"
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func internetFacingPrecondition() schema.Precondition {
	return schema.Precondition{
		ID:                 "internet-facing",
		Description:        "The affected service or endpoint is reachable from an untrusted network.",
		VerificationSignal: "network.internet_facing",
		MatchKind:          "equals",
		MatchValue:         "true",
		VerificationMethod: "Confirm asset exposure and firewall/load-balancer path.",
		Severity:           schema.PreconditionBlocker,
	}
}

func portPresentPrecondition() schema.Precondition {
	return schema.Precondition{
		ID:                 "service-port-open",
		Description:        "The relevant datastore or management service port is open.",
		VerificationSignal: "network.open_ports",
		MatchKind:          "present",
		VerificationMethod: "Confirm port scan or service inventory shows the service as open.",
		Severity:           schema.PreconditionContributing,
	}
}

func secretLivePrecondition() schema.Precondition {
	return schema.Precondition{
		ID:                 "secret-live",
		Description:        "The recovered credential is still accepted by the downstream service.",
		VerificationSignal: "extra.secret_verified",
		MatchKind:          "equals",
		MatchValue:         "true",
		VerificationMethod: "Perform only a read-only or metadata validation request against the downstream service.",
		Severity:           schema.PreconditionBlocker,
	}
}

func genericVector(v schema.GenericVulnerability) string {
	if strings.HasPrefix(v.CVSSVector, "CVSS:") {
		return v.CVSSVector
	}
	return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
}

func genericScore(v schema.GenericVulnerability) float64 {
	if v.CVSSScore > 0 {
		return v.CVSSScore
	}
	switch strings.ToLower(v.Severity) {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 3.0
	default:
		return 6.5
	}
}

func genericFindingID(v schema.GenericVulnerability, asset *schema.Asset) string {
	h := sha256.Sum256([]byte(v.ID + "|" + v.Title + "|" + v.Evidence + "|" + asset.ID))
	return "asm-" + hex.EncodeToString(h[:])[:20]
}

func buildGenericRecommendation(v schema.GenericVulnerability, asset *schema.Asset, analysis *schema.IntrinsicAnalysis, score schema.OPESScore, preconditions schema.PreconditionEvalSet) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[%s] %s — OPES %.1f (confidence: %s)\n", score.Category, score.Label, score.Value, score.Confidence)
	if asset != nil {
		fmt.Fprintf(&sb, "Asset: %s (%s)\n", asset.Hostname, asset.ID)
	}
	if analysis != nil {
		sb.WriteString("\nATTACK PATH\n")
		sb.WriteString(analysis.AnalystBrief.AttackScenario + "\n")
		sb.WriteString("\nAFFECTED IF\n")
		sb.WriteString(analysis.AnalystBrief.AffectedIf + "\n")
		if analysis.AnalystBrief.NotAffectedIf != "" {
			sb.WriteString("\nNOT AFFECTED IF\n")
			sb.WriteString(analysis.AnalystBrief.NotAffectedIf + "\n")
		}
	}
	if len(preconditions) > 0 {
		sb.WriteString("\nVERIFICATION\n")
		for _, p := range preconditions {
			fmt.Fprintf(&sb, "- %s: %s (%s)\n", p.Precondition.ID, p.Status, p.Reason)
		}
	}
	if v.Remediation != "" {
		sb.WriteString("\nREMEDIATION\n")
		sb.WriteString(v.Remediation + "\n")
	}
	return sb.String()
}

func buildLogger(cfg Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Log.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func safeDSN(dsn string) string {
	if i := len(dsn); i > 30 {
		return dsn[:30] + "..."
	}
	return dsn
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
