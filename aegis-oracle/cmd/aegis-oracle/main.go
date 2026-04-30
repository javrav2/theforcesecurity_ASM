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
//	GET  /findings         — list open findings (queryable by cve_id, asset_id, category)
//	GET  /findings/:id     — single finding detail
//	POST /findings/:id/suppress  — suppress a finding
//	GET  /health           — liveness probe
//	GET  /kb/stats         — knowledge base summary
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/your-org/aegis-oracle/internal/knowledgebase"
	"github.com/your-org/aegis-oracle/internal/llm"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/intrinsic"
	"github.com/your-org/aegis-oracle/internal/modules/reasoners/priority/opes"
	"github.com/your-org/aegis-oracle/internal/pipeline"
	"github.com/your-org/aegis-oracle/internal/react"
	reacttools "github.com/your-org/aegis-oracle/internal/react/tools"
	"github.com/your-org/aegis-oracle/internal/store/pg"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

type Config struct {
	DB            pg.Config     `yaml:"db"`
	LLM           llm.Config    `yaml:"llm"`
	Knowledgebase struct {
		Root string `yaml:"root"`
	} `yaml:"knowledgebase"`
	OPES    opes.Config `yaml:"opes"`
	PDCPKey string      `yaml:"pdcp_api_key"` // ProjectDiscovery Cloud Platform key (optional)
	Log     struct {
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

	// LLM provider.
	provider, err := llm.New(cfg.LLM)
	if err != nil {
		slog.Error("llm init failed", "error", err)
		os.Exit(1)
	}
	slog.Info("llm provider ready", "provider", cfg.LLM.Provider)

	// Phase A reasoner.
	reasoner, err := intrinsic.New(provider, store, kb)
	if err != nil {
		slog.Error("intrinsic reasoner init failed", "error", err)
		os.Exit(1)
	}

	// Pipeline runner.
	runner := pipeline.New(store, reasoner, cfg.OPES)

	// ReAct loop — wires Oracle tools to the LLM for iterative reasoning.
	toolRegistry := reacttools.BuildRegistry(reacttools.Deps{
		Store:   store,
		Runner:  runner,
		KB:      kb,
		PDCPKey: os.Getenv("PDCP_API_KEY"), // optional; higher vulnx rate limits
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
		Handler:      buildMux(runner, store, kb, reactLoop),
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

func buildMux(runner *pipeline.Runner, store *pg.Store, kb *knowledgebase.KB, loop *react.Loop) http.Handler {
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

	// POST /analyze  body: {"cve_id":"...","asset_id":"..."}
	mux.HandleFunc("POST /analyze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CVEID   string `json:"cve_id"`
			AssetID string `json:"asset_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		if req.CVEID == "" || req.AssetID == "" {
			writeError(w, http.StatusBadRequest, "cve_id and asset_id are required")
			return
		}

		result, err := runner.Run(r.Context(), req.CVEID, req.AssetID, nil, schema.ExploitationEvidence{})
		if err != nil {
			slog.Error("pipeline run failed", "cve", req.CVEID, "asset", req.AssetID, "error", err)
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"finding":    result.Finding,
			"llm_model":  result.LLMModel,
			"elapsed_ms": result.ElapsedMS,
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
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	return cfg, nil
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
