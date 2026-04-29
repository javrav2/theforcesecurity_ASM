// Package module defines the public interfaces every Aegis Oracle module
// implements. Sources, enrichers, reasoners, verifiers, and sinks all
// implement Module plus their role-specific interface, then register with
// the pipeline at startup.
//
// Modules depend only on pkg/schema and pkg/module — never on internal/
// packages from other modules. This keeps modules independently
// testable, swappable, and (eventually) extractable into separate repos.
package module

import "context"

// Module is the base interface every plug-in implements.
//
// Name is dotted and unique across the registry, e.g. "sources.cvelistv5",
// "reasoners.intrinsic", "sinks.linear".
//
// Init runs once at startup with shared infra deps. Modules should fail
// fast (return error) on misconfiguration rather than panic later.
//
// HealthCheck is invoked periodically by the daemon for liveness probing
// and admin diagnostics. Implementations should be cheap (no LLM calls,
// no full DB scans).
type Module interface {
	Name() string
	Version() string
	Init(ctx context.Context, deps Deps) error
	HealthCheck(ctx context.Context) error
}

// Deps is the shared infrastructure handed to every module at Init.
// Module-specific config lives under Config keyed by the module Name.
type Deps struct {
	Store     Store
	Queue     Queue
	LLM       LLMProvider
	Config    map[string]any
	Telemetry Telemetry
}

// Store is the persistence interface. The minimal surface required by
// modules — full CRUD lives behind a richer internal interface used by
// the pipeline.
type Store interface {
	// Get and Put on opaque keyed values, used for module-private state
	// (e.g. "sources.cvelistv5.last_synced_at"). Module data that is
	// part of the canonical pipeline (CVEs, findings) goes through
	// typed methods on the internal store, not this surface.
	Get(ctx context.Context, key string, dest any) error
	Put(ctx context.Context, key string, val any) error
}

// Queue is the job queue interface used by modules to enqueue follow-up
// work (e.g. an enricher requesting a re-fetch, a sink scheduling a
// retry).
type Queue interface {
	Enqueue(ctx context.Context, kind string, payload any) error
}

// LLMProvider is the abstracted LLM interface. Implementations wrap
// Anthropic, OpenAI, self-hosted models, etc. Modules should request
// structured output via the JSON schema interface rather than parse
// freeform text.
type LLMProvider interface {
	CompleteJSON(ctx context.Context, req JSONRequest) (JSONResponse, error)
}

// JSONRequest asks the LLM for output that conforms to a JSON schema.
// Implementations enforce schema compliance via the provider's
// structured-output feature when available.
type JSONRequest struct {
	Model        string
	System       string
	User         string
	Schema       any // JSON schema describing the expected output
	MaxTokens    int
	Temperature  float64
	StopOnError  bool
}

type JSONResponse struct {
	Content    string // raw JSON text
	Model      string
	TokenUsage TokenUsage
	StopReason string
}

type TokenUsage struct {
	Input  int
	Output int
}

// Telemetry is the metrics/tracing/logging surface modules use to record
// timing, counts, and errors. Implementations may be no-ops in tests.
type Telemetry interface {
	Counter(name string, tags map[string]string, delta int64)
	Gauge(name string, tags map[string]string, value float64)
	Timing(name string, tags map[string]string, ms int64)
	Event(name string, tags map[string]string, message string)
}
