// Package react implements the Oracle ReAct (Reasoning + Acting) harness.
//
// The harness runs an iterative Thought → Action → Observation loop driven
// by the LLM. On each iteration the LLM receives the full trace so far and
// emits a structured Decision — either call a named tool or produce a
// FinalAnswer that includes an optional OPES finding.
//
// This mirrors the Vanguard agent's LangGraph pattern but is implemented
// in pure Go without an external framework, keeping the Oracle service
// dependency-free and its loop behaviour fully auditable.
package react

import (
	"context"
	"fmt"
)

// ─────────────────────────── Tool interface ───────────────────────────────

// Tool is a single callable capability the LLM can invoke during a loop
// iteration. The name must be unique within a Registry.
//
// Schema returns a JSON-schema-compatible description of the args map
// that the LLM should populate. This is injected into the system prompt
// so the model knows how to form valid calls.
type Tool interface {
	// Name is the identifier the LLM uses in Decision.ToolName.
	// Use snake_case, e.g. "lookup_cve", "run_analysis".
	Name() string

	// Description is shown to the LLM in the tool listing. Keep it
	// concise and action-oriented (1-2 sentences).
	Description() string

	// ArgsSchema returns a JSON-schema object describing the tool's
	// input. Only "type", "properties", and "required" are used.
	ArgsSchema() map[string]any

	// Run executes the tool with the provided args (decoded from the
	// LLM's JSON output). The return value is an Observation that is
	// appended to the loop trace.
	//
	// Errors are wrapped by the loop into an "error" observation —
	// they do NOT terminate the loop, giving the LLM a chance to
	// recover or try a different tool.
	Run(ctx context.Context, args map[string]any) (string, error)
}

// ─────────────────────────── Registry ─────────────────────────────────────

// Registry holds the set of tools available to the ReAct loop.
type Registry struct {
	tools map[string]Tool
	order []string // insertion order for deterministic prompt rendering
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]Tool)}
}

// Register adds a tool. Panics on duplicate name.
func (r *Registry) Register(t Tool) {
	if _, exists := r.tools[t.Name()]; exists {
		panic(fmt.Sprintf("react: duplicate tool name %q", t.Name()))
	}
	r.tools[t.Name()] = t
	r.order = append(r.order, t.Name())
}

// Get returns a tool by name and whether it was found.
func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// All returns all tools in insertion order.
func (r *Registry) All() []Tool {
	out := make([]Tool, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.tools[name])
	}
	return out
}
