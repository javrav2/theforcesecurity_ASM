package module

import "context"

// Sink publishes events to downstream systems (the host ASM, ticketing,
// chat, custom webhooks). Sinks must handle their own retry/backoff and
// must never block the pipeline on transient failures.
type Sink interface {
	Module
	Publish(ctx context.Context, event SinkEvent) error
}

// SinkEvent is a tagged event delivered to sinks. The Kind determines
// the shape of Payload — sinks should ignore unknown kinds rather than
// erroring (forward-compatibility).
type SinkEvent struct {
	Kind    string // 'finding.created' | 'finding.updated' | 'task.opened' | 'task.resolved' | ...
	Payload any
}
