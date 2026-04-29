package module

import (
	"context"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Enricher takes a CVE record and adds context to the EnrichmentBundle.
// Enrichers run in topological order based on DependsOn (e.g. devpatterns
// depends on cwe profiles being loaded).
//
// Enrichers must be idempotent and content-hashable: re-running with the
// same inputs must produce the same outputs. The pipeline relies on this
// for cache invalidation.
type Enricher interface {
	Module
	Enrich(ctx context.Context, cve *schema.CVE, bundle *schema.EnrichmentBundle) error

	// DependsOn returns module names that must run before this one.
	// Empty list means the enricher can run as soon as the CVE record
	// is loaded.
	DependsOn() []string
}
