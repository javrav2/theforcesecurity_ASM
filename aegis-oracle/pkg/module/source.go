package module

import (
	"context"
	"iter"
	"time"
)

// Source is a module that pulls raw CVE-related data from an upstream
// provider. Sources are the only place external I/O for CVE ingestion
// should happen.
//
// Sync streams records modified since `since`. Implementations should
// stream — not batch — to keep memory bounded for large syncs (cvelistV5
// has ~250k records).
//
// Each SourceRecord carries a SourceKind so the merge logic in the
// pipeline knows how to fold it into the canonical CVE record.
type Source interface {
	Module
	Sync(ctx context.Context, since time.Time) iter.Seq2[SourceRecord, error]
}

type SourceRecord struct {
	CVEID      string
	SourceKind string // e.g. "cvelistv5", "nvd", "kev", "epss", "hackerone"
	Payload    any    // typed per source; the pipeline knows how to merge per kind
	ModifiedAt time.Time
}
