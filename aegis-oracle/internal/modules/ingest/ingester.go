package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// Store is the persistence surface required by the on-demand ingester.
// Implemented by *store/pg.Store in production; small interface so callers
// can pass test fakes.
type Store interface {
	GetCVE(ctx context.Context, cveID string) (*schema.CVE, error)
	UpsertCVE(ctx context.Context, c *schema.CVE) error
}

// Ingester orchestrates on-demand CVE ingestion. EnsureCVE returns a
// canonical record either from the store (cache hit) or by fetching from
// vulnx (preferred) or NVD (fallback), upserting, and returning the fresh
// row.
//
// Concurrency: safe for concurrent EnsureCVE calls; vulnx/NVD calls are
// stateless, and the store handles its own locking on upsert. We do not
// deduplicate in-flight fetches for the same CVE in the same process —
// the upstream APIs cache aggressively and a duplicate call is harmless.
type Ingester struct {
	store Store
	vulnx *VulnxClient
	nvd   *NVDClient
}

// New constructs an Ingester. pdcpKey is the optional ProjectDiscovery
// Cloud Platform key for vulnx; nvdKey is the optional NVD API key.
func New(store Store, pdcpKey, nvdKey string) *Ingester {
	if nvdKey == "" {
		nvdKey = os.Getenv("NVD_API_KEY")
	}
	return &Ingester{
		store: store,
		vulnx: NewVulnxClient(pdcpKey),
		nvd:   NewNVDClient(nvdKey),
	}
}

// EnsureCVE returns the canonical CVE record, fetching it from upstream
// when not in the store. The boolean indicates whether ingestion ran
// (false = cache hit). When upstream sources don't know the CVE, returns
// (nil, false, nil) — callers should treat that as "not found".
//
// Idempotent: callers should call EnsureCVE liberally before any analysis;
// it does the right thing whether the row exists or not.
func (i *Ingester) EnsureCVE(ctx context.Context, cveID string) (*schema.CVE, bool, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, false, fmt.Errorf("ingest: empty cve id")
	}

	existing, err := i.store.GetCVE(ctx, cveID)
	if err != nil {
		return nil, false, fmt.Errorf("ingest: store get: %w", err)
	}
	if existing != nil {
		return existing, false, nil
	}

	cve, source, err := i.fetch(ctx, cveID)
	if err != nil {
		return nil, false, err
	}
	if cve == nil {
		return nil, false, nil
	}

	if err := i.store.UpsertCVE(ctx, cve); err != nil {
		// Upsert failure is a real error (DB down, schema drift). We
		// still return the fetched record so the daemon can serve a
		// degraded response, but log the failure prominently.
		slog.Error("cve upsert failed", "cve", cveID, "source", source, "error", err)
		return cve, true, fmt.Errorf("ingest: upsert: %w", err)
	}
	slog.Info("cve ingested on demand", "cve", cveID, "source", source,
		"cwes", len(cve.CWEs), "refs", len(cve.References),
		"cvss_vectors", len(cve.CVSSVectors))
	return cve, true, nil
}

// fetch tries vulnx first, then NVD. Returns the CVE plus the source name
// used (for observability). Errors from one source do not abort the
// chain — we only return an error if both sources fail.
func (i *Ingester) fetch(ctx context.Context, cveID string) (*schema.CVE, string, error) {
	var firstErr error

	if i.vulnx != nil {
		cve, err := i.vulnx.FetchCVE(ctx, cveID)
		if err == nil && cve != nil {
			return cve, "vulnx", nil
		}
		if err != nil {
			firstErr = err
			slog.Warn("vulnx fetch failed; trying nvd",
				"cve", cveID, "error", err)
		}
	}

	if i.nvd != nil {
		cve, err := i.nvd.FetchCVE(ctx, cveID)
		if err == nil && cve != nil {
			return cve, "nvd", nil
		}
		if err != nil {
			if firstErr != nil {
				return nil, "", errors.Join(firstErr, err)
			}
			return nil, "", err
		}
	}

	if firstErr != nil {
		return nil, "", firstErr
	}
	return nil, "", nil
}
