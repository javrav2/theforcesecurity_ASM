package ingest

// OSVClient fetches CVE intelligence from the OSV.dev API (https://osv.dev).
//
// OSV.dev aggregates GHSA advisories, PyPA, RustSec, and other ecosystem
// databases and exposes them through a public, unauthenticated REST API.
// It is used as a third-fallback source when both vulnx and NVD return empty
// results — the most common case being a brand-new CVE that NVD has not yet
// indexed, but whose GHSA advisory is already live.
//
// What OSV provides that NVD may not for day-zero CVEs:
//   - Full advisory description from the GitHub Advisory Database (GHSA)
//   - Affected package ecosystem + version ranges (better than CPE for most OSS)
//   - CVSS severity vectors from the advisory author
//   - References including the GHSA advisory URL, commit, and patch links
//   - Related advisory aliases (GHSA-XXXX, CVE-YYYY, …) — used by the
//     patch-bypass enricher to discover predecessor CVEs
//
// Rate limits: no auth, no hard limit documented; be polite (one call per CVE).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

const osvAPIBase = "https://api.osv.dev/v1/vulns"

// OSVClient queries the OSV.dev public API for a single CVE record.
type OSVClient struct {
	httpClient *http.Client
}

// NewOSVClient constructs an OSV client with a sensible default timeout.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

// FetchCVE returns a schema.CVE populated from the OSV advisory, or (nil, nil)
// when OSV does not know the CVE. Network/parsing errors return a non-nil error.
func (c *OSVClient) FetchCVE(ctx context.Context, cveID string) (*schema.CVE, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("osv: empty cve id")
	}

	url := fmt.Sprintf("%s/%s", osvAPIBase, cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("osv: status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB cap
	if err != nil {
		return nil, fmt.Errorf("osv: read body: %w", err)
	}

	var raw osvRecord
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("osv: unmarshal: %w", err)
	}

	cve := raw.toSchemaCVE(cveID)
	if cve == nil {
		return nil, nil
	}

	slog.Info("osv: fetched advisory", "cve", cveID,
		"aliases", len(raw.Aliases),
		"refs", len(cve.References),
		"cvss_vectors", len(cve.CVSSVectors))
	return cve, nil
}

// ─────────────────────────── OSV wire types ──────────────────────────────────

type osvRecord struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Published string     `json:"published"`
	Modified  string     `json:"modified"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Severity  []osvSev   `json:"severity"`
	References []osvRef  `json:"references"`
	Affected  []osvAff   `json:"affected"`
	Related   []string   `json:"related"`
}

type osvSev struct {
	Type  string `json:"type"`  // "CVSS_V3" | "CVSS_V4"
	Score string `json:"score"` // vector string e.g. "CVSS:3.1/AV:N/..."
}

type osvRef struct {
	Type string `json:"type"` // "ADVISORY" | "FIX" | "REPORT" | "WEB"
	URL  string `json:"url"`
}

type osvAff struct {
	Package osvPkg    `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// ─────────────────────────── Conversion ──────────────────────────────────────

func (r *osvRecord) toSchemaCVE(cveID string) *schema.CVE {
	desc := r.Details
	if desc == "" {
		desc = r.Summary
	}
	if desc == "" && len(r.Aliases) == 0 {
		return nil
	}

	now := time.Now().UTC()
	pub := parseOSVTime(r.Published, now)
	mod := parseOSVTime(r.Modified, now)

	cve := &schema.CVE{
		ID:            cveID,
		PublishedAt:   pub,
		ModifiedAt:    mod,
		Description:   desc,
		PrimarySource: "osv",
	}

	// CVSS vectors
	for _, s := range r.Severity {
		vec := s.Score
		if !strings.HasPrefix(vec, "CVSS:") {
			continue
		}
		ver := "3.1"
		if strings.HasPrefix(vec, "CVSS:4.") {
			ver = "4.0"
		}
		score := estimateCVSSScore(vec)
		cve.CVSSVectors = append(cve.CVSSVectors, schema.CVSSVector{
			Source:  "GHSA",
			Version: ver,
			Vector:  vec,
			Score:   score,
		})
	}

	// References — map OSV type to schema SourceKind
	for _, ref := range r.References {
		kind := "other"
		url := ref.URL
		switch ref.Type {
		case "ADVISORY":
			if strings.Contains(url, "github.com/advisories") || strings.HasPrefix(url, "https://ghsa") {
				kind = "github"
			} else {
				kind = "vendor"
			}
		case "FIX":
			kind = "github"
		case "REPORT":
			kind = "other"
		}
		cve.References = append(cve.References, schema.Reference{
			URL:        url,
			SourceKind: kind,
		})
	}

	// Build Related field on CVE for patch-bypass enricher.
	// Aliases includes other CVE IDs and GHSA IDs that describe the same vuln.
	// Related includes predecessor/successor advisories.
	// We store both in References with a "related" source kind so the
	// patch-bypass enricher can find them.
	for _, alias := range append(r.Aliases, r.Related...) {
		if alias == cveID {
			continue
		}
		refURL := ""
		if strings.HasPrefix(alias, "GHSA-") {
			refURL = "https://github.com/advisories/" + alias
		} else if strings.HasPrefix(alias, "CVE-") {
			refURL = "https://nvd.nist.gov/vuln/detail/" + alias
		} else {
			continue
		}
		cve.References = append(cve.References, schema.Reference{
			URL:        refURL,
			SourceKind: "related",
			Tags:       []string{"alias:" + alias},
		})
	}

	return cve
}

func parseOSVTime(s string, fallback time.Time) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return fallback
}

// estimateCVSSScore extracts the numeric score from the CVSS vector string
// using a lightweight heuristic. The full scoring formula is not implemented
// here — this is a best-effort approximation used only when no explicit score
// field is provided by OSV. The intrinsic LLM will reconcile CVSS later.
func estimateCVSSScore(vector string) float64 {
	// Count high-severity indicators: AV:N, AC:L, PR:N, UI:N, C:H, I:H, A:H
	score := 0.0
	high := []string{"AV:N", "AC:L", "PR:N", "UI:N", "VC:H", "VI:H", "VA:H", "C:H", "I:H", "A:H"}
	for _, ind := range high {
		if strings.Contains(vector, ind) {
			score += 1.0
		}
	}
	// Very rough mapping: 7+ high markers → 9.x, 4–6 → 7.x, 2–3 → 5.x, <2 → 3.x
	switch {
	case score >= 7:
		return 9.8
	case score >= 4:
		return 7.5
	case score >= 2:
		return 5.3
	default:
		return 3.1
	}
}
