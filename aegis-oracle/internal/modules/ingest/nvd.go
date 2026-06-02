package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// nvdBaseURL is the public NVD CVE 2.0 API. No API key is required for low
// volume; setting NVD_API_KEY raises the per-IP quota.
const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDClient is the NVD-only fallback used when vulnx returns 404 (typically
// for very new CVE ids that vulnx hasn't merged yet).
//
// vs vulnx, NVD's CVE 2.0 payload is leaner: CVSS metrics, CWEs, references,
// CPE matches, and dates. We do not get EPSS, KEV flags, PoC counts, or
// Nuclei templates from NVD — those are layered in by the merge pipeline
// later. The result is still good enough for Phase A: the LLM has the
// description, CWEs, CVSS, and references to reason about.
type NVDClient struct {
	httpClient *http.Client
	apiKey     string
}

// NewNVDClient constructs an NVD client. apiKey is optional.
func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{
		httpClient: &http.Client{Timeout: 20 * time.Second},
		apiKey:     apiKey,
	}
}

// FetchCVE returns a canonical CVE record from NVD, or (nil, nil) when
// the id isn't in NVD yet. Network/parsing failures return non-nil error.
func (c *NVDClient) FetchCVE(ctx context.Context, cveID string) (*schema.CVE, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("nvd: empty cve id")
	}

	url := fmt.Sprintf("%s?cveId=%s", nvdBaseURL, cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("nvd: build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		// NVD throttles aggressive unauthenticated callers; surface as
		// a rate-limit error so the daemon can retry.
		return nil, fmt.Errorf("nvd: HTTP 403 (rate limit — set NVD_API_KEY)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MiB
	if err != nil {
		return nil, fmt.Errorf("nvd: read body: %w", err)
	}

	var envelope struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Metrics struct {
					CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
					CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
					CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
					CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
				} `json:"metrics"`
				References []struct {
					URL    string   `json:"url"`
					Source string   `json:"source"`
					Tags   []string `json:"tags"`
				} `json:"references"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Vulnerable bool   `json:"vulnerable"`
							Criteria   string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("nvd: parse: %w", err)
	}
	if envelope.TotalResults == 0 || len(envelope.Vulnerabilities) == 0 {
		return nil, nil
	}

	v := envelope.Vulnerabilities[0].CVE
	cve := &schema.CVE{
		ID:            v.ID,
		PublishedAt:   parseTime(v.Published, time.Now().UTC()),
		ModifiedAt:    parseTime(v.LastModified, time.Now().UTC()),
		PrimarySource: "nvd",
	}

	for _, d := range v.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			cve.Description = d.Value
			break
		}
	}
	if cve.Description == "" && len(v.Descriptions) > 0 {
		cve.Description = v.Descriptions[0].Value
	}

	for _, w := range v.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				cve.CWEs = append(cve.CWEs, d.Value)
			}
		}
	}
	cve.CWEs = dedupeStrings(cve.CWEs)

	cve.CVSSVectors = append(cve.CVSSVectors,
		nvdMetricsToVectors(v.Metrics.CVSSMetricV40, "4.0")...)
	cve.CVSSVectors = append(cve.CVSSVectors,
		nvdMetricsToVectors(v.Metrics.CVSSMetricV31, "3.1")...)
	cve.CVSSVectors = append(cve.CVSSVectors,
		nvdMetricsToVectors(v.Metrics.CVSSMetricV30, "3.0")...)
	cve.CVSSVectors = append(cve.CVSSVectors,
		nvdMetricsToVectors(v.Metrics.CVSSMetricV2, "2.0")...)

	for _, r := range v.References {
		if r.URL == "" {
			continue
		}
		cve.References = append(cve.References, schema.Reference{
			URL:        r.URL,
			SourceKind: classifyReferenceKind(r.URL),
			Tags:       r.Tags,
		})
	}

	for _, conf := range v.Configurations {
		for _, n := range conf.Nodes {
			for _, m := range n.CPEMatch {
				if m.Criteria == "" {
					continue
				}
				cve.CPEs = append(cve.CPEs, schema.CPEMatch{
					URI: m.Criteria, Vulnerable: m.Vulnerable,
				})
			}
		}
	}

	return cve, nil
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version  string  `json:"version"`
		Vector   string  `json:"vectorString"`
		Score    float64 `json:"baseScore"`
		Severity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

func nvdMetricsToVectors(metrics []nvdMetric, defaultVersion string) []schema.CVSSVector {
	out := make([]schema.CVSSVector, 0, len(metrics))
	for _, m := range metrics {
		version := m.CVSSData.Version
		if version == "" {
			version = defaultVersion
		}
		out = append(out, schema.CVSSVector{
			Source:   strings.ToUpper(m.Source),
			Version:  version,
			Vector:   m.CVSSData.Vector,
			Score:    m.CVSSData.Score,
			Severity: strings.ToLower(m.CVSSData.Severity),
		})
	}
	return out
}
