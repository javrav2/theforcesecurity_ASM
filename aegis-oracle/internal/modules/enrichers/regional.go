// regional.go — enrichers for national/regional vulnerability databases:
//
//   - CISA Vulnrichment  (cisagov/vulnrichment on GitHub)
//                        Adds CVSS 4.0, SSVC decision, and CPE annotations
//                        for CVEs that NVD has not yet fully scored.
//   - JVN iPedia (Japan) (MyJVN API — jvndb.jvn.jp)
//                        Japanese NVD equivalent. Often scores CVEs in
//                        Japanese-vendor products before NVD does.
//   - BDU FSTEC (Russia) (velvetway/bdu-fstec-mirror GitHub CDN)
//                        Russian national vulnerability database. bdu.fstec.ru
//                        geo-blocks non-Russian IPs; this uses the public
//                        GitHub mirror for searchable access.
//
// CNVD (China) does not offer a public programmatic API; it is documented as
// a reference-only source. Integrate manually when needed.
package enrichers

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ─────────────────────────── CISA Vulnrichment ───────────────────────────────

// VulnrichmentResult holds CISA-enriched CVE data from cisagov/vulnrichment.
// CISA enriches CVEs with CVSS 4.0, SSVC decisions, and CPE annotations,
// often before NVD processes them — closing the gap for recently-published CVEs.
type VulnrichmentResult struct {
	Found        bool                   `json:"found"`
	CVSS4Vector  string                 `json:"cvss4_vector,omitempty"`
	CVSS4Score   float64                `json:"cvss4_score,omitempty"`
	SSVCDecision string                 `json:"ssvc_decision,omitempty"` // e.g. "Immediate", "Out-of-Cycle", "Scheduled", "Defer"
	SSVCAction   string                 `json:"ssvc_action,omitempty"`
	CPEs         []string               `json:"cpes,omitempty"`
	RawMetrics   map[string]interface{} `json:"raw_metrics,omitempty"`
	Note         string                 `json:"note,omitempty"`
}

// FetchVulnrichment fetches CISA-enriched CVE data from the cisagov/vulnrichment
// GitHub repository. Files are stored at {YEAR}/{CVE-ID}.json.
func FetchVulnrichment(ctx context.Context, cveID string) VulnrichmentResult {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	year := extractYear(cveID)
	if year == "" {
		return VulnrichmentResult{Note: "cannot extract year from CVE ID"}
	}

	rawURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/cisagov/vulnrichment/main/%s/%s.json",
		year, cveID,
	)

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return VulnrichmentResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return VulnrichmentResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return VulnrichmentResult{Found: false, Note: "not yet enriched by CISA Vulnrichment"}
	}
	if resp.StatusCode != http.StatusOK {
		return VulnrichmentResult{Note: fmt.Sprintf("HTTP %d from vulnrichment", resp.StatusCode)}
	}

	// The file is a standard CVE JSON 5.0 record with CISA container additions.
	var record map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&record); err != nil {
		return VulnrichmentResult{Note: "JSON decode failed"}
	}

	result := VulnrichmentResult{Found: true}

	// Navigate containers → cisa → metrics to find CVSS4 and SSVC.
	containers, _ := record["containers"].(map[string]interface{})
	if containers != nil {
		cisa, _ := containers["cna"].(map[string]interface{})
		if cisa == nil {
			cisa, _ = containers["adp"].(map[string]interface{})
		}
		// Check all ADP containers for CISA's enrichment.
		adpList, ok := containers["adp"].([]interface{})
		if ok {
			for _, a := range adpList {
				adp, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				if title, _ := adp["title"].(string); strings.Contains(strings.ToLower(title), "cisa") {
					cisa = adp
					break
				}
			}
		}
		_ = cisa // parsed below

		// Parse metrics from the CISA ADP container.
		if cisa != nil {
			metrics, _ := cisa["metrics"].([]interface{})
			for _, m := range metrics {
				metric, ok := m.(map[string]interface{})
				if !ok {
					continue
				}
				// CVSS 4.0
				if cvss4, ok := metric["cvssV4_0"].(map[string]interface{}); ok {
					if v, ok := cvss4["vectorString"].(string); ok {
						result.CVSS4Vector = v
					}
					if s, ok := cvss4["baseScore"].(float64); ok {
						result.CVSS4Score = s
					}
				}
				// SSVC
				if ssvc, ok := metric["other"].(map[string]interface{}); ok {
					if t, _ := ssvc["type"].(string); strings.EqualFold(t, "ssvc") {
						content, _ := ssvc["content"].(map[string]interface{})
						if content != nil {
							result.SSVCDecision, _ = content["decision"].(string)
							result.SSVCAction, _ = content["action"].(string)
						}
					}
				}
			}
			// CPEs
			affected, _ := cisa["affected"].([]interface{})
			for _, a := range affected {
				aff, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				cpes, _ := aff["cpes"].([]interface{})
				for _, c := range cpes {
					if cpe, ok := c.(string); ok {
						result.CPEs = append(result.CPEs, cpe)
					}
				}
			}
		}
	}

	notes := []string{}
	if result.CVSS4Vector != "" {
		notes = append(notes, fmt.Sprintf("CVSS4=%s (%.1f)", result.CVSS4Vector, result.CVSS4Score))
	}
	if result.SSVCDecision != "" {
		notes = append(notes, fmt.Sprintf("SSVC=%s", result.SSVCDecision))
	}
	if len(result.CPEs) > 0 {
		notes = append(notes, fmt.Sprintf("%d CPE(s)", len(result.CPEs)))
	}
	result.Note = "CISA Vulnrichment: " + strings.Join(notes, " | ")
	return result
}

// ─────────────────────────── JVN iPedia ──────────────────────────────────────

// JVNResult holds data from the Japan Vulnerability Notes iPedia database.
// JVN often covers Japanese-vendor products and scores CVEs before NVD.
type JVNResult struct {
	Found   bool       `json:"found"`
	Entries []JVNEntry `json:"entries,omitempty"`
	Note    string     `json:"note,omitempty"`
}

// JVNEntry represents a single JVN vulnerability record.
type JVNEntry struct {
	JVNDBID   string  `json:"jvndb_id"`
	Title     string  `json:"title"`
	Link      string  `json:"link"`
	Summary   string  `json:"summary,omitempty"`
	CVSSScore float64 `json:"cvss_score,omitempty"`
	Severity  string  `json:"severity,omitempty"`
}

// FetchJVNiPedia queries the MyJVN API for JVN iPedia entries that reference
// the given CVE ID.
func FetchJVNiPedia(ctx context.Context, cveID string) JVNResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// MyJVN getVulnOverviewList — keyword search, English output, XML format.
	apiURL := fmt.Sprintf(
		"https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd&keyword=%s&lang=en",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, apiURL, nil)
	if err != nil {
		return JVNResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/xml,text/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return JVNResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return JVNResult{Note: fmt.Sprintf("HTTP %d from MyJVN API", resp.StatusCode)}
	}

	// MyJVN returns JVNRSS XML. Use a namespace-agnostic token scan to
	// extract title, link, and sec:identifier (which uses the sec namespace)
	// from each <item> block without relying on struct-based XML unmarshalling.
	type jvnItem struct {
		Title   string
		Link    string
		ID      string
		Summary string
	}

	var (
		items   []jvnItem
		current *jvnItem
		inItem  bool
		lastTag string
	)

	dec := xml.NewDecoder(io.LimitReader(resp.Body, 256*1024))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch se := tok.(type) {
		case xml.StartElement:
			local := strings.ToLower(se.Name.Local)
			switch local {
			case "item":
				inItem = true
				item := &jvnItem{}
				current = item
			case "title", "link", "identifier", "description", "summary":
				lastTag = local
			}
		case xml.EndElement:
			if strings.ToLower(se.Name.Local) == "item" && inItem && current != nil {
				items = append(items, *current)
				inItem = false
				current = nil
			}
			lastTag = ""
		case xml.CharData:
			if inItem && current != nil && lastTag != "" {
				text := strings.TrimSpace(string(se))
				switch lastTag {
				case "title":
					current.Title += text
				case "link":
					current.Link += text
				case "identifier":
					current.ID += text
				case "description", "summary":
					current.Summary += text
				}
			}
		}
	}

	if len(items) == 0 {
		return JVNResult{Found: false}
	}

	entries := make([]JVNEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, JVNEntry{
			JVNDBID: item.ID,
			Title:   item.Title,
			Link:    item.Link,
			Summary: truncate(item.Summary, 300),
		})
	}
	return JVNResult{
		Found:   true,
		Entries: entries,
		Note:    fmt.Sprintf("JVN iPedia: %d entry(entries) for %s", len(entries), cveID),
	}
}

// ─────────────────────────── BDU FSTEC ───────────────────────────────────────

// BDUResult holds data from the Russian Federal FSTEC vulnerability database.
// bdu.fstec.ru geo-blocks non-Russian IPs, so we use a GitHub mirror
// (velvetway/bdu-fstec-mirror) which provides searchable access to the
// same dataset via GitHub Code Search.
type BDUResult struct {
	Found      bool       `json:"found"`
	BDUEntries []BDUEntry `json:"bdu_entries,omitempty"`
	Note       string     `json:"note,omitempty"`
}

// BDUEntry is a minimal BDU FSTEC vulnerability record.
type BDUEntry struct {
	BDUID   string `json:"bdu_id"`
	FileURL string `json:"file_url"`
}

// FetchBDUFSTEC searches the BDU FSTEC GitHub mirror for entries referencing
// the given CVE ID. The mirror at velvetway/bdu-fstec-mirror contains the
// full BDU XML dump, accessible without the Russian IP geo-block.
func FetchBDUFSTEC(ctx context.Context, cveID string) BDUResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Search for the CVE ID in the BDU XML mirror.
	searchURL := fmt.Sprintf(
		"https://api.github.com/search/code?q=%s+repo:velvetway/bdu-fstec-mirror",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return BDUResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return BDUResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return BDUResult{Note: "GitHub rate-limited; set GITHUB_TOKEN"}
	}
	if resp.StatusCode != http.StatusOK {
		return BDUResult{Note: fmt.Sprintf("HTTP %d from GitHub", resp.StatusCode)}
	}

	var payload struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			HTMLURL string `json:"html_url"`
			Name    string `json:"name"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return BDUResult{Note: "JSON decode failed"}
	}
	if payload.TotalCount == 0 {
		return BDUResult{Found: false}
	}

	entries := make([]BDUEntry, 0, len(payload.Items))
	for _, item := range payload.Items {
		entries = append(entries, BDUEntry{
			BDUID:   item.Name,
			FileURL: item.HTMLURL,
		})
	}
	return BDUResult{
		Found:      true,
		BDUEntries: entries,
		Note: fmt.Sprintf(
			"BDU FSTEC (Russian NVD): %d reference(s) to %s found in national database",
			payload.TotalCount, cveID,
		),
	}
}

// ─────────────────────────── helpers ─────────────────────────────────────────

func extractYear(cveID string) string {
	// CVE-YYYY-NNNNN
	parts := strings.Split(cveID, "-")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
