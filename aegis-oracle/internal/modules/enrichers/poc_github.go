package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PoCGitHubResult holds public PoC repository evidence from
// github.com/nomi-sec/PoC-in-GitHub — the same index used by aggregators
// such as Zero Day Clock's Explorer for GitHub PoC coverage.
//
// A hit means public proof-of-concept code exists; it is weaker than
// Metasploit / VulnCheck weaponization or KEV (confirmed ITW), but it is
// the primary open signal for "exploit code is circulating."
type PoCGitHubResult struct {
	Found         bool            `json:"found"`
	POCCount      int             `json:"poc_count,omitempty"`
	RecentPOCDays int             `json:"recent_poc_days,omitempty"` // age of newest PoC; 0 = none
	EarliestPOCAt string          `json:"earliest_poc_at,omitempty"` // RFC3339
	NewestPOCAt   string          `json:"newest_poc_at,omitempty"`   // RFC3339
	POCs          []PoCGitHubRepo `json:"pocs,omitempty"`
	Note          string          `json:"note,omitempty"`
}

// PoCGitHubRepo is a single indexed public PoC repository.
type PoCGitHubRepo struct {
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	Stars       int    `json:"stars"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// FetchPoCGitHub looks up nomi-sec/PoC-in-GitHub for repositories tagged to
// the given CVE. The index is published as raw JSON per CVE year/ID:
//
//	https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{YYYY}/{CVE-ID}.json
//
// No API key is required. A 404 means no indexed PoCs (not an error).
func FetchPoCGitHub(ctx context.Context, cveID string) PoCGitHubResult {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return PoCGitHubResult{Note: "cve_id is required"}
	}
	year, ok := cveYear(cveID)
	if !ok {
		return PoCGitHubResult{Note: "CVE ID does not contain a parseable year"}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	rawURL := fmt.Sprintf(
		"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/%s/%s.json",
		year, cveID,
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return PoCGitHubResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return PoCGitHubResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return PoCGitHubResult{
			Found: false,
			Note:  "No public PoC repositories indexed in nomi-sec/PoC-in-GitHub for this CVE",
		}
	case http.StatusOK:
		// continue
	default:
		return PoCGitHubResult{Note: fmt.Sprintf("HTTP %d from PoC-in-GitHub raw index", resp.StatusCode)}
	}

	var entries []struct {
		Name            string `json:"name"`
		FullName        string `json:"full_name"`
		HTMLURL         string `json:"html_url"`
		Description     string `json:"description"`
		StargazersCount int    `json:"stargazers_count"`
		CreatedAt       string `json:"created_at"`
		Fork            bool   `json:"fork"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&entries); err != nil {
		return PoCGitHubResult{Note: "JSON decode failed: " + err.Error()}
	}
	if len(entries) == 0 {
		return PoCGitHubResult{Found: false, Note: "Empty PoC index entry"}
	}

	type dated struct {
		repo PoCGitHubRepo
		at   time.Time
	}
	var datedEntries []dated
	for _, e := range entries {
		if e.Fork || e.HTMLURL == "" {
			continue
		}
		repo := PoCGitHubRepo{
			Name:        e.Name,
			FullName:    e.FullName,
			URL:         e.HTMLURL,
			Description: e.Description,
			Stars:       e.StargazersCount,
			CreatedAt:   e.CreatedAt,
		}
		t, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err != nil {
			// Keep undated repos; they still count as PoC presence.
			datedEntries = append(datedEntries, dated{repo: repo})
			continue
		}
		datedEntries = append(datedEntries, dated{repo: repo, at: t})
	}
	if len(datedEntries) == 0 {
		return PoCGitHubResult{Found: false, Note: "Index contained only forks or empty URLs"}
	}

	// Prefer newest first, then star count — surfaces fresh + popular PoCs.
	sort.SliceStable(datedEntries, func(i, j int) bool {
		if !datedEntries[i].at.Equal(datedEntries[j].at) {
			return datedEntries[i].at.After(datedEntries[j].at)
		}
		return datedEntries[i].repo.Stars > datedEntries[j].repo.Stars
	})

	const maxPOCs = 15
	pocs := make([]PoCGitHubRepo, 0, min(maxPOCs, len(datedEntries)))
	var newest, earliest time.Time
	for i, d := range datedEntries {
		if i < maxPOCs {
			pocs = append(pocs, d.repo)
		}
		if d.at.IsZero() {
			continue
		}
		if newest.IsZero() || d.at.After(newest) {
			newest = d.at
		}
		if earliest.IsZero() || d.at.Before(earliest) {
			earliest = d.at
		}
	}

	result := PoCGitHubResult{
		Found:    true,
		POCCount: len(datedEntries),
		POCs:     pocs,
		Note: fmt.Sprintf(
			"%d public PoC repo(s) in nomi-sec/PoC-in-GitHub — proof-of-concept code is circulating (not the same as confirmed ITW / weaponized exploit)",
			len(datedEntries),
		),
	}
	now := time.Now().UTC()
	if !newest.IsZero() {
		result.NewestPOCAt = newest.UTC().Format(time.RFC3339)
		days := int(now.Sub(newest.UTC()).Hours() / 24)
		if days < 1 {
			days = 1
		}
		result.RecentPOCDays = days
	}
	if !earliest.IsZero() {
		result.EarliestPOCAt = earliest.UTC().Format(time.RFC3339)
	}
	return result
}

// cveYear extracts the YYYY portion of a CVE-YYYY-NNNNN identifier.
func cveYear(cveID string) (string, bool) {
	parts := strings.Split(cveID, "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "CVE") {
		return "", false
	}
	if len(parts[1]) != 4 {
		return "", false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", false
	}
	return parts[1], true
}
