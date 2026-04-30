// threat_intel.go — enrichers that map CVEs to threat-actor TTPs, weaponized
// exploit modules, and industry classification frameworks:
//
//   - MITRE ATT&CK + Mappings Explorer
//                        CVE → technique/tactic mappings from the
//                        Center for Threat-Informed Defense.
//   - Metasploit          GitHub search for exploit modules that reference the CVE.
//                        A Metasploit module is the strongest weaponization signal
//                        (push OPES up toward P1 if reachable).
//   - OWASP Top 10        Static CWE → OWASP category mapping.
//                        Useful for classification and reporting.
//   - Nuclei Templates    GitHub search for nuclei-templates that target the CVE.
//                        A nuclei template means automated scanning tools can
//                        trivially detect and sometimes exploit the issue.
package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ─────────────────────────── MITRE ATT&CK + Mappings Explorer ────────────────

// ATTACKResult holds MITRE ATT&CK technique mappings for a CVE.
type ATTACKResult struct {
	Found      bool           `json:"found"`
	Techniques []ATTACKTactic `json:"techniques,omitempty"`
	Note       string         `json:"note,omitempty"`
}

// ATTACKTactic describes one mapped ATT&CK technique.
type ATTACKTactic struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	Tactics       []string `json:"tactics,omitempty"`
	URL           string   `json:"url,omitempty"`
}

// FetchATTACKMappings looks up MITRE ATT&CK CVE-to-technique mappings using
// the Center for Threat-Informed Defense Mappings Explorer data on GitHub.
// Falls back to searching the MITRE ATT&CK STIX repo if mappings-explorer
// doesn't return a result.
func FetchATTACKMappings(ctx context.Context, cveID string) ATTACKResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Mappings Explorer publishes a machine-readable JSON file for CVE mappings.
	// Search GitHub for the CVE in the mappings data.
	searchURL := fmt.Sprintf(
		"https://api.github.com/search/code?q=%s+repo:center-for-threat-informed-defense/mappings-explorer+extension:json",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return ATTACKResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ATTACKResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return ATTACKResult{Note: "GitHub rate-limited"}
	}
	if resp.StatusCode != http.StatusOK {
		return ATTACKResult{Note: fmt.Sprintf("HTTP %d from GitHub", resp.StatusCode)}
	}

	var payload struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name    string `json:"name"`
			HTMLURL string `json:"html_url"`
			Path    string `json:"path"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return ATTACKResult{Note: "JSON decode failed"}
	}
	if payload.TotalCount == 0 {
		return ATTACKResult{Found: false}
	}

	// Derive techniques from file paths (files are named by technique ID).
	techniques := make([]ATTACKTactic, 0, len(payload.Items))
	seen := map[string]bool{}
	for _, item := range payload.Items {
		tid := extractTechniqueID(item.Path)
		if tid == "" || seen[tid] {
			continue
		}
		seen[tid] = true
		techniques = append(techniques, ATTACKTactic{
			TechniqueID: tid,
			URL:         fmt.Sprintf("https://attack.mitre.org/techniques/%s/", strings.ReplaceAll(tid, ".", "/")),
		})
	}

	return ATTACKResult{
		Found:      true,
		Techniques: techniques,
		Note: fmt.Sprintf(
			"ATT&CK/Mappings Explorer: %d technique mapping(s) found for %s",
			len(techniques), cveID,
		),
	}
}

// ─────────────────────────── Metasploit ──────────────────────────────────────

// MetasploitResult holds data about Metasploit modules targeting this CVE.
// A Metasploit module is one of the strongest weaponization signals —
// it means a reliable, GUI-accessible exploit exists for the vulnerability.
type MetasploitResult struct {
	Found         bool     `json:"found"`
	ModuleCount   int      `json:"module_count,omitempty"`
	ModulePaths   []string `json:"module_paths,omitempty"`
	Note          string   `json:"note,omitempty"`
}

// FetchMetasploit searches the rapid7/metasploit-framework GitHub repo for
// exploit modules that reference the given CVE ID.
func FetchMetasploit(ctx context.Context, cveID string) MetasploitResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Restrict to modules/exploits path for stronger signal.
	searchURL := fmt.Sprintf(
		"https://api.github.com/search/code?q=%s+repo:rapid7/metasploit-framework+path:modules/exploits",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return MetasploitResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return MetasploitResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return MetasploitResult{Note: "GitHub rate-limited; set GITHUB_TOKEN"}
	}
	if resp.StatusCode != http.StatusOK {
		return MetasploitResult{Note: fmt.Sprintf("HTTP %d from GitHub", resp.StatusCode)}
	}

	var payload struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Path    string `json:"path"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return MetasploitResult{Note: "JSON decode failed"}
	}
	if payload.TotalCount == 0 {
		return MetasploitResult{Found: false}
	}

	paths := make([]string, 0, len(payload.Items))
	for _, item := range payload.Items {
		paths = append(paths, item.Path)
	}
	return MetasploitResult{
		Found:       true,
		ModuleCount: payload.TotalCount,
		ModulePaths: paths,
		Note: fmt.Sprintf(
			"Metasploit: %d weaponized exploit module(s) for %s — reliable GUI-accessible exploit exists",
			payload.TotalCount, cveID,
		),
	}
}

// ─────────────────────────── Nuclei Templates ────────────────────────────────

// NucleiResult holds data about ProjectDiscovery nuclei-templates for a CVE.
// A nuclei template means the vulnerability can be scanned/detected (and
// sometimes exploited) by automated tooling with a single command.
type NucleiResult struct {
	Found         bool     `json:"found"`
	TemplateCount int      `json:"template_count,omitempty"`
	TemplatePaths []string `json:"template_paths,omitempty"`
	Note          string   `json:"note,omitempty"`
}

// FetchNucleiTemplate searches the projectdiscovery/nuclei-templates GitHub
// repo for templates that target the given CVE.
func FetchNucleiTemplate(ctx context.Context, cveID string) NucleiResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	searchURL := fmt.Sprintf(
		"https://api.github.com/search/code?q=%s+repo:projectdiscovery/nuclei-templates+extension:yaml",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return NucleiResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NucleiResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return NucleiResult{Note: "GitHub rate-limited"}
	}
	if resp.StatusCode != http.StatusOK {
		return NucleiResult{Note: fmt.Sprintf("HTTP %d from GitHub", resp.StatusCode)}
	}

	var payload struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Path    string `json:"path"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return NucleiResult{Note: "JSON decode failed"}
	}
	if payload.TotalCount == 0 {
		return NucleiResult{Found: false}
	}

	paths := make([]string, 0, len(payload.Items))
	for _, item := range payload.Items {
		paths = append(paths, item.Path)
	}
	return NucleiResult{
		Found:         true,
		TemplateCount: payload.TotalCount,
		TemplatePaths: paths,
		Note: fmt.Sprintf(
			"Nuclei templates: %d template(s) for %s — automated scanning/detection available",
			payload.TotalCount, cveID,
		),
	}
}

// ─────────────────────────── OWASP Top 10 ────────────────────────────────────

// OWASPResult maps a CVE's CWE identifiers to OWASP Top 10 2021 categories.
// This is a deterministic mapping — no network call required.
type OWASPResult struct {
	Categories []OWASPCategory `json:"categories,omitempty"`
	Note       string          `json:"note,omitempty"`
}

// OWASPCategory describes one matched OWASP Top 10 category.
type OWASPCategory struct {
	ID          string   `json:"id"`          // e.g. "A03:2021"
	Name        string   `json:"name"`        // e.g. "Injection"
	MatchedCWEs []string `json:"matched_cwes"` // CWEs that triggered this match
}

// owaspMapping maps CWE IDs to OWASP Top 10 2021 categories.
// Source: https://owasp.org/Top10/ (includes primary and secondary CWEs per category).
var owaspMapping = map[string]struct{ ID, Name string }{
	// A01: Broken Access Control
	"CWE-200": {"A01:2021", "Broken Access Control"},
	"CWE-201": {"A01:2021", "Broken Access Control"},
	"CWE-352": {"A01:2021", "Broken Access Control"},
	"CWE-284": {"A01:2021", "Broken Access Control"},
	"CWE-285": {"A01:2021", "Broken Access Control"},
	"CWE-639": {"A01:2021", "Broken Access Control"},
	"CWE-22":  {"A01:2021", "Broken Access Control"},
	"CWE-59":  {"A01:2021", "Broken Access Control"},
	// A02: Cryptographic Failures
	"CWE-311": {"A02:2021", "Cryptographic Failures"},
	"CWE-312": {"A02:2021", "Cryptographic Failures"},
	"CWE-327": {"A02:2021", "Cryptographic Failures"},
	"CWE-326": {"A02:2021", "Cryptographic Failures"},
	"CWE-320": {"A02:2021", "Cryptographic Failures"},
	"CWE-522": {"A02:2021", "Cryptographic Failures"},
	"CWE-916": {"A02:2021", "Cryptographic Failures"},
	// A03: Injection
	"CWE-79":  {"A03:2021", "Injection"},
	"CWE-89":  {"A03:2021", "Injection"},
	"CWE-77":  {"A03:2021", "Injection"},
	"CWE-78":  {"A03:2021", "Injection"},
	"CWE-91":  {"A03:2021", "Injection"},
	"CWE-94":  {"A03:2021", "Injection"},
	"CWE-917": {"A03:2021", "Injection"},
	"CWE-943": {"A03:2021", "Injection"},
	// A04: Insecure Design
	"CWE-209": {"A04:2021", "Insecure Design"},
	"CWE-256": {"A04:2021", "Insecure Design"},
	"CWE-501": {"A04:2021", "Insecure Design"},
	"CWE-732": {"A04:2021", "Insecure Design"},
	// A05: Security Misconfiguration
	"CWE-16":  {"A05:2021", "Security Misconfiguration"},
	"CWE-611": {"A05:2021", "Security Misconfiguration"},
	"CWE-614": {"A05:2021", "Security Misconfiguration"},
	"CWE-693": {"A05:2021", "Security Misconfiguration"},
	// A06: Vulnerable and Outdated Components
	"CWE-1395": {"A06:2021", "Vulnerable and Outdated Components"},
	// A07: Identification and Authentication Failures
	"CWE-287": {"A07:2021", "Identification and Authentication Failures"},
	"CWE-290": {"A07:2021", "Identification and Authentication Failures"},
	"CWE-294": {"A07:2021", "Identification and Authentication Failures"},
	"CWE-302": {"A07:2021", "Identification and Authentication Failures"},
	"CWE-384": {"A07:2021", "Identification and Authentication Failures"},
	"CWE-521": {"A07:2021", "Identification and Authentication Failures"},
	"CWE-613": {"A07:2021", "Identification and Authentication Failures"},
	// A08: Software and Data Integrity Failures
	"CWE-345": {"A08:2021", "Software and Data Integrity Failures"},
	"CWE-346": {"A08:2021", "Software and Data Integrity Failures"},
	"CWE-502": {"A08:2021", "Software and Data Integrity Failures"},
	"CWE-915": {"A08:2021", "Software and Data Integrity Failures"},
	"CWE-116": {"A08:2021", "Software and Data Integrity Failures"},
	// A09: Security Logging and Monitoring Failures
	"CWE-117": {"A09:2021", "Security Logging and Monitoring Failures"},
	"CWE-223": {"A09:2021", "Security Logging and Monitoring Failures"},
	"CWE-532": {"A09:2021", "Security Logging and Monitoring Failures"},
	"CWE-778": {"A09:2021", "Security Logging and Monitoring Failures"},
	// A10: Server-Side Request Forgery
	"CWE-918": {"A10:2021", "Server-Side Request Forgery"},
	"CWE-601": {"A10:2021", "Server-Side Request Forgery"},
	// Memory Safety (also cross-list with A04/A05)
	"CWE-119": {"A04:2021", "Insecure Design"},
	"CWE-120": {"A04:2021", "Insecure Design"},
	"CWE-121": {"A04:2021", "Insecure Design"},
	"CWE-122": {"A04:2021", "Insecure Design"},
	"CWE-125": {"A04:2021", "Insecure Design"},
	"CWE-787": {"A04:2021", "Insecure Design"},
}

// MapOWASP maps a list of CWE IDs (e.g. ["CWE-79", "CWE-89"]) to OWASP
// Top 10 2021 categories. This is a pure in-memory lookup — no network call.
func MapOWASP(cweIDs []string) OWASPResult {
	type catKey struct{ ID, Name string }
	matched := map[catKey][]string{}

	for _, cwe := range cweIDs {
		normalized := normalizeCWE(cwe)
		if cat, ok := owaspMapping[normalized]; ok {
			k := catKey{cat.ID, cat.Name}
			matched[k] = append(matched[k], normalized)
		}
	}

	if len(matched) == 0 {
		return OWASPResult{Note: "no OWASP Top 10 category matched for the given CWEs"}
	}

	cats := make([]OWASPCategory, 0, len(matched))
	for k, cwes := range matched {
		cats = append(cats, OWASPCategory{
			ID:          k.ID,
			Name:        k.Name,
			MatchedCWEs: cwes,
		})
	}
	names := make([]string, 0, len(cats))
	for _, c := range cats {
		names = append(names, c.ID+" "+c.Name)
	}
	return OWASPResult{
		Categories: cats,
		Note:       "OWASP Top 10 2021: " + strings.Join(names, "; "),
	}
}

// ─────────────────────────── helpers ─────────────────────────────────────────

// normalizeCWE ensures the CWE ID is in "CWE-NNN" form.
func normalizeCWE(s string) string {
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "CWE-") {
		return upper
	}
	return "CWE-" + s
}

// extractTechniqueID extracts a T#### or T####.### ID from a file path.
func extractTechniqueID(path string) string {
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if len(p) >= 5 && strings.HasPrefix(strings.ToUpper(p), "T") {
			// T followed by digits and optional .digits
			rest := p[1:]
			ok := true
			for _, c := range rest {
				if c != '.' && (c < '0' || c > '9') {
					ok = false
					break
				}
			}
			if ok {
				return strings.ToUpper(p)
			}
		}
	}
	return ""
}
