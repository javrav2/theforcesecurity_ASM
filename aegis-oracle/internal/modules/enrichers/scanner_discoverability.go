// Package enrichers — scanner_discoverability.go
//
// AttackerDiscoverability measures how easily an external, unauthenticated
// attacker can confirm whether a specific target is vulnerable to a CVE —
// BEFORE any exploit attempt.
//
// This is intentionally distinct from two other concepts:
//
//  1. Detection confidence (did OUR scanner confirm the feature is active?)
//     → That's a defender signal about what WE found.
//
//  2. Exploitation automability (can the exploit itself be scripted?)
//     → That's about what happens AFTER the attacker confirms the target.
//
// Discoverability answers: "given only an IP/hostname, how quickly can an
// attacker determine this is a target worth exploiting?"
//
// Signal sources and their attacker relevance:
//
//   AlienVault OTX  ── Free threat intelligence feed. Pulse count per CVE is a
//   (no API key)       proxy for attacker-community interest and active tooling
//                      deployment. No authentication required. 20+ pulses →
//                      active targeting campaigns.
//
//   Nuclei remote   ── The ProjectDiscovery community wrote an automated
//   template           detection/exploit that works with no credentials.
//                      Attackers run Nuclei. Classified by template path:
//                        /cves/, /exploits/ → exploit (sends payload, gets proof)
//                        /exposed-panels/, /misconfiguration/ → detect (confirms endpoint)
//                        /technologies/, /fingerprint/ → version (passive)
//
//   Tenable plugin  ── Plugin family determines whether credentials are needed.
//   family             "Web Servers", "Cisco", "Firewalls" → remote, no auth,
//   classification     attacker-replicatable.
//                      "Local Security Checks", "Policy Compliance", "Agent" →
//                      credentials/agent required — DEFENDER signal only.
//                      A credentialed-only Tenable detection actually means
//                      the external attacker faces higher recon uncertainty.
//
// OPES difficulty (E) impact:
//
//   OTX ≥20 pulses + Nuclei exploit → E −2.5  (active campaign + weaponised tool)
//   OTX ≥20 pulses only            → E −2.0  (targeted at internet scale)
//   Nuclei exploit template        → E −1.5  (one-command exploitation possible)
//   Nuclei detect / OTX 5–19       → E −1.0  (target identification automatable)
//   Tenable remote (no auth)       → E −0.5  (externally replicatable check)
//   Credentialed/agent only        → E +0.5  (attacker cannot detect externally)

package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Result types ──────────────────────────────────────────────────────────────

// OTXResult holds CVE-specific threat intelligence from AlienVault Open Threat
// Exchange. The pulse count is the number of community threat-intel reports
// referencing this CVE — a strong proxy for attacker tooling deployment.
// No API key required; the CVE indicator endpoint is publicly accessible.
type OTXResult struct {
	Found           bool     `json:"found"`
	PulseCount      int      `json:"pulse_count,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	MalwareFamilies []string `json:"malware_families,omitempty"`
	Note            string   `json:"note,omitempty"`
}

// TenableResult holds plugin coverage from Tenable's plugin database,
// classified into remote (no-auth) vs local (credentialed/agent).
// Only remote plugins are attacker-relevant — local ones are defender signals.
type TenableResult struct {
	Found          bool     `json:"found"`
	TotalCount     int      `json:"total_count,omitempty"`
	RemoteCount    int      `json:"remote_count,omitempty"`
	LocalCount     int      `json:"local_count,omitempty"`
	Families       []string `json:"families,omitempty"`
	RemoteFamilies []string `json:"remote_families,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// NucleiDiscoveryResult extends the basic Nuclei check with template-type
// classification: exploit (sends payload) vs detect (confirms endpoint active)
// vs version (passive fingerprint only).
type NucleiDiscoveryResult struct {
	Found              bool     `json:"found"`
	TotalTemplates     int      `json:"total_templates,omitempty"`
	RemoteExploitCount int      `json:"remote_exploit_count,omitempty"`
	RemoteDetectCount  int      `json:"remote_detect_count,omitempty"`
	VersionDetectCount int      `json:"version_detect_count,omitempty"`
	TemplatePaths      []string `json:"template_paths,omitempty"`
	Note               string   `json:"note,omitempty"`
}

// AttackerDiscoverabilityResult synthesises OTX + Nuclei + Tenable into a
// single attacker-perspective discoverability tier and score.
type AttackerDiscoverabilityResult struct {
	OTX     OTXResult             `json:"otx"`
	Nuclei  NucleiDiscoveryResult `json:"nuclei"`
	Tenable TenableResult         `json:"tenable"`

	// Tier is the overall attacker discoverability classification:
	//   "mass_scanned"       OTX high pulse count or active scanning evidence
	//   "remote_exploit"     Nuclei exploit/detect template or Tenable remote plugin
	//   "version_detectable" Only version fingerprint accessible remotely
	//   "credentialed_only"  Only findable with credentials/agent — attacker blind
	//   "unknown"            No scanner coverage data available
	Tier  string  `json:"tier"`
	Score float64 `json:"score"` // 0–10

	Note string `json:"note,omitempty"`
}

// ── Tenable family classification ─────────────────────────────────────────────

var tenableLocalFamilyKeywords = []string{
	"local security checks",
	"policy compliance",
	"settings",
	"patch management",
	"agent",
	"windows: microsoft bulletins",
	"windows: user management",
	"slackware local security checks",
	"solaris local security checks",
	"compliance",
}

func isTenableLocalFamily(family string) bool {
	lower := strings.ToLower(family)
	for _, kw := range tenableLocalFamilyKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return strings.Contains(lower, "local")
}

// ── Nuclei path classification ────────────────────────────────────────────────

func classifyNucleiPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/cves/"),
		strings.Contains(lower, "/exploits/"),
		strings.Contains(lower, "/rce/"),
		strings.Contains(lower, "/sqli/"),
		strings.Contains(lower, "/ssrf/"),
		strings.Contains(lower, "/lfi/"),
		strings.HasPrefix(lower, "cves/"):
		return "exploit"
	case strings.Contains(lower, "/technologies/"),
		strings.Contains(lower, "/fingerprint"),
		strings.Contains(lower, "/version-detect"),
		strings.HasPrefix(lower, "technologies/"),
		strings.HasSuffix(lower, "-detect.yaml"):
		return "version"
	default:
		// exposed-panels, misconfiguration, exposures → unauthenticated endpoint probe
		return "detect"
	}
}

// ── AlienVault OTX ────────────────────────────────────────────────────────────

// FetchOTXCVE checks AlienVault Open Threat Exchange for threat intelligence
// pulses referencing this CVE. No API key required.
//
// Pulse count interpretation:
//   1–4  pulses → tracked but niche; low attacker tooling deployment
//   5–19 pulses → moderate community interest; some tooling likely
//   20+  pulses → high interest / active campaigns; tooling widely deployed
func FetchOTXCVE(ctx context.Context, cveID string) OTXResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf(
		"https://otx.alienvault.com/api/v1/indicator/cve/%s/general",
		url.PathEscape(strings.ToUpper(cveID)),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return OTXResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return OTXResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return OTXResult{Found: false}
	case http.StatusTooManyRequests:
		return OTXResult{Note: "OTX: rate limited"}
	}
	if resp.StatusCode != http.StatusOK {
		return OTXResult{Note: fmt.Sprintf("OTX HTTP %d", resp.StatusCode)}
	}

	var payload struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Tags            []string `json:"tags"`
				MalwareFamilies []struct {
					DisplayName string `json:"display_name"`
				} `json:"malware_families"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&payload); err != nil {
		return OTXResult{Note: "JSON decode failed"}
	}

	count := payload.PulseInfo.Count
	if count == 0 {
		return OTXResult{Found: false}
	}

	tagSet := make(map[string]struct{})
	malwareSet := make(map[string]struct{})
	for _, p := range payload.PulseInfo.Pulses {
		for _, t := range p.Tags {
			if t != "" {
				tagSet[strings.ToLower(t)] = struct{}{}
			}
		}
		for _, m := range p.MalwareFamilies {
			if m.DisplayName != "" {
				malwareSet[m.DisplayName] = struct{}{}
			}
		}
	}
	tags := mapKeys(tagSet)
	malware := mapKeys(malwareSet)

	interestLevel := "low"
	switch {
	case count >= 20:
		interestLevel = "high"
	case count >= 5:
		interestLevel = "moderate"
	}

	malwareSuffix := ""
	if len(malware) > 0 {
		shown := malware
		if len(shown) > 5 {
			shown = shown[:5]
		}
		malwareSuffix = " — malware families: " + strings.Join(shown, ", ")
	}

	return OTXResult{
		Found:           true,
		PulseCount:      count,
		Tags:            tags,
		MalwareFamilies: malware,
		Note: fmt.Sprintf(
			"OTX: %d pulse(s) referencing %s (interest: %s)%s",
			count, cveID, interestLevel, malwareSuffix,
		),
	}
}

// ── Tenable ───────────────────────────────────────────────────────────────────

// FetchTenablePlugins checks the Tenable plugin database and classifies
// results as remote (attacker-replicatable) vs credentialed/agent (defender only).
func FetchTenablePlugins(ctx context.Context, cveID string) TenableResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	searchURL := fmt.Sprintf(
		"https://www.tenable.com/plugins/search?q=%%22%s%%22&sort=&page=1",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return TenableResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return TenableResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return TenableResult{Note: fmt.Sprintf("Tenable HTTP %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return TenableResult{Note: "read failed"}
	}
	page := string(body)

	if strings.Contains(page, "0 Total") || !strings.Contains(strings.ToUpper(page), strings.ToUpper(cveID)) {
		return TenableResult{Found: false}
	}

	families := make([]string, 0)
	remoteFamilies := make([]string, 0)
	remoteCount, localCount := 0, 0

	content := page
	const familyPrefix = `/plugins/nessus/families/`
	for {
		idx := strings.Index(content, familyPrefix)
		if idx == -1 {
			break
		}
		content = content[idx+len(familyPrefix):]
		end := strings.IndexAny(content, `"'>`)
		if end == -1 {
			break
		}
		raw := content[:end]
		family := strings.ReplaceAll(strings.ReplaceAll(raw, "-", " "), "%20", " ")

		if family != "" && !containsStr(families, family) {
			families = append(families, family)
			if isTenableLocalFamily(family) {
				localCount++
			} else {
				remoteCount++
				remoteFamilies = append(remoteFamilies, family)
			}
		}
	}

	if len(families) == 0 {
		return TenableResult{Found: false, Note: "Tenable: no plugin families parsed"}
	}

	var note string
	if remoteCount == 0 {
		note = fmt.Sprintf(
			"Tenable: %d family(ies) ALL require credentials/agent (%s) — external attacker cannot replicate",
			len(families), strings.Join(families, ", "),
		)
	} else {
		note = fmt.Sprintf(
			"Tenable: %d remote (no-auth: %s), %d credentialed/local",
			remoteCount, strings.Join(remoteFamilies, ", "), localCount,
		)
	}

	return TenableResult{
		Found:          true,
		TotalCount:     len(families),
		RemoteCount:    remoteCount,
		LocalCount:     localCount,
		Families:       families,
		RemoteFamilies: remoteFamilies,
		Note:           note,
	}
}

// ── Nuclei (classified) ───────────────────────────────────────────────────────

// FetchNucleiDiscovery searches for Nuclei templates and classifies each
// by exploit / detect / version-only category.
func FetchNucleiDiscovery(ctx context.Context, cveID string) NucleiDiscoveryResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	searchURL := fmt.Sprintf(
		"https://api.github.com/search/code?q=%s+repo:projectdiscovery/nuclei-templates+extension:yaml",
		url.QueryEscape(cveID),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return NucleiDiscoveryResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NucleiDiscoveryResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return NucleiDiscoveryResult{Note: "GitHub rate-limited; set GITHUB_TOKEN for higher limits"}
	}
	if resp.StatusCode != http.StatusOK {
		return NucleiDiscoveryResult{Note: fmt.Sprintf("HTTP %d from GitHub", resp.StatusCode)}
	}

	var payload struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Path string `json:"path"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return NucleiDiscoveryResult{Note: "JSON decode failed"}
	}
	if payload.TotalCount == 0 {
		return NucleiDiscoveryResult{Found: false}
	}

	exploitCount, detectCount, versionCount := 0, 0, 0
	paths := make([]string, 0, len(payload.Items))
	for _, item := range payload.Items {
		paths = append(paths, item.Path)
		switch classifyNucleiPath(item.Path) {
		case "exploit":
			exploitCount++
		case "version":
			versionCount++
		default:
			detectCount++
		}
	}

	attackerCapability := "identify the vulnerable version passively"
	if exploitCount > 0 {
		attackerCapability = "execute the full exploit chain remotely without credentials"
	} else if detectCount > 0 {
		attackerCapability = "confirm the vulnerable endpoint/feature is active"
	}

	return NucleiDiscoveryResult{
		Found:              true,
		TotalTemplates:     payload.TotalCount,
		RemoteExploitCount: exploitCount,
		RemoteDetectCount:  detectCount,
		VersionDetectCount: versionCount,
		TemplatePaths:      paths,
		Note: fmt.Sprintf(
			"Nuclei: %d template(s) — %d exploit, %d detect, %d version-only. Attacker can: %s.",
			payload.TotalCount, exploitCount, detectCount, versionCount, attackerCapability,
		),
	}
}

// ── Synthesis ─────────────────────────────────────────────────────────────────

// ComputeAttackerDiscoverability synthesises OTX, Nuclei, and Tenable signals
// into a single attacker-perspective tier and 0–10 score.
func ComputeAttackerDiscoverability(
	otx OTXResult,
	nuclei NucleiDiscoveryResult,
	tenable TenableResult,
) AttackerDiscoverabilityResult {
	score := 0.0
	tier := "unknown"
	var notes []string

	// OTX pulse count: attacker community interest signal
	if otx.Found && otx.PulseCount >= 20 && nuclei.RemoteExploitCount > 0 {
		score = max64(score, 9.5)
		tier = "mass_scanned"
		notes = append(notes, fmt.Sprintf(
			"OTX %d pulses + Nuclei exploit template — active campaign with weaponised tooling",
			otx.PulseCount,
		))
	} else if otx.Found && otx.PulseCount >= 20 {
		score = max64(score, 9.0)
		tier = "mass_scanned"
		notes = append(notes, fmt.Sprintf(
			"OTX: %d pulses — high community interest, active targeting campaigns",
			otx.PulseCount,
		))
	} else if otx.Found && otx.PulseCount >= 5 {
		score = max64(score, 7.0)
		if tier == "unknown" {
			tier = "remote_exploit"
		}
		notes = append(notes, fmt.Sprintf("OTX: %d pulses — moderate threat-intel interest", otx.PulseCount))
	} else if otx.Found && otx.PulseCount > 0 {
		score = max64(score, 4.0)
		notes = append(notes, fmt.Sprintf("OTX: %d pulse(s) — low/niche interest", otx.PulseCount))
	}

	// Nuclei exploit template (highest attacker capability signal)
	if nuclei.RemoteExploitCount > 0 {
		score = max64(score, 8.0)
		if tier == "unknown" {
			tier = "remote_exploit"
		}
		notes = append(notes, fmt.Sprintf(
			"Nuclei: %d exploit template(s) — full remote exploitation automatable",
			nuclei.RemoteExploitCount,
		))
	}

	// Nuclei detect template
	if nuclei.RemoteDetectCount > 0 {
		score = max64(score, 6.5)
		if tier == "unknown" {
			tier = "remote_exploit"
		}
		notes = append(notes, fmt.Sprintf(
			"Nuclei: %d detect template(s) — vulnerable endpoint confirmable without credentials",
			nuclei.RemoteDetectCount,
		))
	}

	// Tenable remote plugin (no auth)
	if tenable.RemoteCount > 0 {
		score = max64(score, 5.5)
		if tier == "unknown" {
			tier = "remote_exploit"
		}
		notes = append(notes, fmt.Sprintf(
			"Tenable: %d remote plugin(s) (families: %s) — attacker can replicate externally",
			tenable.RemoteCount, strings.Join(tenable.RemoteFamilies, ", "),
		))
	}

	// Nuclei version-only (passive fingerprint)
	if nuclei.VersionDetectCount > 0 && nuclei.RemoteExploitCount == 0 && nuclei.RemoteDetectCount == 0 {
		score = max64(score, 4.5)
		if tier == "unknown" {
			tier = "version_detectable"
		}
		notes = append(notes, fmt.Sprintf(
			"Nuclei: %d version-detect template(s) — version visible passively, feature reachability unknown",
			nuclei.VersionDetectCount,
		))
	}

	// Credentialed/agent only — defender signal, increases attacker difficulty
	if tenable.Found && tenable.LocalCount > 0 && tenable.RemoteCount == 0 &&
		!nuclei.Found && !otx.Found {
		score = max64(score, 1.0)
		if tier == "unknown" {
			tier = "credentialed_only"
		}
		notes = append(notes, fmt.Sprintf(
			"Tenable: %d credentialed/agent plugin(s) only — external attacker cannot replicate; difficulty raised",
			tenable.LocalCount,
		))
	}

	if len(notes) == 0 {
		notes = append(notes, "No automated scanner coverage found — attacker must manually identify vulnerability")
	}

	return AttackerDiscoverabilityResult{
		OTX:     otx,
		Nuclei:  nuclei,
		Tenable: tenable,
		Tier:    tier,
		Score:   score,
		Note:    strings.Join(notes, "; "),
	}
}

// ── Concurrent fetch ──────────────────────────────────────────────────────────

// FetchAttackerDiscoverability runs OTX + Nuclei + Tenable concurrently.
func FetchAttackerDiscoverability(ctx context.Context, cveID string) AttackerDiscoverabilityResult {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		otx     OTXResult
		nuclei  NucleiDiscoveryResult
		tenable TenableResult
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		r := FetchOTXCVE(ctx, cveID)
		mu.Lock()
		otx = r
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := FetchNucleiDiscovery(ctx, cveID)
		mu.Lock()
		nuclei = r
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := FetchTenablePlugins(ctx, cveID)
		mu.Lock()
		tenable = r
		mu.Unlock()
	}()
	wg.Wait()

	return ComputeAttackerDiscoverability(otx, nuclei, tenable)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func max64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
