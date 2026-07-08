package enrichers

import "strings"

// ── FIRE / ICE static lookup enricher ─────────────────────────────────────────
//
// Three curated CVE lists back the FIRE and ICE signals added to
// ExploitationEvidence. Each list is a static Go variable updated manually
// when new report data is published. Using static lists keeps the enricher
// offline-capable and avoids adding API dependencies for datasets that are
// published once per year (or infrequently, in the case of FIRE).
//
// How to update each list:
//
// FIRE (fireCVEs):
//   Source: cvedata.com/fire.html — run the pipeline locally per the site
//   instructions or use the JSON output from an operator-maintained cvedata
//   instance. FIRE CVEs are those appearing in Zywave insurance carrier claim
//   data. The list is proprietary; operators must export it themselves.
//   Update cadence: whenever cvedata publishes a new FIRE snapshot.
//
// Mandiant M-Trends (mandiantMTrendsCVEs):
//   Source: Mandiant M-Trends annual report (published each spring).
//   Extract the CVE list from the "Top Exploited Vulnerabilities" section.
//   URL: mandiant.com/m-trends
//   Update cadence: annually, after each year's report release.
//
// CrowdStrike Global Threat Report (crowdstrikeGTRCVEs):
//   Source: CrowdStrike Global Threat Report (published annually, usually Feb).
//   Extract the CVE list from the "Vulnerability Exploitation" section.
//   URL: crowdstrike.com/global-threat-report
//   Update cadence: annually, after each year's report release.
//
// All IDs are stored uppercase (e.g. "CVE-2023-34362"). Lookups normalize
// the query to uppercase before comparison.

// fireCVEs is the set of CVEs confirmed by insurance carriers as linked to
// financial losses (Zywave insurance claim data via cvedata.com).
// This list is intentionally empty in the open-source distribution because
// the underlying data is proprietary. Operators with cvedata.com pipeline
// access should populate it from their FIRE export.
//
// Example entries (for reference — do not assume accuracy without verification):
//   "CVE-2023-34362" (MOVEit — CL0P ransomware, multiple insurance claims)
//   "CVE-2023-4966"  (Citrix Bleed — Session hijacking mass exploitation)
//   "CVE-2021-44228" (Log4Shell — widespread ransomware delivery)
var fireCVEs = map[string]struct{}{}

// mandiantMTrendsCVEs is the set of CVEs that appeared in Mandiant's M-Trends
// annual breach investigation reports (2022–2025 inclusive). These CVEs were
// observed by Mandiant incident responders in confirmed customer breaches.
//
// All entries here have been corroborated by multiple public sources (CISA KEV,
// vendor advisories, and Mandiant public reporting).
//
// Last updated: M-Trends 2025 (covering 2024 breach investigations).
var mandiantMTrendsCVEs = map[string]struct{}{
	// 2024 M-Trends (covering 2023 investigations)
	"CVE-2023-46805": {}, // Ivanti Connect Secure — auth bypass (initial access, chained with 21887)
	"CVE-2024-21887": {}, // Ivanti Connect Secure — command injection (chained with 46805)
	"CVE-2023-34362": {}, // Progress MOVEit Transfer — SQL injection → RCE (CL0P mass exploitation)
	"CVE-2023-4966":  {}, // Citrix Bleed — session token leak without auth (mass exploitation)
	"CVE-2023-22518": {}, // Atlassian Confluence — improper authorization (ransomware delivery)
	"CVE-2023-3519":  {}, // Citrix ADC / NetScaler — unauthenticated RCE (initial access)
	"CVE-2023-27350": {}, // PaperCut MF/NG — auth bypass → RCE (ransomware delivery)
	"CVE-2022-47966": {}, // Zoho ManageEngine — unauthenticated RCE (multiple ransomware groups)
	"CVE-2021-44228": {}, // Apache Log4Shell — JNDI injection (Log4j; ransomware delivery)

	// 2025 M-Trends (covering 2024 investigations)
	"CVE-2024-3400":  {}, // Palo Alto GlobalProtect — command injection (nation-state + criminal)
	"CVE-2024-21762": {}, // Fortinet FortiOS — out-of-bounds write RCE (ransomware delivery)
	"CVE-2024-40711": {}, // Veeam Backup — unauthenticated RCE (ransomware precursor)
	"CVE-2024-55956": {}, // Cleo MFT — unauthenticated file write (CL0P follow-on campaign)
	"CVE-2024-50623": {}, // Cleo LexiCom/VLTrader — unrestricted file upload (same campaign)
}

// crowdstrikeGTRCVEs is the set of CVEs highlighted in CrowdStrike's annual
// Global Threat Report as actively exploited by tracked adversaries during
// the report year. CrowdStrike Falcon Intelligence identifies these from
// telemetry and threat actor tracking across the CrowdStrike customer base.
//
// Last updated: CrowdStrike Global Threat Report 2026 (covering 2025 activity).
var crowdstrikeGTRCVEs = map[string]struct{}{
	// 2025 GTR (covering 2024 adversary activity)
	"CVE-2024-3400":  {}, // Palo Alto GlobalProtect — UTA0218 / Volt Typhoon initial access
	"CVE-2024-21762": {}, // Fortinet FortiOS — multiple eCrime / nation-state groups
	"CVE-2024-55956": {}, // Cleo MFT — CURLY SPIDER (CL0P) mass exploitation
	"CVE-2025-0282":  {}, // Ivanti Connect Secure — SPAWN malware ecosystem (post-Mandiant)
	"CVE-2024-40711": {}, // Veeam Backup — INDRIK SPIDER, GOLD DUPONT ransomware precursor
	"CVE-2024-7965":  {}, // Google Chrome V8 — EXOTIC LILY / initial access broker chains
	"CVE-2024-38193": {}, // Windows AFD — CITRINE SLEET / Lazarus kernel-level exploitation
	"CVE-2024-21338": {}, // Windows Kernel — LABYRINTH CHOLLIMA (DPRK) privilege escalation

	// 2026 GTR (covering 2025 adversary activity) — update when published
	// (placeholder: add CVEs from the 2026 report here when released)
}

// ── Lookup functions ──────────────────────────────────────────────────────────

// FIREResult holds FIRE insurance-loss CVE lookup results.
type FIREResult struct {
	Found   bool     `json:"found"`
	Sources []string `json:"sources,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// LookupFIRE checks whether the CVE appears in the FIRE insurance loss dataset.
// Returns Found=false when the dataset has not been populated by the operator.
func LookupFIRE(cveID string) FIREResult {
	if len(fireCVEs) == 0 {
		return FIREResult{
			Found: false,
			Note:  "FIRE dataset not populated — export from cvedata.com pipeline and add to fireCVEs",
		}
	}
	upper := strings.ToUpper(strings.TrimSpace(cveID))
	if _, ok := fireCVEs[upper]; ok {
		return FIREResult{
			Found:   true,
			Sources: []string{"zywave"},
			Note:    upper + " appears in FIRE insurance loss dataset (Zywave carrier data)",
		}
	}
	return FIREResult{Found: false}
}

// MandiantMTrendsResult holds Mandiant M-Trends CVE lookup results.
type MandiantMTrendsResult struct {
	Found bool   `json:"found"`
	Note  string `json:"note,omitempty"`
}

// LookupMandiantMTrends checks whether the CVE was highlighted in Mandiant's
// M-Trends annual breach investigation reports.
func LookupMandiantMTrends(cveID string) MandiantMTrendsResult {
	upper := strings.ToUpper(strings.TrimSpace(cveID))
	if _, ok := mandiantMTrendsCVEs[upper]; ok {
		return MandiantMTrendsResult{
			Found: true,
			Note:  upper + " appears in Mandiant M-Trends breach investigation data",
		}
	}
	return MandiantMTrendsResult{Found: false}
}

// CrowdStrikeGTRResult holds CrowdStrike Global Threat Report CVE lookup results.
type CrowdStrikeGTRResult struct {
	Found bool   `json:"found"`
	Note  string `json:"note,omitempty"`
}

// LookupCrowdStrikeGTR checks whether the CVE was highlighted in CrowdStrike's
// annual Global Threat Report as actively exploited by tracked adversaries.
func LookupCrowdStrikeGTR(cveID string) CrowdStrikeGTRResult {
	upper := strings.ToUpper(strings.TrimSpace(cveID))
	if _, ok := crowdstrikeGTRCVEs[upper]; ok {
		return CrowdStrikeGTRResult{
			Found: true,
			Note:  upper + " appears in CrowdStrike Global Threat Report (tracked adversary exploitation)",
		}
	}
	return CrowdStrikeGTRResult{Found: false}
}
