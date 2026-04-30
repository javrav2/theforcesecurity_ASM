// Package tools provides the Oracle-specific tools available to the ReAct loop.
//
// Each tool implements react.Tool and is registered into a react.Registry
// by BuildRegistry. Tools are deliberately thin — they do the minimum work
// to surface structured data to the LLM and return it as JSON text.
//
// Tool contract for the LLM:
//   - lookup_cve              — fetch CVE metadata + description from the store
//   - get_asset               — fetch an asset record and its signals from inventory
//   - check_epss_kev          — fetch EPSS score and CISA/VulnCheck KEV status
//   - search_exploit_evidence — search for public PoCs, Exploit-DB, GHSA
//   - lookup_kb_pattern       — query the KB for matching CWE / dev patterns
//   - get_open_findings       — list Oracle findings, optionally filtered
//   - run_analysis            — execute the full Phase A → Phase B → OPES pipeline
//   - check_breach_context    — VCDB breach records + ENISA EUVD + Google P0
//   - check_attackerkb        — AttackerKB community practitioner scoring
//   - check_weaponization     — Metasploit exploit modules + Nuclei templates
//   - check_cisa_vulnrichment — CISA Vulnrichment CVSS 4.0 + SSVC triage decision
//   - check_regional_nvds     — JVN iPedia (JP) + BDU FSTEC (RU) national DB coverage
//   - check_attack_mappings   — MITRE ATT&CK + Mappings Explorer CVE→TTP techniques
//   - map_owasp               — static CWE→OWASP Top 10 2021 category mapping
package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/internal/knowledgebase"
	"github.com/your-org/aegis-oracle/internal/modules/enrichers"
	"github.com/your-org/aegis-oracle/internal/pipeline"
	"github.com/your-org/aegis-oracle/internal/react"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

// ─────────────────────────── Deps ────────────────────────────────────────────

// Deps are the shared dependencies injected into every tool at build time.
type Deps struct {
	Store   ToolStore
	Runner  *pipeline.Runner
	KB      *knowledgebase.KB
	PDCPKey string // ProjectDiscovery Cloud Platform API key (optional; higher rate limits)
}

// ToolStore is the minimal persistence surface tools need.
type ToolStore interface {
	GetCVE(ctx context.Context, cveID string) (*schema.CVE, error)
	GetAsset(ctx context.Context, assetID string) (*schema.Asset, error)
	GetOpenFindings(ctx context.Context, cveID, assetID string) ([]*schema.Finding, error)
	GetIntrinsicAnalysis(ctx context.Context, cveID string) (*schema.IntrinsicAnalysis, error)
}

// ─────────────────────────── BuildRegistry ────────────────────────────────

// BuildRegistry constructs and returns a react.Registry populated with all
// Oracle tools wired to the provided dependencies.
func BuildRegistry(d Deps) *react.Registry {
	reg := react.NewRegistry()
	reg.Register(&lookupCVETool{store: d.Store})
	reg.Register(&getAssetTool{store: d.Store})
	reg.Register(&searchVulnxTool{pdcpKey: d.PDCPKey})    // single CVE deep-dive (ID lookup)
	reg.Register(&vulnxSearchTool{pdcpKey: d.PDCPKey})    // CVE discovery by technology/query
	reg.Register(&checkEPSSKEVTool{})                     // EPSS + KEV (no API key needed)
	reg.Register(&searchExploitEvidenceTool{})            // cvelistV5 + GHSA advisory text
	reg.Register(&lookupKBPatternTool{kb: d.KB})
	reg.Register(&getOpenFindingsTool{store: d.Store})
	reg.Register(&runAnalysisTool{runner: d.Runner})
	reg.Register(&checkBreachContextTool{})               // VCDB + ENISA EUVD + Google P0
	reg.Register(&checkAttackerKBTool{})                  // community practitioner scoring
	reg.Register(&checkWeaponizationTool{})               // Metasploit modules + Nuclei templates
	reg.Register(&checkCISAVulnrichmentTool{})            // CVSS 4.0 + SSVC from CISA
	reg.Register(&checkRegionalNVDsTool{})                // JVN iPedia (JP) + BDU FSTEC (RU)
	reg.Register(&checkATTACKMappingsTool{})              // MITRE ATT&CK CVE→TTP mappings
	reg.Register(&mapOWASPTool{})                         // CWE → OWASP Top 10 (static)
	return reg
}

// ─────────────────────────── lookup_cve ─────────────────────────────────────

type lookupCVETool struct{ store ToolStore }

func (t *lookupCVETool) Name() string { return "lookup_cve" }
func (t *lookupCVETool) Description() string {
	return "Fetch CVE metadata (description, CVSS, CWEs, affected packages) from the Oracle store. " +
		"If the CVE is not yet ingested it returns a not-found message — use the CVE ID from the user question."
}
func (t *lookupCVETool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2025-55130",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *lookupCVETool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cve, err := t.store.GetCVE(ctx, strings.ToUpper(cveID))
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	if cve == nil {
		return fmt.Sprintf(`{"found":false,"cve_id":%q,"note":"CVE not yet ingested. Proceed with what you know from training data and label confidence as low."}`, cveID), nil
	}
	b, _ := json.MarshalIndent(cve, "", "  ")
	return string(b), nil
}

// ─────────────────────────── search_vulnx ───────────────────────────────────

// searchVulnxTool calls the ProjectDiscovery vulnx API
// (https://api.projectdiscovery.io/v2/vulnerability/{id}) and returns a
// structured snapshot combining CVSS, EPSS, CISA KEV, VulnCheck KEV, PoC
// tracking, HackerOne stats, Nuclei template coverage, Shodan/Fofa exposure,
// affected products, requirements (preconditions), and remediation guidance.
//
// This is the richest single-call CVE data source available and should be
// preferred over the separate check_epss_kev + search_exploit_evidence calls
// when a PDCP key is available. Works unauthenticated with stricter rate limits.
type searchVulnxTool struct{ pdcpKey string }

func (t *searchVulnxTool) Name() string { return "search_vulnx" }
func (t *searchVulnxTool) Description() string {
	return "Query the ProjectDiscovery vulnx API for rich CVE intelligence in one call: " +
		"CVSS, EPSS, CISA KEV, VulnCheck KEV, PoC URLs, HackerOne report count, " +
		"Nuclei template name, internet exposure (Shodan/Fofa), affected products, " +
		"requirements/preconditions, and remediation guidance. " +
		"Prefer this over check_epss_kev and search_exploit_evidence when available."
}
func (t *searchVulnxTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *searchVulnxTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	url := fmt.Sprintf("https://api.projectdiscovery.io/v2/vulnerability/%s", cveID)
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	if t.pdcpKey != "" {
		req.Header.Set("X-PDCP-Key", t.pdcpKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vulnx API: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Sprintf(`{"found":false,"cve_id":%q,"note":"CVE not in ProjectDiscovery database."}`, cveID), nil
	case http.StatusTooManyRequests:
		return fmt.Sprintf(`{"rate_limited":true,"cve_id":%q,"note":"vulnx rate limit hit. Set PDCP_API_KEY for higher limits."}`, cveID), nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vulnx HTTP %d for %s", resp.StatusCode, cveID)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	// Parse top-level envelope {"data": {...}}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Data == nil {
		// Return raw JSON if parsing fails — LLM can still read it
		return string(body), nil
	}
	d := envelope.Data

	// Re-serialise as pretty-printed JSON so the LLM can read it clearly.
	// Filter to the fields most useful for exploitability reasoning.
	useful := map[string]any{
		"cve_id":           cveID,
		"severity":         d["severity"],
		"cvss_score":       d["cvss_score"],
		"cvss_metrics":     d["cvss_metrics"],
		"epss_score":       d["epss_score"],
		"epss_percentile":  d["epss_percentile"],
		"is_kev":           d["is_kev"],
		"is_vkev":          d["is_vkev"],
		"kev":              d["kev"],
		"is_poc":           d["is_poc"],
		"poc_count":        d["poc_count"],
		"pocs":             d["pocs"],
		"h1":               d["h1"],
		"is_template":      d["is_template"],
		"filename":         d["filename"],
		"tags":             d["tags"],
		"requirements":     d["requirements"],
		"requirement_type": d["requirement_type"],
		"exposure":         d["exposure"],
		"affected_products": limitSlice(d["affected_products"], 5),
		"description":      truncStr(d["description"], 600),
		"remediation":      truncStr(d["remediation"], 400),
		"cwe":              d["cwe"],
		"is_remote":        d["is_remote"],
		"is_auth":          d["is_auth"],
		"is_patch_available": d["is_patch_available"],
		"vuln_status":      d["vuln_status"],
	}
	out, _ := json.MarshalIndent(useful, "", "  ")
	return string(out), nil
}

// ─────────────────────────── vulnx_search ───────────────────────────────────

// vulnxSearchTool uses the ProjectDiscovery PDCP search API to find CVEs
// matching a rich query string — technology, severity, exploit status, date
// ranges — and returns a summary list. This is distinct from search_vulnx
// (which fetches a single CVE by ID): vulnx_search is for DISCOVERY (e.g.
// "what high-severity remotely-exploitable CVEs affect Node.js 24?") while
// search_vulnx is for ENRICHMENT (deep intel on a known CVE ID).
//
// If vulnx binary is installed, it is exec'd with --json --silent for the
// richest output. Falls back to the PDCP HTTP search API otherwise.
type vulnxSearchTool struct{ pdcpKey string }

func (t *vulnxSearchTool) Name() string { return "vulnx_search" }
func (t *vulnxSearchTool) Description() string {
	return "Search the ProjectDiscovery vulnerability database using a rich query string. " +
		"Use this to DISCOVER CVEs relevant to a technology stack or asset profile — e.g. " +
		"'nodejs && severity:high && is_remote:true', " +
		"'apache && is_kev:true', " +
		"'severity:critical && is_poc:true && age_in_days:<30'. " +
		"Supports boolean logic (&&, ||, NOT), field filters (severity:, cvss_score:>, epss_score:>, is_kev:, is_poc:, " +
		"is_template:, is_remote:, affected_products.vendor:, affected_products.product:, age_in_days:), " +
		"and date ranges (cve_created_at:>=2024). Returns a ranked list of matching CVEs. " +
		"Distinct from search_vulnx (single CVE deep-dive) — use this when you don't have a specific CVE yet."
}
func (t *vulnxSearchTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "vulnx query string, e.g. 'nodejs && severity:high && is_remote:true'",
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": "Max results to return (default 10, max 25)",
			},
			"sort": map[string]any{
				"type":        "string",
				"description": "Field to sort descending by: cvss_score, epss_score, cve_created_at (default: cvss_score)",
			},
		},
		"required": []string{"query"},
	}
}

func (t *vulnxSearchTool) Run(ctx context.Context, args map[string]any) (string, error) {
	query, _ := args["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	limit := 10
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int(l)
	}
	if limit > 25 {
		limit = 25
	}
	sortField := "cvss_score"
	if s, ok := args["sort"].(string); ok && s != "" {
		sortField = s
	}

	// Prefer binary exec if available.
	if result, err := t.runViaBinary(ctx, query, limit, sortField); err == nil {
		return result, nil
	}

	// Fall back to HTTP API.
	return t.runViaAPI(ctx, query, limit, sortField)
}

func (t *vulnxSearchTool) runViaBinary(ctx context.Context, query string, limit int, sort string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmdArgs := []string{
		"search", query,
		"--json", "--silent", "--disable-update-check",
		"--limit", fmt.Sprintf("%d", limit),
		"--sort-desc", sort,
	}
	out, err := runCommand(execCtx, "vulnx", cmdArgs, map[string]string{
		"PDCP_API_KEY": t.pdcpKey,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (t *vulnxSearchTool) runViaAPI(ctx context.Context, query string, limit int, sort string) (string, error) {
	// PDCP search API: GET /v2/vulnerability?q=QUERY&limit=N&sort-desc=FIELD
	apiURL := fmt.Sprintf(
		"https://api.projectdiscovery.io/v2/vulnerability?q=%s&limit=%d&sort-desc=%s",
		urlEncodeQuery(query), limit, sort,
	)

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	if t.pdcpKey != "" {
		req.Header.Set("X-PDCP-Key", t.pdcpKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vulnx search API: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return fmt.Sprintf(`{"rate_limited":true,"note":"vulnx rate limit. Set PDCP_API_KEY for higher limits.","query":%q}`, query), nil
	case http.StatusUnauthorized:
		return fmt.Sprintf(`{"error":"unauthorized","note":"PDCP_API_KEY invalid or missing.","query":%q}`, query), nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vulnx search HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	// The response is {"data": {"vulnerabilities": [...], "count": N}} or similar.
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return string(body), nil
	}

	// Normalise to a clean summary list for the LLM.
	data, _ := envelope["data"].(map[string]any)
	if data == nil {
		// Try flat array response.
		return summariseVulnList(body, query), nil
	}
	vulnsAny := data["vulnerabilities"]
	if vulnsAny == nil {
		vulnsAny = data["data"]
	}
	if vulnsAny == nil {
		return string(body), nil
	}
	vulnBytes, _ := json.Marshal(vulnsAny)
	return summariseVulnList(vulnBytes, query), nil
}

// summariseVulnList renders a list of vulnerability objects as a compact
// summary the LLM can scan quickly without hitting token limits.
func summariseVulnList(raw []byte, query string) string {
	var vulns []map[string]any
	if err := json.Unmarshal(raw, &vulns); err != nil {
		return string(raw)
	}
	if len(vulns) == 0 {
		return fmt.Sprintf(`{"query":%q,"count":0,"note":"No CVEs matched the query."}`, query)
	}
	type row struct {
		CVEID    string  `json:"cve_id"`
		Severity string  `json:"severity"`
		CVSS     float64 `json:"cvss_score"`
		EPSS     float64 `json:"epss_score"`
		IsKEV    bool    `json:"is_kev"`
		IsPOC    bool    `json:"is_poc"`
		IsRemote bool    `json:"is_remote"`
		Template bool    `json:"is_template"`
		Age      any     `json:"age_in_days"`
		Desc     string  `json:"description"`
	}
	var rows []row
	for _, v := range vulns {
		r := row{}
		r.CVEID, _ = v["cve_id"].(string)
		r.Severity, _ = v["severity"].(string)
		r.CVSS, _ = v["cvss_score"].(float64)
		r.EPSS, _ = v["epss_score"].(float64)
		r.IsKEV, _ = v["is_kev"].(bool)
		r.IsPOC, _ = v["is_poc"].(bool)
		r.IsRemote, _ = v["is_remote"].(bool)
		r.Template, _ = v["is_template"].(bool)
		r.Age = v["age_in_days"]
		desc, _ := v["description"].(string)
		if len(desc) > 150 {
			desc = desc[:150] + "…"
		}
		r.Desc = desc
		rows = append(rows, r)
	}
	out := map[string]any{
		"query":           query,
		"count":           len(rows),
		"vulnerabilities": rows,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

func urlEncodeQuery(q string) string {
	// Manual percent-encoding of the query string without importing net/url
	// (which is already imported via the http package).
	var sb strings.Builder
	for _, c := range q {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			sb.WriteRune(c)
		case c == '-', c == '_', c == '.', c == '~':
			sb.WriteRune(c)
		default:
			sb.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return sb.String()
}

// runCommand execs a binary with args and env overrides.
// Returns stdout bytes on success.
func runCommand(ctx context.Context, name string, args []string, env map[string]string) ([]byte, error) {
	import_exec := execLookup(name)
	if import_exec == "" {
		return nil, fmt.Errorf("%q not found in PATH", name)
	}
	return execRun(ctx, import_exec, args, env)
}

func limitSlice(v any, n int) any {
	if v == nil {
		return nil
	}
	s, ok := v.([]any)
	if !ok || len(s) <= n {
		return v
	}
	return s[:n]
}

func truncStr(v any, max int) any {
	s, ok := v.(string)
	if !ok || len(s) <= max {
		return v
	}
	return s[:max] + "…"
}

// ─────────────────────────── get_asset ──────────────────────────────────────

type getAssetTool struct{ store ToolStore }

func (t *getAssetTool) Name() string { return "get_asset" }
func (t *getAssetTool) Description() string {
	return "Fetch an asset record from the ASM inventory including its technology fingerprints, " +
		"network exposure class, and runtime signals. Returns not-found if the asset ID is unknown."
}
func (t *getAssetTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"asset_id": map[string]any{
				"type":        "string",
				"description": "Asset identifier as stored in the Oracle inventory, e.g. ftds-tenant-prod-7421",
			},
		},
		"required": []string{"asset_id"},
	}
}
func (t *getAssetTool) Run(ctx context.Context, args map[string]any) (string, error) {
	assetID, _ := args["asset_id"].(string)
	if assetID == "" {
		return "", fmt.Errorf("asset_id is required")
	}
	asset, err := t.store.GetAsset(ctx, assetID)
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	if asset == nil {
		return fmt.Sprintf(`{"found":false,"asset_id":%q,"note":"Asset not found in inventory. Proceed with unknown asset signals — preconditions will be marked unknown."}`, assetID), nil
	}
	b, _ := json.MarshalIndent(asset, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_epss_kev ─────────────────────────────────

type checkEPSSKEVTool struct{}

func (t *checkEPSSKEVTool) Name() string { return "check_epss_kev" }
func (t *checkEPSSKEVTool) Description() string {
	return "Fetch the FIRST EPSS score (probability of exploitation in the next 30 days) " +
		"and CISA KEV membership for a CVE from live public APIs. " +
		"EPSS > 0.5 and KEV membership are strong signals of active exploitation."
}
func (t *checkEPSSKEVTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkEPSSKEVTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(cveID)

	type result struct {
		CVEID    string  `json:"cve_id"`
		EPSS     float64 `json:"epss_score"`
		EPSSPerc float64 `json:"epss_percentile"`
		InKEV    bool    `json:"in_cisa_kev"`
		KEVAdded string  `json:"kev_date_added,omitempty"`
		Source   string  `json:"source"`
	}
	r := result{CVEID: cveID, Source: "first.org/EPSS + CISA KEV"}

	// EPSS — first.org public API
	epssURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID)
	epssResp, err := httpGetWithTimeout(ctx, epssURL, 8*time.Second)
	if err == nil {
		var out struct {
			Data []struct {
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		if jsonErr := json.Unmarshal(epssResp, &out); jsonErr == nil && len(out.Data) > 0 {
			fmt.Sscanf(out.Data[0].EPSS, "%f", &r.EPSS)
			fmt.Sscanf(out.Data[0].Percentile, "%f", &r.EPSSPerc)
		}
	}

	// CISA KEV — public JSON catalogue
	kevURL := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevResp, err := httpGetWithTimeout(ctx, kevURL, 10*time.Second)
	if err == nil {
		var kev struct {
			Vulnerabilities []struct {
				CVEID    string `json:"cveID"`
				DateAdded string `json:"dateAdded"`
			} `json:"vulnerabilities"`
		}
		if jsonErr := json.Unmarshal(kevResp, &kev); jsonErr == nil {
			for _, v := range kev.Vulnerabilities {
				if strings.EqualFold(v.CVEID, cveID) {
					r.InKEV = true
					r.KEVAdded = v.DateAdded
					break
				}
			}
		}
	}

	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b), nil
}

// ─────────────────────────── search_exploit_evidence ────────────────────────

type searchExploitEvidenceTool struct{}

func (t *searchExploitEvidenceTool) Name() string { return "search_exploit_evidence" }
func (t *searchExploitEvidenceTool) Description() string {
	return "Search GitHub Security Advisories (GHSA) and CVElistV5 for PoC references, " +
		"exploit code links, and vendor-published CVSS vectors for a given CVE. " +
		"Returns public advisory text that may contain precondition details not in NVD."
}
func (t *searchExploitEvidenceTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *searchExploitEvidenceTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	cveID = strings.ToUpper(cveID)

	type advisory struct {
		Source  string `json:"source"`
		CVEID   string `json:"cve_id"`
		Summary string `json:"summary,omitempty"`
		URL     string `json:"url"`
	}
	var results []advisory

	// CVE.org cvelistV5 raw advisory
	parts := strings.SplitN(strings.TrimPrefix(cveID, "CVE-"), "-", 2)
	if len(parts) == 2 {
		year := parts[0]
		num := parts[1]
		// Bucket: last 3 digits of the sequence number → directory prefix
		prefix := "0xxx"
		if len(num) >= 3 {
			prefix = num[:len(num)-3] + "xxx"
		}
		cveListURL := fmt.Sprintf(
			"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/%s/%s/CVE-%s-%s.json",
			year, prefix, year, num,
		)
		body, err := httpGetWithTimeout(ctx, cveListURL, 8*time.Second)
		if err == nil {
			var raw map[string]any
			if jsonErr := json.Unmarshal(body, &raw); jsonErr == nil {
				summary := extractCVEDescription(raw)
				results = append(results, advisory{
					Source:  "cvelistV5",
					CVEID:   cveID,
					Summary: summary,
					URL:     cveListURL,
				})
			}
		}
	}

	// GitHub Security Advisory API (public, no auth for read)
	ghsaURL := fmt.Sprintf("https://api.github.com/advisories?cve_id=%s&per_page=3", cveID)
	ghsaBody, err := httpGetWithTimeout(ctx, ghsaURL, 8*time.Second)
	if err == nil {
		var ghsa []struct {
			GHSAID  string `json:"ghsa_id"`
			Summary string `json:"summary"`
			URL     string `json:"html_url"`
		}
		if jsonErr := json.Unmarshal(ghsaBody, &ghsa); jsonErr == nil {
			for _, g := range ghsa {
				results = append(results, advisory{
					Source:  "GHSA",
					CVEID:   cveID,
					Summary: g.Summary,
					URL:     g.URL,
				})
			}
		}
	}

	if len(results) == 0 {
		return fmt.Sprintf(`{"cve_id":%q,"found":false,"note":"No public advisory data found from cvelistV5 or GHSA."}`, cveID), nil
	}
	b, _ := json.MarshalIndent(map[string]any{"cve_id": cveID, "advisories": results}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── lookup_kb_pattern ──────────────────────────────

type lookupKBPatternTool struct{ kb *knowledgebase.KB }

func (t *lookupKBPatternTool) Name() string { return "lookup_kb_pattern" }
func (t *lookupKBPatternTool) Description() string {
	return "Search the Oracle knowledge base for CWE profiles and dev patterns matching " +
		"a CWE ID or keyword (e.g. 'path traversal', 'symlink', 'Node.js permissions'). " +
		"Returns curated exploit archetypes, preconditions, and ecosystem-specific notes."
}
func (t *lookupKBPatternTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cwe_id": map[string]any{
				"type":        "string",
				"description": "CWE identifier, e.g. CWE-22 (optional if keyword provided)",
			},
			"keyword": map[string]any{
				"type":        "string",
				"description": "Keyword to search across pattern names and descriptions (optional)",
			},
		},
	}
}
func (t *lookupKBPatternTool) Run(_ context.Context, args map[string]any) (string, error) {
	if t.kb == nil {
		return `{"note":"Knowledge base not loaded."}`, nil
	}
	cweID, _ := args["cwe_id"].(string)
	keyword, _ := args["keyword"].(string)

	type kbMatch struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
		Data any    `json:"data"`
	}
	var matches []kbMatch

	// CWE profile lookup
	if cweID != "" {
		cweID = strings.ToUpper(strings.TrimSpace(cweID))
		if profile, ok := t.kb.CWEProfile(cweID); ok {
			matches = append(matches, kbMatch{Kind: "cwe_profile", ID: cweID, Data: profile})
		}
	}

	// Dev pattern search
	for _, pattern := range t.kb.AllPatterns() {
		name := strings.ToLower(pattern.Name + " " + pattern.Description)
		kw := strings.ToLower(keyword)
		if (keyword != "" && strings.Contains(name, kw)) ||
			(cweID != "" && containsString(pattern.CWEs, cweID)) {
			matches = append(matches, kbMatch{Kind: "dev_pattern", ID: pattern.ID, Data: pattern})
		}
	}

	if len(matches) == 0 {
		return fmt.Sprintf(`{"found":false,"cwe_id":%q,"keyword":%q,"note":"No KB matches. Proceed without curated preconditions."}`, cweID, keyword), nil
	}
	b, _ := json.MarshalIndent(map[string]any{"matches": matches}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── get_open_findings ──────────────────────────────

type getOpenFindingsTool struct{ store ToolStore }

func (t *getOpenFindingsTool) Name() string { return "get_open_findings" }
func (t *getOpenFindingsTool) Description() string {
	return "List open Oracle findings from the database, optionally filtered by CVE ID " +
		"or asset ID. Returns OPES scores, categories, and precondition statuses."
}
func (t *getOpenFindingsTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "Filter to a specific CVE (optional)",
			},
			"asset_id": map[string]any{
				"type":        "string",
				"description": "Filter to a specific asset (optional)",
			},
		},
	}
}
func (t *getOpenFindingsTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	assetID, _ := args["asset_id"].(string)

	findings, err := t.store.GetOpenFindings(ctx, cveID, assetID)
	if err != nil {
		return "", fmt.Errorf("store: %w", err)
	}
	b, _ := json.MarshalIndent(map[string]any{
		"findings": findings,
		"count":    len(findings),
	}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── run_analysis ───────────────────────────────────

type runAnalysisTool struct{ runner *pipeline.Runner }

func (t *runAnalysisTool) Name() string { return "run_analysis" }
func (t *runAnalysisTool) Description() string {
	return "Execute the full Oracle analysis pipeline (Phase A LLM intrinsic analysis → " +
		"Phase B contextual precondition evaluation → OPES scoring) for a (cve_id, asset_id) pair. " +
		"This is the terminal tool — call it when you have enough context. " +
		"The output contains the complete OracleFinding with OPES score and recommendation."
}
func (t *runAnalysisTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier",
			},
			"asset_id": map[string]any{
				"type":        "string",
				"description": "Asset identifier from the ASM inventory",
			},
		},
		"required": []string{"cve_id", "asset_id"},
	}
}
func (t *runAnalysisTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	assetID, _ := args["asset_id"].(string)
	if cveID == "" || assetID == "" {
		return "", fmt.Errorf("both cve_id and asset_id are required")
	}

	result, err := t.runner.Run(
		ctx,
		strings.ToUpper(cveID),
		assetID,
		nil,
		schema.ExploitationEvidence{},
	)
	if err != nil {
		return "", fmt.Errorf("pipeline: %w", err)
	}

	b, _ := json.MarshalIndent(map[string]any{
		"finding":    result.Finding,
		"llm_model":  result.LLMModel,
		"elapsed_ms": result.ElapsedMS,
	}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── shared helpers ─────────────────────────────────

func httpGetWithTimeout(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
}

func extractCVEDescription(raw map[string]any) string {
	cnaAny, ok := raw["containers"]
	if !ok {
		return ""
	}
	cna, ok := cnaAny.(map[string]any)["cna"].(map[string]any)
	if !ok {
		return ""
	}
	descs, ok := cna["descriptions"].([]any)
	if !ok || len(descs) == 0 {
		return ""
	}
	first, ok := descs[0].(map[string]any)
	if !ok {
		return ""
	}
	val, _ := first["value"].(string)
	return val
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// ─────────────────────────── check_breach_context ───────────────────────────

// checkBreachContextTool aggregates three free breach/exploitation sources:
//   - VCDB  (Verizon DBIR incident database)
//   - ENISA EUVD (EU-confirmed exploitation)
//   - Google Project Zero (pre-patch zero-day)
//
// Use this when you want evidence that a CVE caused actual harm — beyond
// theoretical exploitability or KEV listing.
type checkBreachContextTool struct{}

func (t *checkBreachContextTool) Name() string { return "check_breach_context" }
func (t *checkBreachContextTool) Description() string {
	return "Fetch real-world breach and exploitation confirmation for a CVE from three sources: " +
		"(1) VCDB — Verizon DBIR incident database: appears here means the CVE caused a confirmed breach; " +
		"(2) ENISA EUVD — EU Vulnerability Database, exploitedSince field confirms EU-verified exploitation; " +
		"(3) Google Project Zero — '0day In The Wild' tracker, confirms exploitation before a patch existed. " +
		"Use this alongside check_epss_kev to distinguish 'theoretically exploitable' from 'caused real losses'."
}
func (t *checkBreachContextTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkBreachContextTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}

	// Run all three concurrently with a shared 20 s deadline.
	fetchCtx, cancel := context.WithTimeout(ctx, 22*time.Second)
	defer cancel()

	vcdb := enrichers.FetchVCDB(fetchCtx, cveID)
	enisa := enrichers.FetchENISAEUVD(fetchCtx, cveID)
	gp0 := enrichers.FetchGoogleP0(fetchCtx, cveID)

	// Derive a plain-English summary.
	signals := []string{}
	if vcdb.Found {
		signals = append(signals, fmt.Sprintf("VCDB: %d breach record(s) confirmed", vcdb.IncidentCount))
	}
	if enisa.ExploitConfirmed {
		signals = append(signals, fmt.Sprintf("ENISA EUVD: exploitation confirmed since %s", enisa.ExploitedSince))
	} else if enisa.Found {
		signals = append(signals, fmt.Sprintf("ENISA EUVD: catalogued as %s (no exploitation date)", enisa.EUVDID))
	}
	if gp0.ZeroDayConfirmed {
		signals = append(signals, "Google P0: confirmed exploited before patch (0day ITW)")
	}

	summary := "No breach or pre-patch exploitation evidence found in VCDB, ENISA EUVD, or Google P0."
	if len(signals) > 0 {
		summary = "Breach/exploitation evidence: " + strings.Join(signals, "; ")
	}

	result := map[string]any{
		"cve_id":  strings.ToUpper(cveID),
		"summary": summary,
		"vcdb":    vcdb,
		"enisa":   enisa,
		"gp0":     gp0,
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_attackerkb ───────────────────────────────

// checkAttackerKBTool queries the AttackerKB community scoring API.
// AttackerKB aggregates practitioner assessments of how useful and exploitable
// a CVE is. Scores are on a 0–5 scale; ≥4 is strong attacker interest.
type checkAttackerKBTool struct{}

func (t *checkAttackerKBTool) Name() string { return "check_attackerkb" }
func (t *checkAttackerKBTool) Description() string {
	return "Query AttackerKB for community practitioner scoring of a CVE. Returns: " +
		"attacker_value (0–5: how useful to an attacker?), " +
		"exploitability (0–5: how reliably can it be exploited?), " +
		"common_score (weighted average). " +
		"Scores ≥ 4 represent strong practitioner consensus. " +
		"Useful as a complement to CVSS/EPSS — these are real practitioner votes, not algorithmic estimates."
}
func (t *checkAttackerKBTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkAttackerKBTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	result := enrichers.FetchAttackerKB(fetchCtx, cveID)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_weaponization ────────────────────────────

type checkWeaponizationTool struct{}

func (t *checkWeaponizationTool) Name() string { return "check_weaponization" }
func (t *checkWeaponizationTool) Description() string {
	return "Check whether a weaponized exploit module exists for a CVE in Metasploit " +
		"(rapid7/metasploit-framework) and whether a Nuclei template exists for automated " +
		"scanning/detection (projectdiscovery/nuclei-templates). " +
		"A Metasploit module is one of the strongest OPES weaponization signals — it means " +
		"a reliable, GUI-accessible exploit exists. A Nuclei template means automated detection " +
		"is trivially achievable. Both signals significantly raise practical exploitability."
}
func (t *checkWeaponizationTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkWeaponizationTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	type result struct {
		Metasploit enrichers.MetasploitResult `json:"metasploit"`
		Nuclei     enrichers.NucleiResult     `json:"nuclei"`
		Summary    string                     `json:"summary"`
	}
	msf := enrichers.FetchMetasploit(fetchCtx, cveID)
	nuc := enrichers.FetchNucleiTemplate(fetchCtx, cveID)

	summaryParts := []string{}
	if msf.Found {
		summaryParts = append(summaryParts, fmt.Sprintf("%d Metasploit module(s)", msf.ModuleCount))
	} else {
		summaryParts = append(summaryParts, "no Metasploit module")
	}
	if nuc.Found {
		summaryParts = append(summaryParts, fmt.Sprintf("%d Nuclei template(s)", nuc.TemplateCount))
	} else {
		summaryParts = append(summaryParts, "no Nuclei template")
	}

	r := result{
		Metasploit: msf,
		Nuclei:     nuc,
		Summary:    strings.Join(summaryParts, "; "),
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_cisa_vulnrichment ─────────────────────────

type checkCISAVulnrichmentTool struct{}

func (t *checkCISAVulnrichmentTool) Name() string { return "check_cisa_vulnrichment" }
func (t *checkCISAVulnrichmentTool) Description() string {
	return "Fetch CISA Vulnrichment data for a CVE from the cisagov/vulnrichment GitHub repository. " +
		"CISA enriches CVEs with CVSS 4.0 scores, SSVC (Stakeholder-Specific Vulnerability " +
		"Categorization) triage decisions, and CPE product annotations — often before NVD does. " +
		"SSVC decisions: 'Immediate' = patch ASAP (equivalent to KEV risk), 'Out-of-Cycle' = next " +
		"patch window, 'Scheduled' = routine cycle, 'Defer' = deprioritize. " +
		"Use this when NVD CVSS data is missing or when you need an official triage signal."
}
func (t *checkCISAVulnrichmentTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2024-3094",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkCISAVulnrichmentTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result := enrichers.FetchVulnrichment(fetchCtx, cveID)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_regional_nvds ─────────────────────────────

type checkRegionalNVDsTool struct{}

func (t *checkRegionalNVDsTool) Name() string { return "check_regional_nvds" }
func (t *checkRegionalNVDsTool) Description() string {
	return "Check national/regional vulnerability databases for a CVE: " +
		"JVN iPedia (Japan's IPA/JPCERT national DB — covers Japanese-vendor software often " +
		"before NVD), and BDU FSTEC (Russia's national DB — bdu.fstec.ru is geo-blocked but " +
		"accessed via public GitHub mirror). Useful for confirming whether a CVE in Japan- or " +
		"Russia-origin software has been independently catalogued by those authorities. " +
		"A hit in JVN often means the Japanese vendor has published their own advisory."
}
func (t *checkRegionalNVDsTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2023-12345",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkRegionalNVDsTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	type combined struct {
		JVN enrichers.JVNResult `json:"jvn_ipedia"`
		BDU enrichers.BDUResult `json:"bdu_fstec"`
	}

	var (
		jvn enrichers.JVNResult
		bdu enrichers.BDUResult
	)
	done := make(chan struct{}, 2)
	go func() { jvn = enrichers.FetchJVNiPedia(fetchCtx, cveID); done <- struct{}{} }()
	go func() { bdu = enrichers.FetchBDUFSTEC(fetchCtx, cveID); done <- struct{}{} }()
	<-done
	<-done

	b, _ := json.MarshalIndent(combined{JVN: jvn, BDU: bdu}, "", "  ")
	return string(b), nil
}

// ─────────────────────────── check_attack_mappings ───────────────────────────

type checkATTACKMappingsTool struct{}

func (t *checkATTACKMappingsTool) Name() string { return "check_attack_mappings" }
func (t *checkATTACKMappingsTool) Description() string {
	return "Look up MITRE ATT&CK technique mappings for a CVE using the Center for " +
		"Threat-Informed Defense (CTID) Mappings Explorer dataset and the mitre-attack/attack-stix-data " +
		"repository. Returns the ATT&CK technique IDs (T#### format) and their associated tactics " +
		"(e.g. Initial Access, Execution, Privilege Escalation). Use this to understand the adversary " +
		"kill-chain step where the vulnerability is used and to inform detection engineering."
}
func (t *checkATTACKMappingsTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cve_id": map[string]any{
				"type":        "string",
				"description": "CVE identifier, e.g. CVE-2021-44228",
			},
		},
		"required": []string{"cve_id"},
	}
}
func (t *checkATTACKMappingsTool) Run(ctx context.Context, args map[string]any) (string, error) {
	cveID, _ := args["cve_id"].(string)
	if cveID == "" {
		return "", fmt.Errorf("cve_id is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result := enrichers.FetchATTACKMappings(fetchCtx, cveID)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── map_owasp ───────────────────────────────────────

type mapOWASPTool struct{}

func (t *mapOWASPTool) Name() string { return "map_owasp" }
func (t *mapOWASPTool) Description() string {
	return "Map CWE identifiers to OWASP Top 10 2021 categories. This is a deterministic " +
		"static mapping (no network call). Provide a list of CWE IDs (e.g. [\"CWE-79\", \"CWE-89\"]) " +
		"and receive the corresponding OWASP Top 10 categories (e.g. A03:2021 Injection). " +
		"Use this for classification, reporting, and understanding which OWASP Top 10 risk " +
		"category the vulnerability falls under."
}
func (t *mapOWASPTool) ArgsSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cwe_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "List of CWE identifiers, e.g. [\"CWE-79\", \"89\", \"CWE-22\"]",
			},
		},
		"required": []string{"cwe_ids"},
	}
}
func (t *mapOWASPTool) Run(_ context.Context, args map[string]any) (string, error) {
	rawList, ok := args["cwe_ids"].([]interface{})
	if !ok || len(rawList) == 0 {
		return "", fmt.Errorf("cwe_ids must be a non-empty array")
	}
	cweIDs := make([]string, 0, len(rawList))
	for _, v := range rawList {
		if s, ok := v.(string); ok && s != "" {
			cweIDs = append(cweIDs, s)
		}
	}
	result := enrichers.MapOWASP(cweIDs)
	b, _ := json.MarshalIndent(result, "", "  ")
	return string(b), nil
}

// ─────────────────────────── exec helpers ───────────────────────────────────

// execLookup returns the full path to a binary or "" if not found.
func execLookup(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// execRun runs a binary with the given args and additional env vars.
// Returns combined stdout/stderr on success, error on non-zero exit.
func execRun(ctx context.Context, path string, args []string, extraEnv map[string]string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	// Inherit current env and add overrides.
	cmd.Env = os.Environ()
	for k, v := range extraEnv {
		if v != "" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exec %s: %w (stderr: %s)", path, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

