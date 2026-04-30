// Package enrichers provides lightweight, network-fetching enrichers that
// attach real-world exploitation and breach evidence to CVE records before
// OPES scoring.
//
// Each enricher is a free-standing function returning a typed result.
// Errors are swallowed — every function returns a zero-value result on failure
// so the pipeline remains intact. All fetches time out in ≤ 20 s.
//
// Sources
//
//   - VCDB          Verizon DBIR incident database (github.com/vz-risk/VCDB).
//                   Confirms whether the CVE appears in a real breach record.
//   - ENISA EUVD    EU Vulnerability Database (euvdservices.enisa.europa.eu).
//                   exploitedSince non-null → EU-confirmed exploitation.
//   - Google P0     "0day In The Wild" spreadsheet (Project Zero).
//                   CVE was exploited before a vendor patch existed.
//   - AttackerKB    Community exploitation scoring (api.attackerkb.com).
//   - CISA Vulnrichment  CVSS 4.0 + SSVC triage decisions (GitHub).
//   - Metasploit    Weaponized exploit module detection (GitHub search).
//   - Nuclei        Automated scan template detection (GitHub search).
//   - JVN iPedia    Japanese national vulnerability database (MyJVN API).
//   - BDU FSTEC     Russian national vulnerability database (GitHub mirror).
//   - ATT&CK        CVE → MITRE technique mappings (CTID Mappings Explorer).
//   - OWASP         CWE → OWASP Top 10 2021 category (static mapping).
package enrichers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// ─────────────────────────── Result types ────────────────────────────────────

// VCDBResult holds breach attribution from the Verizon VERIS Community DB.
type VCDBResult struct {
	Found         bool     `json:"found"`
	IncidentCount int      `json:"incident_count,omitempty"`
	IncidentURLs  []string `json:"incident_urls,omitempty"`
	Note          string   `json:"note,omitempty"`
}

// ENISAResult holds exploitation confirmation from ENISA EUVD.
type ENISAResult struct {
	Found            bool    `json:"found"`
	EUVDID           string  `json:"euvd_id,omitempty"`
	ExploitConfirmed bool    `json:"exploit_confirmed"`
	ExploitedSince   string  `json:"exploited_since,omitempty"`
	BaseScore        float64 `json:"base_score,omitempty"`
	BaseScoreVector  string  `json:"base_score_vector,omitempty"`
	Note             string  `json:"note,omitempty"`
}

// GP0Result holds Google Project Zero pre-patch zero-day confirmation.
type GP0Result struct {
	Found            bool   `json:"found"`
	ZeroDayConfirmed bool   `json:"zero_day_confirmed"`
	Product          string `json:"product,omitempty"`
	Notes            string `json:"notes,omitempty"`
}

// AttackerKBResult holds community exploitation scoring from AttackerKB.
// Scores are on a 0–5 scale; 5 is maximum.
type AttackerKBResult struct {
	Found          bool    `json:"found"`
	AttackerValue  int     `json:"attacker_value,omitempty"`
	Exploitability int     `json:"exploitability,omitempty"`
	CommonScore    float64 `json:"common_score,omitempty"`
	Note           string  `json:"note,omitempty"`
}

// ExternalEnrichment bundles all enricher results for one CVE.
// Fetch it with FetchAll, then call Apply to merge signals into ExploitationEvidence.
type ExternalEnrichment struct {
	// Breach and exploitation evidence
	VCDB       VCDBResult       `json:"vcdb"`
	ENISA      ENISAResult      `json:"enisa"`
	GP0        GP0Result        `json:"gp0"`
	AttackerKB AttackerKBResult `json:"attackerkb"`

	// Weaponization
	Metasploit MetasploitResult `json:"metasploit"`
	Nuclei     NucleiResult     `json:"nuclei"`

	// Government / national database coverage
	Vulnrichment VulnrichmentResult `json:"vulnrichment"`
	JVN          JVNResult          `json:"jvn"`
	BDU          BDUResult          `json:"bdu"`

	// Threat intelligence
	ATTACK ATTACKResult `json:"attack"`
	OWASP  OWASPResult  `json:"owasp"` // populated by Apply using CWE data; no network call
}

// ─────────────────────────── FetchAll ────────────────────────────────────────

// FetchAll runs all network-based enrichers concurrently and returns the
// combined ExternalEnrichment. Individual failures are silently swallowed.
// Treat absent/zero-value fields as "unknown" — never as "safe".
//
// Pass the caller's context; each enricher applies its own sub-timeout.
// OWASP mapping is populated later by ApplyWithCWEs, not here, because the
// CWE list comes from the intrinsic analysis rather than a network call.
func FetchAll(ctx context.Context, cveID string) ExternalEnrichment {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		result ExternalEnrichment
	)

	type job struct{ name string; fn func() }
	jobs := []job{
		{"vcdb", func() {
			r := FetchVCDB(ctx, cveID)
			mu.Lock(); result.VCDB = r; mu.Unlock()
		}},
		{"enisa", func() {
			r := FetchENISAEUVD(ctx, cveID)
			mu.Lock(); result.ENISA = r; mu.Unlock()
		}},
		{"gp0", func() {
			r := FetchGoogleP0(ctx, cveID)
			mu.Lock(); result.GP0 = r; mu.Unlock()
		}},
		{"attackerkb", func() {
			r := FetchAttackerKB(ctx, cveID)
			mu.Lock(); result.AttackerKB = r; mu.Unlock()
		}},
		{"metasploit", func() {
			r := FetchMetasploit(ctx, cveID)
			mu.Lock(); result.Metasploit = r; mu.Unlock()
		}},
		{"nuclei", func() {
			r := FetchNucleiTemplate(ctx, cveID)
			mu.Lock(); result.Nuclei = r; mu.Unlock()
		}},
		{"vulnrichment", func() {
			r := FetchVulnrichment(ctx, cveID)
			mu.Lock(); result.Vulnrichment = r; mu.Unlock()
		}},
		{"jvn", func() {
			r := FetchJVNiPedia(ctx, cveID)
			mu.Lock(); result.JVN = r; mu.Unlock()
		}},
		{"bdu", func() {
			r := FetchBDUFSTEC(ctx, cveID)
			mu.Lock(); result.BDU = r; mu.Unlock()
		}},
		{"attack", func() {
			r := FetchATTACKMappings(ctx, cveID)
			mu.Lock(); result.ATTACK = r; mu.Unlock()
		}},
	}

	wg.Add(len(jobs))
	for _, j := range jobs {
		j := j
		go func() { defer wg.Done(); j.fn() }()
	}
	wg.Wait()
	return result
}

// FetchAllWithCWEs is like FetchAll but also populates the OWASP field using
// the given CWE identifiers (which come from intrinsic analysis, not a
// network source). Call this variant when CWE data is available upfront.
func FetchAllWithCWEs(ctx context.Context, cveID string, cweIDs []string) ExternalEnrichment {
	result := FetchAll(ctx, cveID)
	if len(cweIDs) > 0 {
		result.OWASP = MapOWASP(cweIDs)
	}
	return result
}

// ─────────────────────────── Apply ───────────────────────────────────────────

// Apply merges an ExternalEnrichment into a schema.ExploitationEvidence so
// OPES scoring picks up all signals. Call after FetchAll / FetchAllWithCWEs.
func Apply(ext ExternalEnrichment, ev *schema.ExploitationEvidence) {
	if ev == nil {
		return
	}
	// Breach / exploitation sources
	if ext.VCDB.Found {
		ev.BreachConfirmed = true
		ev.BreachIncidentCount = ext.VCDB.IncidentCount
		ev.BreachSources = appendUnique(ev.BreachSources, "vcdb")
	}
	if ext.ENISA.ExploitConfirmed {
		ev.ENISAExploited = true
		ev.ENISAExploitedSince = ext.ENISA.ExploitedSince
		ev.EUVDID = ext.ENISA.EUVDID
		ev.InKEVSources = appendUnique(ev.InKEVSources, "enisa_euvd_kev")
	}
	if ext.GP0.ZeroDayConfirmed {
		ev.ZeroDayConfirmed = true
	}
	if ext.AttackerKB.Found {
		ev.AttackerKBValue = ext.AttackerKB.AttackerValue
		ev.AttackerKBExploitability = ext.AttackerKB.Exploitability
	}

	// Weaponization signals
	if ext.Metasploit.Found {
		ev.MetasploitAvailable = true
		ev.MetasploitModCount = ext.Metasploit.ModuleCount
	}

	// CISA SSVC triage decision
	if ext.Vulnrichment.Found && ext.Vulnrichment.SSVCDecision != "" {
		ev.CISASSVCDecision = ext.Vulnrichment.SSVCDecision
	}
}

// ─────────────────────────── VCDB ────────────────────────────────────────────

// FetchVCDB searches the Verizon VERIS Community Database (GitHub) for
// incident JSON files that reference the given CVE ID.
func FetchVCDB(ctx context.Context, cveID string) VCDBResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := fmt.Sprintf(
		"https://api.github.com/search/code?q=%s+repo:vz-risk/VCDB+extension:json",
		cveID,
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return VCDBResult{Note: "request build failed"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return VCDBResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		return VCDBResult{Note: "GitHub rate-limited; set GITHUB_TOKEN for higher limits"}
	}
	if resp.StatusCode != http.StatusOK {
		return VCDBResult{Note: fmt.Sprintf("HTTP %d from GitHub", resp.StatusCode)}
	}

	var payload struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&payload); err != nil {
		return VCDBResult{Note: "JSON decode failed"}
	}
	if payload.TotalCount == 0 {
		return VCDBResult{Found: false}
	}

	urls := make([]string, 0, len(payload.Items))
	for _, item := range payload.Items {
		urls = append(urls, item.HTMLURL)
	}
	return VCDBResult{
		Found:         true,
		IncidentCount: payload.TotalCount,
		IncidentURLs:  urls,
		Note: fmt.Sprintf(
			"%d VCDB breach record(s) reference %s — confirmed in Verizon DBIR incident data",
			payload.TotalCount, cveID,
		),
	}
}

// ─────────────────────────── ENISA EUVD ──────────────────────────────────────

// FetchENISAEUVD queries the ENISA European Union Vulnerability Database.
// A non-empty exploitedSince field confirms EU-verified exploitation in the wild.
func FetchENISAEUVD(ctx context.Context, cveID string) ENISAResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://euvdservices.enisa.europa.eu/api/enisaid?id=%s", cveID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return ENISAResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ENISAResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ENISAResult{Found: false}
	}
	if resp.StatusCode != http.StatusOK {
		return ENISAResult{Note: fmt.Sprintf("HTTP %d from ENISA", resp.StatusCode)}
	}

	var d struct {
		ID             string  `json:"id"`
		ExploitedSince string  `json:"exploitedSince"`
		BaseScore      float64 `json:"baseScore"`
		BaseScoreVector string `json:"baseScoreVector"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&d); err != nil {
		return ENISAResult{Note: "JSON decode failed"}
	}
	if d.ID == "" {
		return ENISAResult{Found: false}
	}

	exploited := strings.TrimSpace(d.ExploitedSince) != ""
	note := fmt.Sprintf("ENISA EUVD: id=%s exploited=%v", d.ID, exploited)
	if exploited {
		note = fmt.Sprintf("ENISA EUVD confirms exploitation since %s (id=%s)", d.ExploitedSince, d.ID)
	}
	return ENISAResult{
		Found:            true,
		EUVDID:           d.ID,
		ExploitConfirmed: exploited,
		ExploitedSince:   d.ExploitedSince,
		BaseScore:        d.BaseScore,
		BaseScoreVector:  d.BaseScoreVector,
		Note:             note,
	}
}

// ─────────────────────────── Google Project Zero ─────────────────────────────

const googleP0CSV = "https://docs.google.com/spreadsheets/d/" +
	"1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=2"

// FetchGoogleP0 checks whether the CVE appears in Google Project Zero's
// "0day In The Wild" spreadsheet — confirming exploitation before a patch existed.
func FetchGoogleP0(ctx context.Context, cveID string) GP0Result {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, googleP0CSV, nil)
	if err != nil {
		return GP0Result{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return GP0Result{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GP0Result{Note: fmt.Sprintf("HTTP %d from Google Sheets", resp.StatusCode)}
	}

	r := csv.NewReader(io.LimitReader(resp.Body, 2*1024*1024))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1

	headers, err := r.Read()
	if err != nil {
		return GP0Result{Note: "CSV header read failed"}
	}

	// Find column indices.
	cveCol, productCol, notesCol := 0, -1, -1
	for i, h := range headers {
		lo := strings.ToLower(strings.TrimSpace(h))
		switch {
		case strings.Contains(lo, "cve"):
			cveCol = i
		case strings.Contains(lo, "product") || strings.Contains(lo, "software"):
			productCol = i
		case strings.Contains(lo, "note") || strings.Contains(lo, "desc"):
			notesCol = i
		}
	}

	upper := strings.ToUpper(cveID)
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		rowText := strings.ToUpper(strings.Join(row, " "))
		if !strings.Contains(rowText, upper) {
			continue
		}
		if cveCol < len(row) && !strings.Contains(strings.ToUpper(row[cveCol]), upper) {
			continue
		}

		product, notes := "", ""
		if productCol >= 0 && productCol < len(row) {
			product = strings.TrimSpace(row[productCol])
		}
		if notesCol >= 0 && notesCol < len(row) {
			notes = strings.TrimSpace(row[notesCol])
		}
		return GP0Result{Found: true, ZeroDayConfirmed: true, Product: product, Notes: notes}
	}
	return GP0Result{Found: false}
}

// ─────────────────────────── AttackerKB ──────────────────────────────────────

// FetchAttackerKB queries the AttackerKB community scoring API.
// Scores are 0–5: AttackerValue (how useful to an attacker?) and
// Exploitability (how reliably can it be exploited?).
func FetchAttackerKB(ctx context.Context, cveID string) AttackerKBResult {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.attackerkb.com/v1/topics?q=%s&size=1", cveID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return AttackerKBResult{Note: "request build failed"}
	}
	req.Header.Set("User-Agent", "aegis-oracle/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AttackerKBResult{Note: "fetch error: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return AttackerKBResult{Note: "AttackerKB rate-limited"}
	}
	if resp.StatusCode != http.StatusOK {
		return AttackerKBResult{Note: fmt.Sprintf("HTTP %d from AttackerKB", resp.StatusCode)}
	}

	var payload struct {
		Data []struct {
			Name  string `json:"name"`
			Score struct {
				AttackerValue       int     `json:"attackerValue"`
				ExploitabilityScore int     `json:"exploitabilityScore"`
				CommonScore         float64 `json:"commonScore"`
			} `json:"score"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&payload); err != nil {
		return AttackerKBResult{Note: "JSON decode failed"}
	}
	if len(payload.Data) == 0 {
		return AttackerKBResult{Found: false}
	}

	t := payload.Data[0]
	if !strings.EqualFold(t.Name, cveID) {
		return AttackerKBResult{Found: false}
	}
	return AttackerKBResult{
		Found:          true,
		AttackerValue:  t.Score.AttackerValue,
		Exploitability: t.Score.ExploitabilityScore,
		CommonScore:    t.Score.CommonScore,
		Note: fmt.Sprintf(
			"AttackerKB: attacker_value=%d exploitability=%d common_score=%.1f",
			t.Score.AttackerValue, t.Score.ExploitabilityScore, t.Score.CommonScore,
		),
	}
}

// ─────────────────────────── helpers ─────────────────────────────────────────

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
