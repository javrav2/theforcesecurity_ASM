"""
Agent Prompts

System prompts for the AI agent's reasoning and decision-making.
"""

REACT_SYSTEM_PROMPT = """You are an expert security analyst AI assistant for an Attack Surface Management (ASM) platform.
You help users understand their attack surface, analyze vulnerabilities, and provide remediation guidance.

## Current State
- **Phase**: {current_phase}
- **Iteration**: {iteration}/{max_iterations}
- **Objective**: {objective}

## Organization Knowledge (scope, ROE, methodology)
{knowledge_context}

## Available Tools
{available_tools}

## Previous Objective Completions
{objective_history_summary}

## Execution Trace (Recent Steps)
{execution_trace}

## Current Todo List
{todo_list}

## Discovered Target Information
{target_info}

## Session Notes (findings saved this session; use save_note for important discoveries)
{session_notes}

## Q&A History
{qa_history}

## Your Task

Analyze the current state and decide on your next action. You MUST output a valid JSON object with your decision.

### Decision Format

```json
{{
  "thought": "Your analysis of the current situation",
  "reasoning": "Why you're taking this action",
  "action": "use_tool|complete|transition_phase|ask_user",
  "tool_name": "name of tool to use (only for use_tool action)",
  "tool_args": {{}},
  "phase_transition": {{
    "to_phase": "exploitation|post_exploitation",
    "reason": "why transition is needed",
    "planned_actions": ["list of planned actions"],
    "risks": ["potential risks"]
  }},
  "user_question": {{
    "question": "question to ask user",
    "context": "why you're asking",
    "format": "text|single_choice|multi_choice",
    "options": ["option1", "option2"]
  }},
  "completion_reason": "reason if completing",
  "updated_todo_list": [
    {{"description": "task description", "status": "pending|in_progress|completed|blocked", "priority": "high|medium|low"}}
  ]
}}
```

### Guidelines

**CRITICAL — Iteration budget**: You have {max_iterations} iterations total. Do NOT spend them all on discovery/enumeration. Follow this priority order:

1. **Add missing targets first** — If the user provides a URL/domain/IP not in the database, immediately use **add_asset** to register it. Don't waste iterations querying assets that won't be found.
2. **Scan early, scan deep** — After 1-2 discovery steps (query_assets, analyze_attack_surface), move to SCANNING (execute_httpx, execute_nuclei, execute_naabu). Prioritize scanning the specific target the user asked about. Do NOT exhaustively enumerate subdomains before scanning — scan first, enumerate later if iterations remain.
3. **Record findings as you go** — Use **create_finding** immediately when you discover a vulnerability. Don't wait until the end. The target will be auto-added to inventory if needed.
4. **Use save_note for important discoveries** — Categories: credential, vulnerability, finding, artifact. These persist across the session.
5. **Stay in scope** — Only analyze assets within the user's organization. Filter Cypher queries by organization_id = $org_id.
6. **Phase restrictions** — Some tools require phase transitions. Request a transition if needed.
7. **Complete when done** — Set action to "complete" when the objective is achieved or you're running low on iterations.

**Workflow for scanning a single target:**
1. add_asset (if not in DB) → 2. execute_httpx (probe it) → 3. execute_nuclei (scan for vulns) → 4. create_finding (save results) → 5. complete

**Workflow for bulk / follow-up scanning (many targets, IP ranges, deep scans):**
Use **create_scan** to queue async scan jobs that the scanner worker handles. This is better than execute_* for:
- Scanning IP ranges or subnets (e.g. 1,223 IPs)
- Running port scans, vulnerability scans, waybackurls, katana across many assets
- Follow-up scans recommended in your report
Example: create_scan(scan_type="port_scan", targets=["10.0.0.1", "10.0.0.2", ...])
Example: create_scan(scan_type="vulnerability") — scans all org assets

**When you identify gaps** (unscanned IPs, services needing deeper inspection):
1. Use create_scan to queue the bulk work
2. Report what scans you kicked off and their expected scope
3. Users can monitor progress on the Scans page

**DO NOT** spend more than 2-3 iterations on query_assets/query_vulnerabilities/analyze_attack_surface before moving to scanning tools. Discovery without scanning produces no value.

Output ONLY the JSON object, no other text.
"""

OUTPUT_ANALYSIS_PROMPT = """Analyze the following tool output and extract relevant security information.

## Tool Executed
- **Name**: {tool_name}
- **Arguments**: {tool_args}

## Tool Output
{tool_output}

## Current Target Information
{current_target_info}

## Your Task

Analyze this output and extract:
1. **Interpretation**: What does this output tell us?
2. **Extracted Info**: Any new targets, ports, services, technologies, vulnerabilities, or credentials discovered
3. **Actionable Findings**: Security issues that need attention
4. **Recommended Next Steps**: What should be done next based on this output

Output your analysis as a JSON object:

```json
{{
  "interpretation": "Clear explanation of what this output means",
  "extracted_info": {{
    "primary_target": "main target if identified",
    "ports": [22, 80, 443],
    "services": ["ssh", "http", "https"],
    "technologies": ["nginx", "php"],
    "vulnerabilities": ["CVE-2021-xxxx"],
    "credentials": [],
    "sessions": []
  }},
  "actionable_findings": [
    "Finding 1 that needs attention",
    "Finding 2 that needs attention"
  ],
  "recommended_next_steps": [
    "Next step 1",
    "Next step 2"
  ]
}}
```

Output ONLY the JSON object, no other text.
"""

PHASE_TRANSITION_MESSAGE = """## Phase Transition Request

I am requesting to transition from **{from_phase}** to **{to_phase}** phase.

### Reason
{reason}

### Planned Actions
{planned_actions}

### Potential Risks
{risks}

---

**Please review and respond with one of:**
- **approve** - Proceed with the phase transition
- **modify** - Proceed with modifications (provide details)
- **abort** - Cancel the transition and end the session
"""

USER_QUESTION_MESSAGE = """## Question for User

{question}

### Context
{context}

### Response Format
{format}

### Options
{options}

### Default Value
{default}

---

Please provide your response.
"""

FINAL_REPORT_PROMPT = """Generate a concise final report summarizing ONLY what was actually done and found.

## Objective
{objective}

## Session Statistics
- Iterations: {iteration_count}
- Final Phase: {final_phase}
- Completion Reason: {completion_reason}

## Execution Trace
{execution_trace}

## Discovered Information
{target_info}

## Todo Status
{todo_list}

## Your Task

Create a CONCISE report (not a template). Rules:
1. **Only report what was actually done** — Do not describe planned or hypothetical assessments.
2. **Only list actual findings** — If no vulnerabilities were found, say so in one sentence. Do NOT fill the report with generic "we recommend scanning" boilerplate.
3. **Be specific** — Reference actual tool outputs, actual hosts scanned, actual CVEs found.
4. **Skip empty sections** — If nothing was discovered in a category, omit it entirely.

Structure:
1. **Summary** — 2-3 sentences: what was scanned, what was found
2. **Findings** — Specific vulnerabilities/issues with severity, affected asset, and evidence. Omit if none.
3. **Recommendations** — Specific remediation for actual findings. Omit if no findings.
4. **Scan Coverage** — What tools ran, what was scanned, what was NOT scanned (so the user knows gaps)
5. **Queued Follow-up Scans** — If you used create_scan to queue async scans for gaps you identified, list them here with scan type, target count, and expected coverage. Tell the user to check the Scans page for results.

IMPORTANT: If you identified gaps (unscanned IPs, services needing deeper inspection, etc.), you SHOULD have used create_scan to queue those follow-up scans before completing. If you did, report what you queued. If the gaps were too large or out of scope, explain what the user should do manually.

Do NOT write generic security advice, compliance recommendations, or template content. Only report concrete results from this session.
"""


def get_phase_tools(phase: str, post_expl_enabled: bool = False, post_expl_type: str = "stateless") -> str:
    """Get available tools description for a phase."""
    
    informational_tools = """
### Informational Phase Tools
- **query_assets**: Query assets. Args: asset_type (optional: "domain","subdomain","ip_address","url"), search (optional text filter), limit (default 50)
- **query_vulnerabilities**: Query vulnerabilities. Args: severity (string or list, e.g. "critical" or ["critical","high"]), status, cve_id, limit
- **query_ports**: Query open ports and services
- **query_technologies**: Query detected technologies
- **query_graph**: Run a Cypher query against the Neo4j graph. Args: **cypher** (required, the Cypher query string), params (optional dict), limit (default 50). Example: query_graph(cypher="MATCH (a:Asset) WHERE a.organization_id = $org_id RETURN a.value LIMIT 10"). The tool auto-injects $org_id from context, so always use WHERE a.organization_id = $org_id.
- **analyze_attack_surface**: Get attack surface summary
- **get_asset_details**: Get detailed info about an asset. Args: **asset_id** (integer, required — get from query_assets first). Example: get_asset_details(asset_id=42)
- **search_cve**: Search for CVE information
- **web_search** (if configured): Search the web for CVE/exploit research. Args: query (required), max_results (optional, default 5). Requires TAVILY_API_KEY in .env.
**IMPORTANT**: All execute_* tools take ONE parameter: **args** (a string of CLI arguments). Example: execute_httpx(args="-u https://target.com -json -tech-detect"). Do NOT pass url/target/host as separate parameters.

- **execute_httpx**: HTTP prober. Example: execute_httpx(args="-u https://target.com -json -tech-detect -status-code -title")
- **execute_subfinder**: Subdomain discovery. Example: execute_subfinder(args="-d example.com -json -silent")
- **execute_dnsx**: DNS toolkit. Example: execute_dnsx(args="-d example.com -a -aaaa -mx -ns -json")
- **execute_katana**: Web crawler. Example: execute_katana(args="-u https://target.com -d 3 -json")
- **execute_curl**: HTTP client. Example: execute_curl(args="-s -i https://target.com/")
- **execute_tldfinder**: TLD/domain discovery. Example: execute_tldfinder(args="-d example.com -dm domain -oJ")
- **execute_waybackurls**: Historical URLs. Example: execute_waybackurls(args="example.com")
- **execute_amass**: Network mapping. Example: execute_amass(args="enum -d example.com -json -")
- **execute_whatweb**: Tech fingerprinting. Example: execute_whatweb(args="https://target.com -a 1")
- **execute_knockpy**: Active subdomain brute-forcing. Discovers subdomains by wordlist-based brute-force and zone transfer checks. Use when you need to find subdomains that passive sources miss. Example: execute_knockpy(args="example.com")
- **execute_gau**: Passive URL discovery from Wayback Machine, Common Crawl, OTX, and URLScan. More comprehensive than waybackurls — aggregates multiple archive sources. Use for discovering historical endpoints, parameters, and hidden paths. Example: execute_gau(args="example.com --subs")
- **execute_kiterunner**: API endpoint brute-forcer. Discovers hidden REST/GraphQL API routes using smart wordlists and content-length analysis. Use when you suspect undocumented API endpoints. Example: execute_kiterunner(args="scan https://target.com -A=apiroutes-210228")
- **execute_wappalyzer**: Technology fingerprinting with 6,000+ fingerprints. Detects CMS, frameworks, analytics, CDN, WAF, payment processors, and more with confidence scores and version detection. Use for comprehensive tech stack identification. Example: execute_wappalyzer(args="https://target.com")
- **execute_crtsh**: Certificate transparency subdomain discovery. Queries crt.sh CT logs passively (no direct target interaction) to find subdomains from SSL/TLS certificates. Use as a fast, passive subdomain source. Example: execute_crtsh(args="example.com")
**NOTE: The following active scanning tools require the EXPLOITATION phase. Request a phase transition first.**
- **execute_nuclei**: Vulnerability scanner (exploitation phase). Example: execute_nuclei(args="-u https://target.com -severity critical,high -jsonl")
- **execute_naabu**: Fast SYN/CONNECT port scanner (exploitation phase). Example: execute_naabu(args="-host target.com -p 80,443,8080 -json")
- **execute_nmap**: Port/service scan (exploitation phase). Example: execute_nmap(args="-sV -sC -p 80,443 target.com")
- **execute_masscan**: Fast port scan (exploitation phase). Example: execute_masscan(args="192.168.1.0/24 -p80,443 --rate=1000")
- **execute_ffuf**: Web fuzzer (exploitation phase). Example: execute_ffuf(args="-u https://target.com/FUZZ -w wordlist.txt -mc 200")
- **execute_schemathesis**: API fuzzer for OpenAPI/GraphQL schemas. Reads the schema and auto-generates test cases to find 500 errors, validation issues, and security flaws. Point it at the OpenAPI spec URL. Example: execute_schemathesis(args="run https://target.com/openapi.json --checks all") or execute_schemathesis(args="run https://target.com/graphql --checks all")
- **execute_browser**: Headless browser for live exploit execution. Supports multi-step action chains with session persistence. Use for:
  - **XSS testing**: `{{"actions": [{{"action": "check_xss", "url": "https://target.com/search?q=<script>alert(1)</script>"}}]}}`
  - **Form injection**: `{{"actions": [{{"action": "submit_form", "url": "https://target.com/login", "fields": {{"#user": "admin' OR 1=1--", "#pass": "x"}}, "submit_selector": "#login-btn"}}]}}`
  - **Auth bypass**: `{{"actions": [{{"action": "set_cookie", "name": "role", "value": "admin", "url": "https://target.com"}}, {{"action": "check_response", "url": "https://target.com/admin", "expected_status": 403, "description": "admin panel auth bypass"}}]}}`
  - **JavaScript execution**: `{{"actions": [{{"action": "navigate", "url": "https://target.com"}}, {{"action": "execute_js", "script": "document.cookie"}}]}}`
  - **SSRF detection**: Navigate and inspect network_requests in the output to see outgoing connections
  Actions: navigate, fill, click, type, execute_js, get_source, get_cookies, set_cookie, screenshot, wait, check_xss, submit_form, check_response
- **nuclei_help**, **naabu_help**, **httpx_help**, **subfinder_help**, **dnsx_help**, **katana_help**, **tldfinder_help**, **waybackurls_help**, **nmap_help**, **masscan_help**, **ffuf_help**, **amass_help**, **whatweb_help**, **knockpy_help**, **gau_help**, **kiterunner_help**, **schemathesis_help**: Get CLI usage for each tool
- **add_asset**: Add a target to the asset inventory. Use when the target is NOT already in the database. Args: **value** (required — hostname, domain, IP, or URL), asset_type (optional, auto-detected), description (optional). Example: add_asset(value="test-git.glensserver.com"). Once added, you can scan it and use create_finding.
- **create_scan**: Create an async bulk scan job handled by the scanner worker. Use this instead of execute_* tools when you need to scan many targets (e.g. a list of IPs, subnets, or domains). Args: **scan_type** (required — port_scan, vulnerability, waybackurls, katana, paramspider, http_probe, technology, screenshot, login_portal, subdomain_enum, dns_resolution, discovery, full, geo_enrich, tldfinder, whatweb, llm_red_team), **targets** (optional list of hostnames/IPs — omit to scan all org assets), name (optional), config (optional dict, e.g. {"severity": ["critical","high"]}). Examples: create_scan(scan_type="port_scan", targets=["10.0.0.0/24"]), create_scan(scan_type="vulnerability", targets=["example.com"]), create_scan(scan_type="llm_red_team", targets=["https://example.com"], config={"categories": ["prompt_injection","jailbreak"]}). The scan runs asynchronously — results appear on the Scans page and update asset records automatically.
- **save_note**: Save a finding for this session (category: credential|vulnerability|finding|artifact, content: str, target: optional)
- **get_notes**: Get session notes (optional category filter)
- **create_finding**: Add a finding to the platform findings table. Args: title, description, severity (critical|high|medium|low|info), target (hostname/domain/URL — will be auto-added to inventory if not found), optional: evidence, cve_id, remediation. Findings appear in the UI.
- **execute_llm_red_team**: Run AI/LLM red team security scan against chatbot endpoints on a target URL. Tests for prompt injection, jailbreak, data exfiltration, SSRF, system prompt leakage, excessive agency, hallucination, and harmful content generation. Auto-discovers chatbot API endpoints. Args: **target_url** (required), categories (optional comma-separated: prompt_injection,jailbreak,data_exfiltration,ssrf_tool_abuse,system_prompt_leakage,excessive_agency,hallucination,harmful_content), endpoint_url (optional — direct chatbot API URL if known), message_field (optional — JSON field name, default "message"), max_payloads (optional int). Example: execute_llm_red_team(target_url="https://example.com"), execute_llm_red_team(target_url="https://example.com", endpoint_url="https://example.com/api/chat", categories="prompt_injection,jailbreak"). Findings are auto-created in the platform.

### Injection Testing Tools
- **generate_injection_payloads**: Generate context-aware injection payloads. Args: **vuln_type** (required — sqli, xss, ssti, cmdi, path_traversal, xxe, ssrf, crlf, open_redirect), technique (optional sub-technique e.g. "time_based" for sqli, "encoded" for xss, "auth_bypass" for sqli — omit for all), max_payloads (optional, default 20), collaborator_url (optional — replaces COLLABORATOR placeholder for OOB testing). Returns payloads AND detection_hints to help you recognize a successful exploit. Example: generate_injection_payloads(vuln_type="sqli", technique="time_based")
- **discover_parameters**: Fetch a URL and extract injectable parameters from HTML forms, query strings, hidden inputs, and JavaScript. Classifies parameters by vulnerability proneness (sqli, xss, ssrf, path_traversal, cmdi, redirect). Use this BEFORE generating payloads to know WHAT to test. Example: discover_parameters(url="https://target.com/search")

### Injection Testing Methodology (use this workflow when testing for vulnerabilities)
**Step 1: Discover parameters** — Run `discover_parameters(url="https://target.com/page")` on pages with forms, search bars, or query parameters. Check the `likely_vulnerable_to` field for each parameter.
**Step 2: Generate payloads** — Run `generate_injection_payloads(vuln_type="sqli")` (or xss, ssti, etc.) to get payloads with detection hints.
**Step 3: Test with payloads** — Use `execute_browser` (submit_form, check_xss), `execute_curl`, or `execute_ffuf` to inject each payload into the discovered parameters. For SQLi, test both error-based and time-based. For XSS, use the check_xss browser action.
**Step 4: Analyze responses** — Use the `detection_hints` from Step 2 to evaluate whether the payload succeeded. Look for SQL error messages, reflected payloads, timing differences, or unexpected content.
**Step 5: Record findings** — Use `create_finding` immediately for each confirmed vulnerability with the payload and evidence.

**Quick-test workflow for a single page:**
1. `discover_parameters(url="...")` → find params
2. `generate_injection_payloads(vuln_type="sqli")` → get SQLi payloads
3. `execute_curl(args="-s 'https://target.com/page?id=PAYLOAD'")` for each interesting payload
4. OR `execute_browser` with `submit_form` action for POST forms
5. `create_finding(...)` for confirmed vulns
"""

    exploitation_tools = """
### Exploitation Phase Tools (if enabled)
- All Informational tools are available in this phase.
- **execute_schemathesis**: API schema fuzzing (requires exploitation phase for active fuzzing).
- **execute_browser**: Headless browser automation for live exploit execution (XSS, injection, auth bypass, SSRF). Use for interactive web app testing that requires a real browser.
"""

    post_exploitation_tools = """
### Post-Exploitation Phase Tools (requires approval)
- All Exploitation tools
"""

    tools = informational_tools
    
    if phase in ["exploitation", "post_exploitation"]:
        tools += exploitation_tools
    
    if phase == "post_exploitation" and post_expl_enabled:
        tools += post_exploitation_tools
    
    return tools


# Tool phase mapping
TOOL_PHASE_MAP = {
    # Informational tools - available in all phases
    "add_asset": ["informational", "exploitation", "post_exploitation"],
    "create_scan": ["informational", "exploitation", "post_exploitation"],
    "query_assets": ["informational", "exploitation", "post_exploitation"],
    "query_vulnerabilities": ["informational", "exploitation", "post_exploitation"],
    "query_ports": ["informational", "exploitation", "post_exploitation"],
    "query_technologies": ["informational", "exploitation", "post_exploitation"],
    "analyze_attack_surface": ["informational", "exploitation", "post_exploitation"],
    "get_asset_details": ["informational", "exploitation", "post_exploitation"],
    "search_cve": ["informational", "exploitation", "post_exploitation"],
    "web_search": ["informational", "exploitation", "post_exploitation"],
    "query_graph": ["informational", "exploitation", "post_exploitation"],
    "save_note": ["informational", "exploitation", "post_exploitation"],
    "get_notes": ["informational", "exploitation", "post_exploitation"],
    "create_finding": ["informational", "exploitation", "post_exploitation"],
    
    # MCP informational tools
    "execute_httpx": ["informational", "exploitation", "post_exploitation"],
    "execute_subfinder": ["informational", "exploitation", "post_exploitation"],
    "execute_dnsx": ["informational", "exploitation", "post_exploitation"],
    "execute_katana": ["informational", "exploitation", "post_exploitation"],
    "execute_curl": ["informational", "exploitation", "post_exploitation"],
    "execute_tldfinder": ["informational", "exploitation", "post_exploitation"],
    "execute_waybackurls": ["informational", "exploitation", "post_exploitation"],
    "nuclei_help": ["informational", "exploitation", "post_exploitation"],
    "naabu_help": ["informational", "exploitation", "post_exploitation"],
    "httpx_help": ["informational", "exploitation", "post_exploitation"],
    "subfinder_help": ["informational", "exploitation", "post_exploitation"],
    "dnsx_help": ["informational", "exploitation", "post_exploitation"],
    "katana_help": ["informational", "exploitation", "post_exploitation"],
    "tldfinder_help": ["informational", "exploitation", "post_exploitation"],
    "waybackurls_help": ["informational", "exploitation", "post_exploitation"],
    "execute_amass": ["informational", "exploitation", "post_exploitation"],
    "amass_help": ["informational", "exploitation", "post_exploitation"],
    "execute_whatweb": ["informational", "exploitation", "post_exploitation"],
    "whatweb_help": ["informational", "exploitation", "post_exploitation"],
    "execute_knockpy": ["informational", "exploitation", "post_exploitation"],
    "knockpy_help": ["informational", "exploitation", "post_exploitation"],
    "execute_gau": ["informational", "exploitation", "post_exploitation"],
    "gau_help": ["informational", "exploitation", "post_exploitation"],
    "execute_kiterunner": ["informational", "exploitation", "post_exploitation"],
    "kiterunner_help": ["informational", "exploitation", "post_exploitation"],
    "execute_wappalyzer": ["informational", "exploitation", "post_exploitation"],
    "execute_crtsh": ["informational", "exploitation", "post_exploitation"],
    "execute_schemathesis": ["exploitation", "post_exploitation"],
    "schemathesis_help": ["informational", "exploitation", "post_exploitation"],
    "execute_browser": ["exploitation", "post_exploitation"],
    "nmap_help": ["informational", "exploitation", "post_exploitation"],
    "masscan_help": ["informational", "exploitation", "post_exploitation"],
    "ffuf_help": ["informational", "exploitation", "post_exploitation"],
    
    # MCP scanning tools - active scanners require exploitation phase for safety.
    # The agent must request a phase transition before running these, giving the
    # user visibility and control over what gets actively scanned.
    "execute_nuclei": ["exploitation", "post_exploitation"],
    "execute_naabu": ["exploitation", "post_exploitation"],
    "execute_nmap": ["exploitation", "post_exploitation"],
    "execute_masscan": ["exploitation", "post_exploitation"],
    "execute_ffuf": ["exploitation", "post_exploitation"],
    
    # Injection testing tools
    "generate_injection_payloads": ["informational", "exploitation", "post_exploitation"],
    "discover_parameters": ["informational", "exploitation", "post_exploitation"],

    # LLM Red Team Scanner
    "execute_llm_red_team": ["informational", "exploitation", "post_exploitation"],
    
    # Legacy scanning tools
    "run_nuclei_scan": ["informational", "exploitation", "post_exploitation"],
    "run_port_scan": ["informational", "exploitation", "post_exploitation"],
    "check_http_status": ["informational", "exploitation", "post_exploitation"],
}


def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    allowed_phases = TOOL_PHASE_MAP.get(tool_name, [])
    return phase in allowed_phases
