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

1. **Query the database and graph first** - Use query_assets, query_vulnerabilities, or query_ports for lists and counts. Use **query_graph** for relationship and context questions (e.g. how assets connect to IPs, ports, technologies, vulnerabilities, CVEs; attack paths; what is exposed where). Always filter Cypher by organization_id = $org_id.
2. **Be thorough** - Analyze all available data before making recommendations
3. **Provide actionable guidance** - Give specific remediation steps
4. **Stay in scope** - Only analyze assets within the user's organization
5. **Phase restrictions** - Some tools are only available in specific phases
6. **Complete when done** - Set action to "complete" when the objective is achieved
7. **Session notes** - Use **save_note** to persist important findings (credentials, vulnerabilities, artifacts) so they are remembered for the rest of the session. Categories: credential, vulnerability, finding, artifact.
8. **Findings table** - Use **create_finding** to add vulnerabilities/findings to the platform's findings table so they appear in the UI (Vulnerabilities list). Required: title, description, severity (critical|high|medium|low|info), target (hostname/domain/URL that must match an existing asset). Optional: evidence, cve_id, remediation. Target must match an in-scope asset (use query_assets first).

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

FINAL_REPORT_PROMPT = """Generate a final report summarizing the security assessment session.

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

Create a comprehensive security report that includes:
1. **Executive Summary** - Brief overview of findings
2. **Assets Analyzed** - What was discovered and assessed
3. **Vulnerabilities Found** - Security issues identified with severity
4. **Recommendations** - Prioritized remediation steps
5. **Next Steps** - Suggested follow-up actions

Format the report in a clear, professional manner suitable for security stakeholders.
"""


def get_phase_tools(phase: str, post_expl_enabled: bool = False, post_expl_type: str = "stateless") -> str:
    """Get available tools description for a phase."""
    
    informational_tools = """
### Informational Phase Tools
- **query_assets**: Query assets from the ASM database
- **query_vulnerabilities**: Query vulnerabilities and findings
- **query_ports**: Query open ports and services
- **query_technologies**: Query detected technologies
- **query_graph**: Run a Cypher query against the Neo4j attack surface graph. Use this to answer relationship and context questions: e.g. which assets have path to critical vulns, what technologies sit on the same IP as a CVE, how domains/subdomains/IPs/ports/services/technologies/vulns connect. Always filter by organization: include WHERE a.organization_id = $org_id (or similar) and pass org_id; the tool injects $org_id automatically.
- **analyze_attack_surface**: Get attack surface summary
- **get_asset_details**: Get detailed information about an asset
- **search_cve**: Search for CVE information
- **web_search** (if configured): Search the web for CVE/exploit research. Args: query (required), max_results (optional, default 5). Requires TAVILY_API_KEY in .env.
- **execute_httpx**: Run HTTPX HTTP prober (args: CLI arguments)
- **execute_subfinder**: Run Subfinder subdomain discovery (args: CLI arguments)
- **execute_dnsx**: Run DNSX DNS toolkit (args: CLI arguments)
- **execute_katana**: Run Katana web crawler (args: CLI arguments)
- **execute_curl**: Execute curl HTTP client (args: CLI arguments)
- **execute_tldfinder**: Run tldfinder for TLD/domain discovery (args: e.g. '-d example.com -dm domain -oJ')
- **execute_waybackurls**: Fetch historical URLs from Wayback Machine (args: domain or CLI args)
- **execute_amass**: Run Amass subdomain/network mapping (args: e.g. 'enum -d example.com -json -')
- **execute_whatweb**: Run WhatWeb tech fingerprinting (args: URL or 'https://target.com -a 1'). Requires WhatWeb CLI.
- **execute_nuclei**: Run Nuclei vulnerability scanner (args: e.g. '-u http://target.com -severity critical,high'). Use for vuln assessments.
- **execute_naabu**: Run Naabu port scanner (args: e.g. '-host target.com -p 80,443' or '-list hosts.txt -p -').
- **execute_nmap**: Run Nmap port/service scanning (args: e.g. '-sV -sC -p 80,443 target.com').
- **execute_masscan**: Run Masscan port scan (args: e.g. '192.168.1.0/24 -p80,443 --rate=1000').
- **execute_ffuf**: Run FFuf web fuzzer (args: e.g. '-u https://target.com/FUZZ -w wordlist.txt -mc 200').
- **nuclei_help**, **naabu_help**, **httpx_help**, **subfinder_help**, **dnsx_help**, **katana_help**, **tldfinder_help**, **waybackurls_help**, **nmap_help**, **masscan_help**, **ffuf_help**, **amass_help**, **whatweb_help**: Get CLI usage for each tool
- **save_note**: Save a finding for this session (category: credential|vulnerability|finding|artifact, content: str, target: optional)
- **get_notes**: Get session notes (optional category filter)
- **create_finding**: Add a finding to the platform findings table (title, description, severity: critical|high|medium|low|info, target: host/domain matching an asset, optional: evidence, cve_id, remediation). Use for vulnerabilities so they appear in the UI.
"""

    exploitation_tools = """
### Exploitation Phase Tools (if enabled)
- All Informational tools (including Nuclei, Naabu, Nmap, Masscan, FFuf) are available in informational phase for normal assessments.
- No additional tools in exploitation; use informational phase for vulnerability and port scanning.
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
    "nmap_help": ["informational", "exploitation", "post_exploitation"],
    "masscan_help": ["informational", "exploitation", "post_exploitation"],
    "ffuf_help": ["informational", "exploitation", "post_exploitation"],
    
    # MCP scanning tools - allowed in informational so agent can run vuln/port scans without phase transition
    "execute_nuclei": ["informational", "exploitation", "post_exploitation"],
    "execute_naabu": ["informational", "exploitation", "post_exploitation"],
    "execute_nmap": ["informational", "exploitation", "post_exploitation"],
    "execute_masscan": ["informational", "exploitation", "post_exploitation"],
    "execute_ffuf": ["informational", "exploitation", "post_exploitation"],
    
    # Legacy scanning tools
    "run_nuclei_scan": ["informational", "exploitation", "post_exploitation"],
    "run_port_scan": ["informational", "exploitation", "post_exploitation"],
    "check_http_status": ["informational", "exploitation", "post_exploitation"],
}


def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    allowed_phases = TOOL_PHASE_MAP.get(tool_name, [])
    return phase in allowed_phases
