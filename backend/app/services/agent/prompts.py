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

1. **Query the database first** - Use query_assets, query_vulnerabilities, or query_graph to understand the current attack surface
2. **Be thorough** - Analyze all available data before making recommendations
3. **Provide actionable guidance** - Give specific remediation steps
4. **Stay in scope** - Only analyze assets within the user's organization
5. **Phase restrictions** - Some tools are only available in specific phases
6. **Complete when done** - Set action to "complete" when the objective is achieved

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
- **analyze_attack_surface**: Get attack surface summary
- **get_asset_details**: Get detailed information about an asset
- **search_cve**: Search for CVE information
- **execute_httpx**: Run HTTPX HTTP prober (args: CLI arguments)
- **execute_subfinder**: Run Subfinder subdomain discovery (args: CLI arguments)
- **execute_dnsx**: Run DNSX DNS toolkit (args: CLI arguments)
- **execute_katana**: Run Katana web crawler (args: CLI arguments)
- **execute_curl**: Execute curl HTTP client (args: CLI arguments)
"""

    exploitation_tools = """
### Exploitation Phase Tools (requires approval)
- All Informational tools
- **execute_nuclei**: Execute Nuclei vulnerability scanner (args: CLI arguments like '-u http://target.com -severity critical,high')
- **execute_naabu**: Execute Naabu port scanner (args: CLI arguments like '-host 192.168.1.1 -p 1-1000')
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
    "query_graph": ["informational", "exploitation", "post_exploitation"],
    
    # MCP informational tools
    "execute_httpx": ["informational", "exploitation", "post_exploitation"],
    "execute_subfinder": ["informational", "exploitation", "post_exploitation"],
    "execute_dnsx": ["informational", "exploitation", "post_exploitation"],
    "execute_katana": ["informational", "exploitation", "post_exploitation"],
    "execute_curl": ["informational", "exploitation", "post_exploitation"],
    
    # MCP exploitation tools
    "execute_nuclei": ["exploitation", "post_exploitation"],
    "execute_naabu": ["exploitation", "post_exploitation"],
    
    # Legacy exploitation tools
    "run_nuclei_scan": ["exploitation", "post_exploitation"],
    "run_port_scan": ["exploitation", "post_exploitation"],
    "check_http_status": ["exploitation", "post_exploitation"],
}


def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    allowed_phases = TOOL_PHASE_MAP.get(tool_name, [])
    return phase in allowed_phases
