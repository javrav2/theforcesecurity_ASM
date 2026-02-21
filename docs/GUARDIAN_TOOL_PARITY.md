# Guardian-CLI Tool Parity

This document maps [Guardian-CLI](https://github.com/zakirkun/guardian-cli) tools to The Force Security ASM and explains how to add more tools so the agent can use them.

---

## Guardian’s 19 Tools vs ASM

| Guardian tool | In ASM agent (MCP) | In ASM scanner/backend | Notes |
|---------------|--------------------|-------------------------|--------|
| **nmap** | ✅ `execute_nmap` | ✅ Port verify, service detect, API | Agent can run arbitrary nmap args. |
| **masscan** | ✅ `execute_masscan` | ✅ Port scan, API | Agent can run arbitrary masscan args. |
| **httpx** | ✅ `execute_httpx` | ✅ Discovery, scans | |
| **whatweb** | ✅ `execute_whatweb` | ✅ Technology scan (source=whatweb), WhatWeb service | Agent + scheduled/ad hoc scans; install: `gem install whatweb` or `apt install whatweb`. |
| **wafw00f** | ❌ | ❌ | Can add if binary installed. |
| **subfinder** | ✅ `execute_subfinder` | ✅ Discovery | |
| **amass** | ✅ `execute_amass` | ✅ Backend image | |
| **dnsrecon** | ❌ | ❌ | We use dnsx; can add dnsrecon if installed. |
| **nuclei** | ✅ `execute_nuclei` | ✅ Vuln scans | |
| **nikto** | ❌ | ❌ | Can add if binary installed. |
| **sqlmap** | ❌ | ❌ | Can add if binary installed. |
| **wpscan** | ❌ | ❌ | Can add if binary installed. |
| **testssl** | ❌ | ❌ | Can add if installed; we have TLS playbooks. |
| **sslyze** | ❌ | ❌ | Can add if installed. |
| **gobuster** | ❌ | ❌ | We have ffuf; can add gobuster if installed. |
| **ffuf** | ✅ `execute_ffuf` | ✅ Backend + ffuf_service | Agent can run arbitrary ffuf args. |
| **arjun** | ❌ | ❌ | Param discovery via ParamSpider; can add Arjun. |
| **xsstrike** | ❌ | ❌ | Can add if installed. |
| **gitleaks** | ❌ | ❌ | We have github_secrets; can add GitLeaks CLI. |
| **cmseek** | ❌ | ❌ | Can add if installed. |

**Also in ASM agent (not in Guardian list):** `execute_naabu`, `execute_dnsx`, `execute_katana`, `execute_curl`, `execute_tldfinder`, `execute_waybackurls` — all available with `*_help` for usage.

---

## How to Add a New Tool for the Agent

To expose a new CLI tool (e.g. Nikto, SQLMap) so the agent can run it:

### 1. Install the binary

- **Backend container (agent runs here):** Add the tool to `backend/Dockerfile` (e.g. `apt-get install` or copy from a builder stage).
- **Scanner container:** Add to `backend/Dockerfile.scanner` only if scheduled/automated scans should run it; the **agent uses the backend** image.

### 2. Register in MCP (`backend/app/services/mcp/server.py`)

In `_register_default_tools()`:

- Register an **execute_&lt;tool&gt;** `MCPTool`:
  - `name="execute_<tool>"`
  - `parameters={"args": {"type": "string", "description": "..."}}`
  - `required_params=["args"]`
  - `handler=self._execute_<tool>`
  - Choose `phase="informational"` or `phase="exploitation"` (exploitation requires user approval in the agent).
- Register a **&lt;tool&gt;_help** `MCPTool` with no params and `handler=self._<tool>_help`.

Implement handlers that run the CLI, e.g.:

```python
async def _execute_nikto(self, args: str) -> Dict[str, Any]:
    cmd = ["nikto"] + args.split()
    return await self._run_command(cmd, timeout=300)

async def _nikto_help(self) -> Dict[str, Any]:
    return await self._run_command(["nikto", "-h"])
```

### 3. Expose to the agent (`backend/app/services/agent/tools.py`)

In `ASMToolsManager._register_tools()`, add:

- `"execute_<tool>": self.execute_mcp_tool`
- `"<tool>_help": self.execute_mcp_tool`

### 4. Add to prompts and phase map (`backend/app/services/agent/prompts.py`)

- In **get_phase_tools()**: add the tool to the appropriate phase block (informational vs exploitation) and list the `*_help` in the help tools line.
- In **TOOL_PHASE_MAP**: add entries for `execute_<tool>` and `<tool>_help` with the correct phase list (e.g. `["exploitation", "post_exploitation"]` for active scanning tools).

After that, the agent will see the tool in its phase and can call it (with approval for exploitation-phase tools when configured).

---

## Summary

- **Agent-available (Guardian-style):** Nmap, Masscan, HTTPX, Subfinder, Amass, Nuclei, FFuf, plus Naabu, DNSX, Katana, curl, TLDFinder, WaybackURLs.
- **Not yet in agent:** WhatWeb, Wafw00f, DNSRecon, Nikto, SQLMap, WPScan, TestSSL, SSLyze, Gobuster, Arjun, XSStrike, GitLeaks, CMSeeK — add by following the steps above once the binary is installed in the backend image.
