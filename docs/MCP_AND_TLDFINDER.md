# MCP Tools & TLDFinder

This document describes the **Model Context Protocol (MCP)** integration and **TLDFinder**-based TLD/domain discovery.

---

## 1. TLDFinder – Platform-Level TLD/Domain Coverage

TLDFinder is implemented **at the platform level**: when you **change targets** (organization or explicit scan targets), the system runs TLD/domain discovery **for that company**. You get broader coverage of domains and subdomains owned by or related to that organization.

- **Targets** come from:
  - **Explicit scan targets** (e.g. `["rockwellautomation.com"]`) when you create a tldfinder scan or schedule, or
  - **The organization’s primary domain** (Settings → organization domain), or
  - **Root domains of existing assets** in that org (if no explicit targets and no org domain).
- So for a company like “Rockwell Automation”: set the org domain or pass `rockwellautomation.com` (or related roots) as targets; tldfinder then discovers subdomains/domains from multiple sources (Wayback, whoisxmlapi, etc.). All discovered domains are created as assets in that organization.

[ProjectDiscovery tldfinder](https://github.com/projectdiscovery/tldfinder) is the underlying tool; the platform runs it for the **current org/targets** so you get **all TLD/domain coverage for that company**.

### Installation

```bash
go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest
```

Ensure `tldfinder` is on the `PATH` where the backend/worker runs (e.g. in your Docker image or host).

### How It’s Used in the App

- **Discovery (optional step)**  
  In full discovery, set `use_tldfinder: true` (API or scan config). After subdomain enumeration, tldfinder runs for the seed domain and extra domains are merged in.
- **Dedicated scan**  
  Run a **tldfinder** scan (schedules or ad-hoc). Targets can be:
  - Explicit `targets` (e.g. `["rockwellautomation.com"]`), or
  - Org’s primary domain, or
  - Root domains from existing assets.  
  Discovered domains are created as assets (subdomain/domain); graph sync runs after completion.
- **API**  
  - **Discovery:** `POST /api/v1/discovery/full` with `use_tldfinder: true` and your `domain`.
  - **Scan:** Create a scan with `scan_type: "tldfinder"` and optional `targets`; if empty, org domain / asset roots are used.

### Configuration

- **Scan config** (e.g. schedule or ad-hoc):  
  `discovery_mode`: `"domain"` (default) | `"dns"` | `"tld"`  
  `max_time_minutes`: timeout for tldfinder (default 10).
- **Discovery config** (full discovery):  
  `use_tldfinder`: boolean (default false).

---

## 2. MCP Layer – What It Is and What It’s Exposed To

**What is the MCP layer?**  
It’s a **Model Context Protocol (MCP)** server inside the app that **exposes your security tools** (Nuclei, Naabu, HTTPX, Subfinder, DNSX, Katana, curl, tldfinder, waybackurls) as **tools** the AI can call by name with arguments.

**What is it exposed to?**  
The MCP tools are exposed to the **AI security agent** (orchestrator). The agent runs inside your backend and uses these tools when it needs to run scans, discovery, or other tests. It does **not** expose tools directly to end users or to the browser; users interact via the **Agent** (see “Ask a question for testing” below).

**Flow:**  
User asks a question → Agent (orchestrator) decides what to do → Agent calls MCP tools (e.g. `execute_nuclei`, `execute_naabu`) → Tools run (nuclei, naabu, etc.) → Results go back to the agent → Agent summarizes and responds to the user.

So: **MCP = the way the agent gets access to your security tooling.** The user gets the ability to “ask a question for testing to take place” through the Agent UI or API, not by calling MCP directly.

---

## 3. Ask a Question for Testing to Take Place

Users **can** ask a question and have the platform run tests (scans, discovery, etc.). The agent uses the MCP tools to do that.

- **In the UI:** Use the **Agent** page (sidebar → **Agent**). Type a question (e.g. “Run a quick port scan on example.com” or “What are the critical vulnerabilities for my organization?”). The agent will plan steps, call tools (nuclei, naabu, httpx, etc.) via MCP, and return a summary and any approval prompts.
- **Via API:**  
  - **Send a question:** `POST /api/v1/agent/query` with `{"question": "Scan example.com for critical vulnerabilities"}`.  
  - The response includes `answer`, `task_complete`, `awaiting_approval`, `question_request`, etc.  
  - If the agent asks for approval (e.g. before running an exploit-phase tool), use `POST /api/v1/agent/approve` or `POST /api/v1/agent/answer` with the same `session_id`.

**Requirements:** Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` so the agent is available. The user must belong to an organization (the agent is scoped to that org).

---

## 4. MCP Server – Tool List 
The app runs a **single MCP server** (in-process) that exposes security tools to the AI agent. **Dynamic CLI** design: the agent passes raw CLI arguments and can call `*_help` for usage.

### Tool List 
| Tool | Description |
|------|-------------|
| **execute_nuclei** | Run Nuclei with CLI args (e.g. `-u http://target.com -severity critical,high -jsonl`) |
| **nuclei_help** | Nuclei usage |
| **execute_naabu** | Run Naabu with CLI args (e.g. `-host 10.0.0.5 -p 1-1000 -json`) |
| **naabu_help** | Naabu usage |
| **execute_httpx** | Run HTTPX (e.g. `-u http://target.com -json -tech-detect`) |
| **httpx_help** | HTTPX usage |
| **execute_subfinder** | Run Subfinder (e.g. `-d example.com -json`) |
| **subfinder_help** | Subfinder usage |
| **execute_dnsx** | Run DNSX (e.g. `-d example.com -a -aaaa -json`) |
| **dnsx_help** | DNSX usage |
| **execute_katana** | Run Katana (e.g. `-u http://target.com -d 3 -json`) |
| **katana_help** | Katana usage |
| **execute_curl** | Run curl (e.g. `-s -i http://target.com/`) |
| **execute_tldfinder** | Run tldfinder (e.g. `-d example.com -dm domain -oJ`) |
| **tldfinder_help** | tldfinder usage |
| **execute_waybackurls** | Run waybackurls (domain or CLI args) |
| **waybackurls_help** | waybackurls usage (if supported) |

Tools are implemented in `backend/app/services/mcp/server.py`. The agent calls them via `execute_mcp_tool`; `execute()` routes any `execute_*` or `*_help` tool to the MCP server.

### API Endpoints

- **List tools:** `GET /api/v1/mcp/tools` (optional `?phase=informational`)  
- **Call tool:** `POST /api/v1/mcp/call` with `{"tool_name": "execute_naabu", "arguments": {"args": "-host 10.0.0.5 -p 80,443"}}`  
- **Convenience:** `POST /api/v1/mcp/execute/execute_naabu?args=-host 10.0.0.5 -p 80`  
- **Health:** `GET /api/v1/mcp/health`

### Running Tools

Tools run as subprocesses (`nuclei`, `naabu`, `httpx`, etc.). Those binaries must be installed and on the `PATH` for the backend (or the container that runs the worker/API). No separate Kali container is required unless you want one; dynamic CLI style is used (the LLM passes tool flags).

### Optional: SSE Transport

Some setups run one MCP server per tool over SSE (e.g. naabu :8000, nuclei :8002). This app uses one in-process server. If you want **external** MCP clients (e.g. Claude Code) to connect over SSE, you would add an SSE transport layer that exposes the same tool list and forwards JSON-RPC to the existing `MCPServer.call_tool()`. The current API is HTTP-only; the agent uses it via the backend’s `execute_mcp_tool` path.

---

## 5. Summary

- **TLDFinder:** Install the binary, then use **full discovery with `use_tldfinder: true`** or a **tldfinder** scan (with targets or org/asset-derived domains) for better TLD/domain coverage (e.g. for keywords like “Rockwell Automation”).
- **MCP:** All listed tools (nuclei, naabu, httpx, subfinder, dnsx, katana, curl, tldfinder, waybackurls + help) are registered and callable by the AI agent and via the HTTP API; add binaries to the environment where the backend runs.
