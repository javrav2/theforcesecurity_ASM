# Graph & Data Flow Roadmap

This document outlines how to embed **asset-centric data flows** and **Neo4j-powered attack surface mapping** across all scan types: *Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE* with multi-tenant support.

---

## 1. Where You Are Today

- **Neo4j** is integrated (`graph_service.py`): full chain plus web layer (BaseURL, Endpoint, Parameter; SERVES_URL, HAS_ENDPOINT, HAS_PARAMETER, FOUND_AT) in `_sync_asset()`.
- **Graph sync** runs after every relevant scan (discovery, DNS, port, HTTP probe, technology, Nuclei, login portal, screenshot, ParamSpider, WaybackURLs, Katana, geo enrich, etc.).
- **AI Agent** has **query_graph** (Cypher, tenant-safe) plus query_assets, query_vulnerabilities, query_ports, query_technologies, analyze_attack_surface. The prompts reference `query_graph` but the tool is not implemented — so the agent cannot reason over the graph (e.g. run Cypher before every decision) yet.

---

## 2. Data Flow Principle: Assets First, Graph Always Updated

**Idea:** Treat **assets** as the source of truth for “what we care about,” and every scan as a **stage in a pipeline** that both updates PostgreSQL and keeps Neo4j in sync so the graph always has full context.

### 2.1 Explicit pipeline stages (asset-centric)

Map your scan types to a linear flow per asset (or per org):

```
Assets (created/updated)
    ↓
Discovery / DNS / Subdomain enum   →  enrich assets, resolve IPs
    ↓
Port scan                          →  HAS_PORT, RUNS_SERVICE
    ↓
HTTP probe / Technology / Cert     →  live URLs, USES_TECHNOLOGY
    ↓
App structure (Katana, ParamSpider, Wayback)  →  endpoints, parameters (optional graph nodes)
    ↓
Vulnerability (Nuclei)              →  HAS_VULNERABILITY, REFERENCES_CVE
    ↓
(Optional) CVE/MITRE enrichment    →  CVE, CWE, CAPEC in graph
```

- Each stage reads from the previous (e.g. port scan runs on assets with IPs; Nuclei on live URLs).
- Every stage that **mutates** assets, ports, technologies, or vulnerabilities should **trigger a graph sync** (see below) so the graph reflects “all assets with context.”

### 2.2 Trigger graph sync after every relevant scan

**Implemented:** `trigger_graph_sync(organization_id)` is called after every scan type that mutates graph-relevant data:

| Scan type / event        | Why trigger sync |
|--------------------------|-------------------|
| Discovery / subdomain    | New/updated assets, parent-child, IPs |
| DNS resolution / enum    | IPs, DNS on assets |
| Port scan / verify       | Ports, services |
| HTTP probe               | `is_live`, `http_status`, etc. |
| Technology               | Technologies on assets |
| **Nuclei (vuln import)** | New/updated vulnerabilities, CVEs |
| **Login portal**         | `has_login_portal`, `login_portals` on host assets |
| Screenshot               | Asset metadata / latest screenshot |
| Katana / ParamSpider / Wayback | Endpoints/parameters on assets → Endpoint/Parameter nodes in graph |

**Implementation:** In `scanner_worker.py`, after each job handler completion, call:

```python
trigger_graph_sync(organization_id)
```

For single-asset updates (e.g. one asset’s ports or tech), you can call `sync_asset_to_graph(asset_id, organization_id)` instead of a full org sync if you add that to the worker.

---

## 3. Neo4j as the place for “context”

- Keep **PostgreSQL** as the system of record for assets, scans, and findings.
- Use **Neo4j** as the **context layer**: relationships (Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE) for visualization, attack-path analysis, and **AI agent reasoning**.

So:

- All **writes** stay in PostgreSQL (and optionally in Neo4j via sync).
- **Reads for “context”** (e.g. “what’s connected to this asset?”, “which assets have critical vulns?”) should be doable via the graph (Cypher) and via your API that uses the graph (e.g. `get_asset_relationships`, `get_attack_paths`).

---

## 4. AI Agent: add `query_graph` (Cypher)

The agent **queries the graph (Cypher)** before making decisions. The app already has the graph and an `execute_graph_query` API, but the agent has no tool to use it.

**Recommendation:**

1. **Implement a `query_graph` tool** in `backend/app/services/agent/tools.py` that:
   - Accepts a **Cypher query** (and optionally params).
   - Enforces **tenant isolation** (inject `organization_id` or use a safe parameter).
   - Calls `GraphService.query(cypher, params)` and returns a sanitized result (e.g. first N rows, no sensitive fields).
2. **Register** `query_graph` in `_register_tools()` and document it in the agent’s tool list.
3. **Prompting:** Keep “query the database first” but make it explicit: use `query_assets` / `query_vulnerabilities` for listing, and **`query_graph`** for “how is X connected to Y?”, “which assets have path to critical vulns?”, “what technologies sit on the same IP as this CVE?”.

This gives you “reason over the graph” without changing your existing ReAct flow.

---

## 5. Endpoint / Parameter / BaseURL nodes — Implemented

Implemented: **BaseURL** (per asset with `live_url`), **Endpoint** (from `asset.endpoints`), **Parameter** (from `asset.parameters`). Relationships: Asset→BaseURL (SERVES_URL), Asset→Endpoint (HAS_ENDPOINT), Asset→Parameter (HAS_PARAMETER), Service→BaseURL for 80/443; **FOUND_AT** (Vulnerability→Endpoint) when vuln has url/path in metadata or evidence. Future: Endpoint→Parameter, AFFECTS_PARAMETER; Header, Certificate, DNSRecord, MitreData, Capec, Exploit.

---

## 6. Optional: Pipeline UI (per asset or per org)

To make “data flows” visible and runnable:

- Add a **pipeline** view (e.g. per organization or per root domain):
  - Rows or columns = stages: Discovery → Port scan → HTTP/Tech → App structure → Vuln scan.
  - For each stage, show status (e.g. “Run”, “Running”, “Done”, “Failed”) and last run time.
- **Actions:** “Run discovery”, “Run port scan for these assets”, “Run Nuclei for live URLs”, etc., each starting the right scan type and then triggering graph sync on completion.

This doesn’t require new scan types — it’s a UI that starts existing scans in order and shows status, so “asset-centric data flow” is clear to users.

---

## 7. Summary checklist

| Item | Status |
|------|--------|
| Trigger graph sync after every scan that mutates graph-relevant data | Done |
| Add `query_graph` tool for the AI agent (Cypher + tenant-safe) | Done |
| BaseURL/Endpoint/Parameter nodes and FOUND_AT | Done |
| Document and enforce asset-centric pipeline in code/docs | Partial |
| Optional: Pipeline UI (run stages in order, show status) | Future |

Once graph sync runs after every relevant scan and the agent can `query_graph`, you’ll have **Neo4j-powered attack surface mapping with context** and **data flows that start from assets** and keep the graph in sync, similar to The approach.
