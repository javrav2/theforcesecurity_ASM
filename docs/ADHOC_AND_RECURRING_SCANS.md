# Ad Hoc and Recurring Scans (Guardian-Style)

This document describes the scan types you can run **on demand** (ad hoc) or **on a schedule** against your assets, including Guardian-CLI–style options.

---

## How to run scans

- **Ad hoc:** Create a scan via API (`POST /api/v1/scans/adhoc`) or from the UI (e.g. “Run scan” on an asset or org) with a `scan_type` and optional targets.
- **Recurring:** Create a **scan schedule** with a `scan_type`, frequency (daily/weekly/monthly), and targets (or label-based targeting). The scheduler creates scan jobs automatically.

All scan types are defined in `CONTINUOUS_SCAN_TYPES` (see `backend/app/models/scan_schedule.py`). The scanner worker runs the corresponding job type (e.g. `WHATWEB_SCAN`, `TECHNOLOGY_SCAN`, `NUCLEI_SCAN`).

---

## Scan types you can add to assets (ad hoc or recurring)

| scan_type       | Description |
|-----------------|-------------|
| **technology**  | Wappalyzer technology fingerprinting on web assets. |
| **whatweb**     | **WhatWeb** CLI enrichment (1800+ plugins: CMS, frameworks, servers, versions). Complements Wappalyzer. Requires WhatWeb installed (`gem install whatweb` or `apt install whatweb`). |
| **nuclei**      | Full Nuclei vulnerability scan (all severities). |
| **nuclei_critical**, **nuclei_high**, **nuclei_critical_high** | Nuclei with severity filters (faster, focused). |
| **port_scan**, **masscan**, **critical_ports** | Port/service scanning (Naabu, Masscan, or critical ports only). |
| **discovery**, **full_discovery**, **full** | Asset discovery (subdomains, DNS, HTTP probe, optional tech + vuln). |
| **http_probe**  | HTTP probing to mark live web assets. |
| **dns_resolution**, **subdomain_enum** | DNS and subdomain enumeration. |
| **screenshot**  | Web screenshot capture (Playwright/EyeWitness). |
| **paramspider**, **waybackurls**, **katana** | Parameter discovery, historical URLs, deep crawling. |
| **login_portal** | Login portal and admin panel detection. |
| **tldfinder**    | TLD/domain discovery (ProjectDiscovery tldfinder). |
| **geo_enrich**   | Geolocation enrichment for assets. |
| **cleanup**      | System maintenance (temp file cleanup). |

Guardian-CLI–style tools (Nuclei, Nmap, Masscan, FFuf, Amass, Subfinder, HTTPX, etc.) are available to the **AI agent** via MCP; the same tools can back **scheduled or ad hoc scans** when the corresponding scan type exists (e.g. **nuclei**, **port_scan**). **WhatWeb** is the main addition that mirrors Guardian’s “tech fingerprinting” with a dedicated scan type (**whatweb**).

---

## Adding a new scan type (Guardian-style)

1. **ScanType enum** (`backend/app/models/scan.py`): Add e.g. `MY_SCAN = "my_scan"`.
2. **Scanner worker** (`backend/app/workers/scanner_worker.py`): Map `ScanType.MY_SCAN` to a job type and implement the handler (or reuse an existing one with different config).
3. **CONTINUOUS_SCAN_TYPES** (`backend/app/models/scan_schedule.py`): Add an entry for `"my_scan"` with `name`, `description`, `default_config`, and optional `recommended_frequency`.
4. **API** (`backend/app/api/routes/scans.py`, `scan_schedules.py`): Add `"my_scan"` to the `scan_type_map` that maps string → `ScanType`, and in `scans.py` add the mapping to the worker `job_type` if needed.
5. **Frontend**: Expose the new type in the scan/schedule creation UI (dropdown or preset list).

After that, users can run **ad hoc** scans and **recurring** schedules with `scan_type: "my_scan"` for the new capability.

---

## References

- [Guardian-CLI](https://github.com/zakirkun/guardian-cli) – tool set and workflow reference  
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) – next-generation web scanner (tech fingerprinting)  
- [GUARDIAN_TOOL_PARITY.md](GUARDIAN_TOOL_PARITY.md) – which Guardian tools are in the agent/MCP  
- [GRAPH_SCHEMA.md](GRAPH_SCHEMA.md) – graph relationships (technology, IP, domain)
