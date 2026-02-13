# Reconnaissance Workflow

This document describes the **recon pipeline** used by the ASM platform: same phase order as common recon frameworks, using our existing tools and richer analysis.

---

## Pipeline order (phases)

Phases run in this order. Each phase can be enabled/disabled per organization via **Project Settings → scan_toggles**.

| # | Phase | Description | Our tools |
|---|--------|-------------|-----------|
| 1 | **Domain discovery** | Subdomains, DNS, WHOIS-style context | `DiscoveryService` (crt.sh, Whoxy, TLD Finder, DNS, subdomain enum); creates/updates assets |
| 2 | **Port scan** | Open ports and services on discovered hosts | `PortScannerService` (Naabu, Masscan, Nmap); port verification and service detection |
| 3 | **HTTP probe** | Live web endpoints, status, titles, tech hints | `DNSResolutionService.probe_http` / `probe_and_update_assets`; updates `is_live`, `live_url`, `http_status` |
| 4 | **Resource enumeration** | Endpoints, parameters, historical URLs | `KatanaService` (crawl), `WaybackURLsService`, `ParamSpiderService`; endpoints/parameters stored on assets |
| 5 | **Vulnerability scan** | Template-based and DAST findings | `NucleiService`; findings stored as vulnerabilities with CVE/CWE enrichment |

After the pipeline (or any scan), **graph sync** runs so Neo4j has the canonical chain: Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE.

---

## Phase details

### 1. Domain discovery

- **Input:** Seed domain(s) from scan targets.
- **Actions:** Subdomain enumeration, DNS resolution, optional HTTP probe and technology detection inside discovery.
- **Output:** Assets (domain, subdomain, IP) in the database; IPs and DNS data on assets.

### 2. Port scan

- **Input:** Targets = asset values (hostnames/IPs) for the organization (from phase 1).
- **Actions:** Naabu/Masscan/Nmap; optional port verification and service detection.
- **Output:** `PortService` records linked to assets; optional port-finding records.

### 3. HTTP probe

- **Input:** Targets = asset hostnames (or “all org assets” if empty).
- **Actions:** HTTP/HTTPS probe; status, title, redirects, `live_url`, optional tech detection.
- **Output:** Assets updated with `is_live`, `http_status`, `http_title`, `live_url`, IPs.

### 4. Resource enumeration

- **Input:** Live (or any domain/subdomain) assets; handlers can resolve targets from DB if not provided.
- **Actions:**
  - **Katana:** Crawl live URLs → endpoints, parameters, JS.
  - **WaybackURLs:** Historical URLs per domain.
  - **ParamSpider:** Parameter discovery per domain.
- **Output:** `endpoints`, `parameters`, `js_files` (and related) on assets.

### 5. Vulnerability scan

- **Input:** Targets = live URLs or hostnames (from assets).
- **Actions:** Nuclei with severity/tags/templates; CVE/CWE and optional MITRE enrichment.
- **Output:** `Vulnerability` records linked to assets; graph gets Vulnerability → CVE / MAPS_TO.

---

## How to run the full workflow

- **Scan type:** Use **Full** (`scan_type: "full"`). The worker runs the **recon pipeline** in the order above.
- **Toggles:** In Project Settings, module **scan_toggles**:
  - `domain_discovery`, `port_scan`, `http_probe`, `resource_enum`, `vuln_scan` (each `true`/`false`).
- **Targets:** Set scan `targets` to one or more seed domains (e.g. `["example.com"]`). Discovery uses these; later phases use discovered assets for the same organization.

You can still run individual phases by scheduling or triggering a single scan type (Discovery, Port scan, HTTP probe, Katana, WaybackURLs, ParamSpider, Vulnerability).

---

## Data flow

```
Seed domain(s)
    → Domain discovery (subdomains, DNS, assets)
    → Port scan (targets = asset values)
    → HTTP probe (live URLs, tech hints)
    → Resource enum (Katana, Wayback, ParamSpider)
    → Vulnerability scan (Nuclei)
    → Graph sync (Domain → … → CVE)
```

All data stays in PostgreSQL (assets, port_services, vulnerabilities, etc.); Neo4j is updated from that data for attack-path and graph analysis.
