# Graph Database Schema

## Canonical relationship chain

```
Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE
                                                          Vulnerability → MITRE
```

## Entity-relationship (high level)

| From       | Relationship   | To           |
|-----------|----------------|--------------|
| Domain    | HAS_SUBDOMAIN  | Subdomain    |
| Subdomain | RESOLVES_TO    | IP           |
| IP        | HAS_PORT       | Port         |
| Port      | RUNS_SERVICE   | Service      |
| Service   | USES_TECHNOLOGY| Technology   |
| Technology| HAS_VULNERABILITY | Vulnerability |
| Vulnerability | REFERENCES | CVE        |
| Vulnerability | MAPS_TO    | MITRE       |
| Subdomain     | SAME_IP_AS | Subdomain   |

**SAME_IP_AS** is created between Subdomains that resolve to the same IP (per organization). Use it to answer “what else is on this IP?” and to reason about shared infrastructure (RedAmon-style graph robustness).

## Logical connections (RedAmon-style)

These patterns support attack-surface reasoning and technology/domain relationships:

- **Same IP** – Subdomains that share an IP (co-hosted):  
  `(s1:Subdomain)-[:SAME_IP_AS]-(s2:Subdomain)`  
  Example: “Subdomains on same IP as this asset”  
  `MATCH (a:Asset)-[:RESOLVES_TO]->(ip:IP)<-[:RESOLVES_TO]-(s:Subdomain) WHERE a.organization_id = $org_id RETURN s`

- **Same technology** – Assets using the same technology:  
  `(t:Technology)<-[:USES_TECHNOLOGY]-(a:Asset)`  
  Example: “All assets running WordPress”  
  `MATCH (t:Technology {name: 'WordPress'})<-[:USES_TECHNOLOGY]-(a:Asset) WHERE a.organization_id = $org_id RETURN a`

- **Technology → CVE** – Vulnerabilities linked to a technology (via Asset or Service):  
  `(t:Technology)-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:REFERENCES]->(c:CVE)`  
  Example: “Technologies with critical CVEs”  
  `MATCH (t:Technology)-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:REFERENCES]->(c:CVE) WHERE v.severity = 'critical' AND v.organization_id = $org_id RETURN t, c`

- **Domain → Subdomain → IP** – Full chain for a root domain:  
  `(d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(ip:IP)`  
  Always filter by `organization_id` (e.g. `d.organization_id = $org_id`).

## Node types and properties

### Domain (root)

- `name` (string) – root domain name
- `organization_id` (number) – tenant
- `discovered_at` (datetime) – when first seen

### Subdomain

- `name` (string) – hostname / subdomain
- `status` (string) – e.g. discovered, verified

### IP

- `address` (string) – IP address
- `type` (string) – e.g. ipv4, ipv6
- `is_cdn` (boolean) – CDN/cloud indicator

### Port

- `number` (int) – port number
- `protocol` (string) – tcp, udp
- `state` (string) – open, closed, filtered

### Service

- `name` (string) – service name
- `version` (string) – optional version
- `banner` (string) – optional banner

### Technology

- `name` (string) – technology name
- `version` (string) – optional version
- `category` (string) – category

### Vulnerability

- `id` (string) – unique identifier
- `severity` (string) – critical, high, medium, low, info
- `description` (string) – finding description

### CVE

- `cve_id` (string) – CVE identifier (e.g. CVE-2021-1234)
- `cvss_score` (number) – optional
- `cwe_id` (string) – optional CWE link

### MITRE (CWE)

- `cwe_id` (string) – CWE identifier (e.g. CWE-89)
- Used for Vulnerability → MAPS_TO → MITRE (weakness mapping).

## Multi-tenant filtering

All queries must filter by `organization_id` (or equivalent tenant id) so that indexes are used and data is isolated per organization.

## Implementation notes

- **Domain**: One node per (organization_id, root domain).
- **Subdomain**: One node per (organization_id, hostname); linked from Domain via HAS_SUBDOMAIN.
- **IP**: One node per address; Subdomain RESOLVES_TO IP.
- **Port**: Linked from IP via HAS_PORT; each port has RUNS_SERVICE to a Service.
- **Service**: Linked from Port; USES_TECHNOLOGY links to Technology.
- **Technology**: Linked from Service; HAS_VULNERABILITY links to Vulnerability.
- **Vulnerability**: REFERENCES CVE and MAPS_TO MITRE (CWE) when applicable.
