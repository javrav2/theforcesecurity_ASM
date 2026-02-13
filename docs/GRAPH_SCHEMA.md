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
