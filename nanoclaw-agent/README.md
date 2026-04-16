# Aegis Vanguard — ASM Scanner Agent

An AI-powered Attack Surface Management agent that runs inside a
[NanoClaw](https://github.com/qwibitai/nanoclaw)-style container (folder still
named `nanoclaw-agent/` for backward compatibility) and reports findings back
to The Force Security ASM platform.

## Architecture

```
┌─────────────────────────────────────┐     ┌──────────────────────────────────┐
│       NanoClaw Container            │     │     ASM Platform                 │
│                                     │     │                                  │
│  Claude Agent (via NanoClaw)        │     │  POST /api/v1/ingest/findings    │
│       │                             │     │       │                          │
│       ▼                             │     │       ▼                          │
│  scanners.py                        │────▶│  Ingestion Service               │
│  (subfinder, naabu, nuclei, etc.)   │     │       │                          │
│       │                             │     │       ▼                          │
│       ▼                             │     │  Assets, Vulns, Ports → Postgres │
│  asm_bridge.py (API client)         │     │       │                          │
│                                     │     │       ▼                          │
│  CLAUDE.md (agent instructions)     │     │  Dashboard (Next.js)             │
└─────────────────────────────────────┘     └──────────────────────────────────┘
```

## Setup

### Phase 1: Standalone Testing (without NanoClaw)

Test the agent components independently before integrating with NanoClaw.

#### 1. Build the scanner container

```bash
cd nanoclaw-agent
docker build -t asm-scanner .
```

#### 2. Generate an API key on your ASM platform

Log into your ASM platform and create an agent API key:

```bash
# Via API (requires admin JWT token)
curl -X POST http://your-asm-platform:8000/api/v1/ingest/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "aegis-vanguard-01", "agent_type": "aegis_vanguard"}'

# Save the returned api_key (starts with tfasm_) - it's only shown once
```

#### 3. Run standalone tests

```bash
# Dry-run test (no API connection needed)
docker run --rm asm-scanner python3 asm_bridge.py test

# Test against your platform
docker run --rm \
  -e ASM_API_URL=http://your-asm-platform:8000 \
  -e ASM_API_KEY=tfasm_YOUR_KEY_HERE \
  -e ASM_AGENT_ID=test-scanner-01 \
  asm-scanner python3 asm_bridge.py test

# Run a real subdomain scan
docker run --rm \
  -e ASM_API_URL=http://your-asm-platform:8000 \
  -e ASM_API_KEY=tfasm_YOUR_KEY_HERE \
  asm-scanner python3 -c "
from asm_bridge import ASMBridge
from scanners import run_subfinder
bridge = ASMBridge()
subs = run_subfinder('example.com', bridge)
print(f'Found {len(subs)} subdomains')
print(bridge.stats)
"
```

### Phase 2: NanoClaw Integration

#### 1. Fork and clone NanoClaw

```bash
gh repo fork qwibitai/nanoclaw --clone
cd nanoclaw
```

#### 2. Set up NanoClaw

```bash
claude  # Start Claude Code
# Then type: /setup
```

#### 3. Create an ASM scanner group

Copy the agent files into a NanoClaw group:

```bash
mkdir -p groups/asm-scanner
cp /path/to/nanoclaw-agent/CLAUDE.md groups/asm-scanner/CLAUDE.md
cp /path/to/nanoclaw-agent/asm_bridge.py groups/asm-scanner/
cp /path/to/nanoclaw-agent/scanners.py groups/asm-scanner/
```

#### 4. Configure the agent environment

Add to your NanoClaw `.env`:

```env
ASM_API_URL=https://your-asm-platform.com
ASM_API_KEY=tfasm_YOUR_KEY_HERE
ASM_AGENT_ID=aegis-vanguard-prod-01
```

#### 5. Mount scanning tools in the container

Update your NanoClaw container configuration to include ProjectDiscovery tools.
You can either:
- Use the provided Dockerfile to build a custom container image
- Install tools via the NanoClaw setup process

#### 6. Talk to your agent

```
@Andy scan example.com for subdomains and open ports
@Andy run a full recon on example.com and report back
@Andy check example.com for critical vulnerabilities
```

### Phase 3: Enterprise Ready

For production deployments:

#### API Key Rotation
- Create API keys with expiration dates
- Rotate keys periodically via the admin API
- Monitor key usage via `GET /api/v1/ingest/api-keys`

#### Multiple Agents
Deploy multiple scanner agents with different scopes:
```
aegis-vanguard-01: Subdomain enumeration + DNS
aegis-vanguard-02: Port scanning
aegis-vanguard-03: Vulnerability scanning
```

#### Monitoring
- Use the heartbeat endpoint for health checks
- Monitor `usage_count` and `last_used_at` on API keys
- Check ingestion batch responses for error rates

#### Network Security
- Run NanoClaw containers in an isolated network
- Only allow outbound traffic to scan targets and the ASM platform
- Use TLS for all API communication

## Files

| File | Purpose |
|------|---------|
| `asm_bridge.py` | Python client for the ASM platform ingestion API |
| `scanners.py` | Wrappers around security scanning tools |
| `CLAUDE.md` | Instructions for the NanoClaw Claude agent |
| `Dockerfile` | Container image with all scanning tools pre-installed |

## API Endpoints Used

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| `POST` | `/api/v1/ingest/findings` | API Key | Submit findings batch |
| `POST` | `/api/v1/ingest/heartbeat` | API Key | Agent health check |
| `POST` | `/api/v1/ingest/api-keys` | JWT | Create agent API key |
| `GET` | `/api/v1/ingest/api-keys` | JWT | List API keys |
| `DELETE` | `/api/v1/ingest/api-keys/{id}` | JWT | Revoke API key |
