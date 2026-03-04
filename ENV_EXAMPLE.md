# Environment Configuration

Copy this to `.env` in your project root:

```bash
# =============================================================================
# ASM Platform - Environment Configuration
# =============================================================================

# Database
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=CHANGE_ME_TO_A_SECURE_PASSWORD
POSTGRES_DB=asm_db
DB_PORT=5432

# Backend
BACKEND_PORT=8000
SECRET_KEY=GENERATE_WITH_openssl_rand_hex_32
DEBUG=false

# Frontend
# For AWS: Set to your public IP, e.g., http://1.2.3.4:8000
NEXT_PUBLIC_API_URL=http://YOUR_PUBLIC_IP:8000
FRONTEND_PORT=80

# CORS Origins - IMPORTANT: Include your public IP!
CORS_ORIGINS=["http://localhost","http://YOUR_PUBLIC_IP","http://YOUR_PUBLIC_IP:8000"]

# Redis
REDIS_PORT=6379

# AWS Configuration (optional)
AWS_REGION=us-east-1
SQS_QUEUE_URL=

# ProjectDiscovery Cloud (optional - for Chaos subdomain dataset)
# Get API key at: https://cloud.projectdiscovery.io
PDCP_API_KEY=

# =============================================================================
# AI Agent Configuration (optional)
# =============================================================================

# AI Provider: "openai" or "anthropic" (default: openai)
# The agent will auto-detect based on which API key is set.
# These keys also enable Katana AI secrets scan (set ai_secrets_scan: true in Katana scan config).
AI_PROVIDER=openai

# OpenAI Configuration
# Get API key at: https://platform.openai.com/api-keys
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o

# Anthropic/Claude Configuration (use API key from Console, NOT Cursor/Claude Code)
# Get key at: https://console.anthropic.com/ → API Keys (must start with sk-ant-)
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-20250514

# Optional: Tavily API for agent web search (CVE/exploit research, RedAmon-style)
# Get key at: https://tavily.com (free tier available)
# TAVILY_API_KEY=

# Agent LLM max output tokens (default 4096; increase for long answers, e.g. 8192, 16384, 64000)
# AGENT_MAX_OUTPUT_TOKENS=4096

# Agent tool output truncation (chars passed to LLM; default 20000)
# AGENT_TOOL_OUTPUT_MAX_CHARS=20000

# =============================================================================
# Neo4j Graph Database (optional - for asset relationship modeling)
# =============================================================================

# Enable with: docker compose --profile graph up -d
NEO4J_USER=neo4j
NEO4J_PASSWORD=neo4j_password
NEO4J_HTTP_PORT=7474
NEO4J_BOLT_PORT=7687

# =============================================================================
# GitHub Secret Scanning (optional)
# =============================================================================

# GitHub Personal Access Token for secret scanning
# Create at: https://github.com/settings/tokens
GITHUB_TOKEN=

```

## Production example (HTTPS + single domain)

For a deployment like `https://asm.theforcesecurity.io`:

```bash
# Database
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=CHANGE_ME_SECURE_PASSWORD
POSTGRES_DB=asm_db

# Security - generate: openssl rand -hex 32
SECRET_KEY=your-generated-secret-key

# Frontend / API (use your real domain)
NEXT_PUBLIC_API_URL=https://asm.theforcesecurity.io
CORS_ORIGINS=["https://asm.theforcesecurity.io"]

# Ports
BACKEND_PORT=8000
FRONTEND_PORT=80

# AWS (one entry each)
SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT_ID/asm-scan-jobs
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_iam_access_key
AWS_SECRET_ACCESS_KEY=your_iam_secret_key

# ProjectDiscovery Cloud (one entry)
PDCP_API_KEY=your-pdcp-key

# AI Agent
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-api03-your-key-from-console-anthropic

# Neo4j (if using graph)
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password
```

- No duplicate variables (e.g. only one `SQS_QUEUE_URL`, one `PDCP_API_KEY`).
- `CORS_ORIGINS` must be valid JSON (one string or list of strings).
- After editing `.env`, run `docker compose restart backend` (or `sudo docker compose restart backend` on the server).

---

## Quick Setup

Use the auto-configure script instead:

```bash
chmod +x scripts/quick-deploy.sh
./scripts/quick-deploy.sh
```

This automatically:
- Detects your public IP
- Generates secure passwords
- Configures CORS
- Builds and starts all services

---

## Troubleshooting: 401 invalid x-api-key (Anthropic/Claude)

If the AI agent returns **Error code: 401 - invalid x-api-key**:

1. **Use the correct key**  
   The app needs an **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com) → **API Keys** (create/copy there).  
   Do **not** use a key from Cursor, “Claude for Code,” or other products — those are not valid for the Claude API.

2. **Check key format**  
   The key must start with `sk-ant-` (e.g. `sk-ant-api03-...`). If it doesn’t, you’re likely using the wrong type of key.

3. **Fix .env**  
   In the project root `.env` (same folder as `docker-compose.yml`):
   - Use one line: `ANTHROPIC_API_KEY=sk-ant-api03-your-key-here`
   - No space after `=`, no extra quotes unless the key contains spaces
   - No leading/trailing spaces or line breaks in the key

4. **Restart backend**  
   After changing `.env`: `docker compose restart backend` (or on AWS: `sudo docker compose restart backend`).

5. **Create a new key**  
   In [Anthropic Console](https://console.anthropic.com) → API Keys, create a new key and replace the value in `.env` in case the previous one was revoked or incorrect.

---

## Troubleshooting: Agent not running when key is configured

If you set `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) but the Agent page still shows "Agent is not available":

1. **Restart the backend after adding the key**  
   The backend reads env vars only at startup. After editing `.env`, run:
   ```bash
   docker compose up -d backend
   ```
   On AWS (EC2): `cd /opt/asm` then the same command with `sudo` if needed.

2. **Use the correct `.env` and variable name**  
   - The `.env` file must be in the **same directory as `docker-compose.yml`** (e.g. project root or `/opt/asm` on the server).
   - Variable must be exactly: `ANTHROPIC_API_KEY=sk-ant-api03-...` (no space around `=`; no typo like `ANTHROPIC_KEY`).

3. **Use an Anthropic API key, not Cursor/Claude Code**  
   Get the key from [Anthropic Console → API Keys](https://console.anthropic.com). Keys from Cursor or "Claude Code" are not valid for this API. Valid keys start with `sk-ant-`.

4. **Confirm the key is in the container**  
   On the server:
   ```bash
   sudo docker exec asm_backend env | grep ANTHROPIC
   ```
   You should see `ANTHROPIC_API_KEY=sk-ant-...` (the value is shown). If it’s missing or empty, fix `.env` and restart the backend.

5. **Check the Agent page message**  
   After the latest frontend/backend updates, the Agent page shows a hint when the agent is unavailable (e.g. "Set ANTHROPIC_API_KEY in .env and restart the backend") or the error from the status request (e.g. network or auth). Use that to narrow down the issue.

---

## Troubleshooting: 504 Gateway Timeout (Agent)

If the agent shows **Request failed with status code 504**:

- **Cause:** A reverse proxy (nginx, ALB, Cloudflare, etc.) in front of the backend stopped waiting for the response. Agent requests can take a long time (LLM calls plus tool runs). Many proxies default to 60 seconds.
- **What to do:** Increase the proxy’s timeout for the API (or at least for agent paths).

  **Nginx** (in the `location` that proxies to the backend):
  ```nginx
  proxy_connect_timeout 300s;
  proxy_send_timeout 300s;
  proxy_read_timeout 300s;
  ```
  Use 300–600 seconds for the agent; you can use a longer timeout only for `/api/v1/agent/` if you prefer.

  **AWS Application Load Balancer:**  
  ALB idle timeout defaults to 60 seconds. Increase it (e.g. to 300 seconds):
  - Console: EC2 → Load Balancers → your ALB → Attributes → Idle timeout.
  - CLI: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn <ARN> --attributes Key=idle_timeout.timeout_seconds,Value=300`

  **Cloudflare / other CDN:**  
  Increase the proxy timeout in the dashboard (e.g. 300s) or use a “stream”/passthrough so the CDN doesn’t time out long requests.

  After changing the proxy, reload nginx or wait for ALB changes to apply, then try the agent again.

---

## Troubleshooting: 529 / Overloaded (Agent)

If the agent shows **Error code: 529** or **overloaded_error / "Overloaded"**:

- **Cause:** Anthropic’s API is temporarily overloaded and is rejecting requests.
- **What to do:** Wait a few minutes and try again. The app now shows a friendly message: *"The AI provider (Anthropic/Claude) is temporarily overloaded. Please try again in a few minutes."*
- **Optional:** You can switch to OpenAI by setting `AI_PROVIDER=openai` and `OPENAI_API_KEY` in `.env` so the agent uses GPT instead when Claude is overloaded.
