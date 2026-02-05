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
# The agent will auto-detect based on which API key is set
AI_PROVIDER=openai

# OpenAI Configuration
# Get API key at: https://platform.openai.com/api-keys
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o

# Anthropic/Claude Configuration (alternative to OpenAI)
# Get API key at: https://console.anthropic.com/
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-20250514

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
