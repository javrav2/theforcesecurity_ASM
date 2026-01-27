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
