# The Force Security - Attack Surface Management

<p align="center">
  <img src="frontend/public/logo.svg" alt="The Force Security Logo" width="120" height="120" style="filter: invert(1);">
</p>

<p align="center">
  <strong>A comprehensive Attack Surface Management (ASM) platform for security teams to discover, monitor, and manage their organization's external attack surface.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-aws-deployment">AWS Deployment</a> •
  <a href="#-api-endpoints">API Docs</a>
</p>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Docker Compose                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Frontend   │    │   Backend   │    │  PostgreSQL │    │    Redis    │  │
│  │  (Next.js)  │───▶│  (FastAPI)  │───▶│     DB      │    │   (Cache)   │  │
│  │  Port 80    │    │  Port 8000  │    │  Port 5432  │    │  Port 6379  │  │
│  └─────────────┘    └──────┬──────┘    └─────────────┘    └─────────────┘  │
│                            │                                                │
│         ┌──────────────────┴──────────────────┐                            │
│         │                                      │                            │
│         ▼                                      ▼                            │
│  ┌─────────────────┐              ┌─────────────────────────────┐          │
│  │    Scheduler    │              │   Security Tools Suite      │          │
│  │  (Cron Worker)  │              │  • Nuclei (Vuln Scanner)    │          │
│  │                 │              │  • Subfinder (Subdomains)   │          │
│  └─────────────────┘              │  • HTTPX (HTTP Probing)     │          │
│                                   │  • DNSX (DNS Toolkit)       │          │
│  ┌─────────────────┐              │  • Naabu (Port Scanner)     │          │
│  │    Scanner      │              │  • Masscan (Mass Scanner)   │          │
│  │   (Worker)      │              │  • EyeWitness (Screenshots) │          │
│  │                 │              │  • WaybackURLs (Historical) │          │
│  └─────────────────┘              └─────────────────────────────┘          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### 🖥️ Modern Dashboard
- **Real-time Metrics**: Security overview with vulnerability counts, asset stats, and risk indicators
- **World Map Visualization**: Geographic distribution of assets with geolocation enrichment
- **Remediation Efficiency**: Track MTTR (Mean Time to Remediate) and vulnerability exposure trends
- **Quick Actions**: One-click access to scans, discovery, and enrichment operations

### 📦 Asset Management
- **Comprehensive Asset Inventory**: Track domains, subdomains, IPs, and web applications
- **Asset Risk Scoring (ARS)**: 0-100 risk score based on vulnerabilities and exposure
- **Asset Criticality Score (ACS)**: 0-10 criticality rating with customizable drivers
- **Open Ports & Services**: Detailed port information with service detection
- **Technology Detection**: Identify web technologies, frameworks, and versions
- **Geolocation Enrichment**: Multiple providers (ip-api, ipinfo, WhoisXML)
- **Labeling System**: Organize assets with custom labels for targeted scanning

### 🔍 Discovery & Reconnaissance
- **Subdomain Enumeration**: Automated discovery using multiple sources
- **DNS Enrichment**: A, AAAA, MX, NS, TXT, SOA records via WhoisXML API
- **CIDR/Netblock Discovery**: Find IP ranges by organization name
- **Domain Validation**: Automatic detection of parked, suspicious, or privacy-protected domains
- **Certificate Transparency**: Discover domains via SSL/TLS certificate logs
- **TLDFinder (optional)**: [ProjectDiscovery tldfinder](https://github.com/projectdiscovery/tldfinder) for better TLD/domain coverage; enable `use_tldfinder` in full discovery or run a dedicated **tldfinder** scan. See [docs/MCP_AND_TLDFINDER.md](docs/MCP_AND_TLDFINDER.md).

### 🏢 Inventory Management
Unified inventory page with three tabs:

| Tab | Description |
|-----|-------------|
| **CIDR Blocks** | Manage IP ranges and netblocks with scope controls |
| **Domains** | Domain inventory with validation status and DNS enrichment |
| **M&A** | Track acquisitions and discover domains from acquired companies |

### 🤝 M&A / Acquisitions Tracking
- **Tracxn Integration**: Import acquisition history automatically
- **Domain Discovery**: Find domains associated with acquired companies
- **Integration Status**: Track merger/acquisition integration progress
- **Asset Linking**: Connect discovered assets to their acquisition source

### 🔒 Vulnerability Management
- **Nuclei Scanning**: 8000+ vulnerability templates
- **Severity-based Sorting**: Critical → High → Medium → Low → Info
- **Vulnerability Details**: CVSS scores, remediation guidance, detection timeline
- **Port Scanning**: Masscan + Nmap for comprehensive service discovery
- **Finding Tracking**: First seen, last seen, resurfaced dates

### 📅 Scheduled Scanning
Automated recurring scans with flexible frequencies:

| Frequency | Use Case |
|-----------|----------|
| Every 15 minutes | Critical port monitoring |
| Every 30 minutes | High-priority asset checks |
| Hourly | Active vulnerability detection |
| Daily | Comprehensive security scans |
| Weekly | Full discovery sweeps |

### 📸 Screenshots & Visual Recon
- **EyeWitness Integration**: Automated web application screenshots
- **Gallery View**: Browse screenshots with filtering and search
- **Scheduled Captures**: Automatic periodic screenshots

### 🌐 External Discovery Sources

| Source | Description | API Key |
|--------|-------------|---------|
| **Certificate Transparency (crt.sh)** | SSL/TLS certificate logs | ❌ Free |
| **Wayback Machine** | Historical URLs and subdomains | ❌ Free |
| **RapidDNS** | DNS enumeration | ❌ Free |
| **Microsoft 365** | Federated domain discovery | ❌ Free |
| **Common Crawl** | Web archive subdomain discovery | ❌ Free |
| **AlienVault OTX** | Threat intelligence passive DNS | ✅ Free tier |
| **VirusTotal** | Subdomain database | ✅ Paid |
| **WhoisXML API** | IP ranges, DNS records | ✅ Paid |
| **Whoxy** | Reverse WHOIS by email | ✅ Paid |
| **Tracxn** | M&A/Acquisition data | ✅ Paid |

### 🛡️ Security Tools Integration

| Tool | Purpose | Use Case |
|------|---------|----------|
| **Nuclei** | Vulnerability scanner | CVE detection, misconfiguration |
| **Subfinder** | Subdomain discovery | Passive enumeration |
| **HTTPX** | HTTP probing | Web server detection |
| **DNSX** | DNS toolkit | DNS resolution |
| **Naabu** | Port scanner | Service discovery |
| **Masscan** | Mass port scanner | Large-scale scanning |
| **Katana** | Web crawler | URL discovery |
| **EyeWitness** | Screenshot capture | Visual reconnaissance |
| **WaybackURLs** | Historical URLs | Attack surface history |
| **Amass** | Asset discovery | Advanced enumeration |
| **MassDNS** | DNS resolver | Bulk DNS queries |

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | Next.js 14, TypeScript, Tailwind CSS, shadcn/ui |
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2.0 |
| **Database** | PostgreSQL 15 |
| **Cache** | Redis 7 |
| **Auth** | JWT (python-jose), bcrypt |
| **Container** | Docker, Docker Compose |
| **Cloud** | AWS (EC2, SQS, S3) |

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Git
- 30GB+ disk space (recommended)

### 1. Clone the Repository

```bash
# Create directory and clone
sudo mkdir -p /opt/asm
sudo chown $USER:$USER /opt/asm
git clone https://github.com/javrav2/theforcesecurity_ASM.git /opt/asm
cd /opt/asm
```

### 2. Create Environment File

```bash
cat > .env << 'EOF'
# Database
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=your_secure_password_here
POSTGRES_DB=asm_db

# Security - Generate with: openssl rand -hex 32
SECRET_KEY=your_64_character_secret_key_here

# Ports
BACKEND_PORT=8000
FRONTEND_PORT=80
DB_PORT=5432
REDIS_PORT=6379

# Settings
DEBUG=false
EOF
```

### 3. Build and Start Services

```bash
# Build and start all services
sudo docker compose up -d --build

# Watch the build progress
sudo docker compose logs -f
```

### 4. Create Admin User

```bash
sudo docker exec -it asm_backend python -c "
from app.db.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

db = SessionLocal()
existing = db.query(User).filter(User.email == 'admin@theforce.security').first()
if existing:
    print('Admin already exists')
else:
    admin = User(
        email='admin@theforce.security',
        username='admin',
        hashed_password=get_password_hash('admin123'),
        full_name='Admin User',
        role='admin',
        is_active=True
    )
    db.add(admin)
    db.commit()
    print('Admin user created!')
db.close()
"
```

### 5. Access the Application

| Service | URL |
|---------|-----|
| **Frontend Dashboard** | `http://localhost` |
| **Backend API** | `http://localhost:8000` |
| **API Documentation** | `http://localhost:8000/api/docs` |
| **MCP (tools for agent)** | `GET/POST /api/v1/mcp/tools`, `/api/v1/mcp/call` — see [MCP & TLDFinder](docs/MCP_AND_TLDFINDER.md) |

**Default Login:**
- Username: `admin`
- Password: `admin123`

⚠️ **Change the default password immediately!**

## ⚙️ Configuring API Keys

Configure external service API keys in **Settings**:

1. Navigate to **Settings** in the sidebar
2. Select your organization
3. Configure API keys:

| Service | Purpose | Get Key |
|---------|---------|---------|
| **VirusTotal** | Subdomain discovery | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **WhoisXML API** | IP ranges, DNS enrichment | [whoisxmlapi.com](https://whoisxmlapi.com/) |
| **AlienVault OTX** | Threat intelligence | [otx.alienvault.com](https://otx.alienvault.com/api) |
| **Whoxy** | Reverse WHOIS | [whoxy.com](https://www.whoxy.com/) |
| **Tracxn** | M&A data | [platform.tracxn.com](https://platform.tracxn.com/) |

4. For **WhoisXML**: Add organization names to discover IP ranges
5. For **Whoxy**: Add registration emails to discover domains

## ☁️ AWS Deployment

### Quick Deploy with CloudFormation

```bash
# Deploy the stack
aws cloudformation create-stack \
  --stack-name asm-platform \
  --template-body file://aws/ec2-single/cloudformation.yml \
  --parameters \
    ParameterKey=KeyName,ParameterValue=your-key-pair \
    ParameterKey=InstanceType,ParameterValue=t3.large \
    ParameterKey=AllowedSSHCIDR,ParameterValue=YOUR_IP/32 \
  --capabilities CAPABILITY_IAM

# Wait for completion (~10 minutes)
aws cloudformation wait stack-create-complete --stack-name asm-platform

# Get outputs
aws cloudformation describe-stacks --stack-name asm-platform \
  --query 'Stacks[0].Outputs' --output table

# SSH and complete setup
ssh -i your-key.pem ubuntu@<PUBLIC_IP>
cd /opt/asm
git clone https://github.com/javrav2/theforcesecurity_ASM.git .
./aws/ec2-single/setup.sh
```

### Manual AWS Setup (Existing EC2)

```bash
# SSH into your EC2 instance
ssh -i your-key.pem ubuntu@YOUR_EC2_IP

# Create and setup directory
sudo mkdir -p /opt/asm
sudo chown $USER:$USER /opt/asm
cd /opt/asm

# Clone repository
git clone https://github.com/javrav2/theforcesecurity_ASM.git .

# Create .env file (update PUBLIC_IP with your EC2 IP)
PUBLIC_IP=$(curl -s ifconfig.me)
cat > .env << EOF
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
POSTGRES_DB=asm_db
SECRET_KEY=$(openssl rand -hex 32)
BACKEND_PORT=8000
FRONTEND_PORT=80
DEBUG=false
NEXT_PUBLIC_API_URL=http://${PUBLIC_IP}:8000
CORS_ORIGINS=["http://localhost","http://${PUBLIC_IP}","http://${PUBLIC_IP}:80"]
SQS_QUEUE_URL=
AWS_REGION=us-east-1
EOF

# Build and start
sudo docker compose up -d --build

# Check status
sudo docker compose ps
```

### Updating Code on AWS (push your changes)

**1. Push code to your Git remote** (so the EC2 or CI can pull it):

```bash
git add -A
git commit -m "Your message"
git push origin main   # or your branch, e.g. origin master
```

If you use **AWS CodeCommit** instead of GitHub:

```bash
# One-time: add CodeCommit as remote (replace with your repo URL)
git remote add aws https://git-codecommit.us-east-1.amazonaws.com/v1/repos/your-repo-name
# Push
git push aws main
```

**2. On the EC2 instance** (single-instance / Docker Compose):

```bash
ssh -i your-key.pem ubuntu@YOUR_EC2_IP
cd /opt/asm
git pull
sudo docker compose up -d --build --force-recreate
```

**Alternative: ECR + ECS**  
If you deploy with ECS and the `aws/scripts/deploy.sh` script, from your **local machine** (after pushing code to Git):

```bash
cd /path/to/theforcesecurity_ASM/aws/scripts
./deploy.sh all prod   # builds images, pushes to ECR, updates ECS services
```

Requires ECR repositories and ECS cluster (`asm-cluster`, etc.) already set up.

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed AWS deployment instructions.

## 📁 Project Structure

```
theforcesecurity_ASM/
├── frontend/                    # Next.js Frontend
│   ├── src/
│   │   ├── app/                # Pages (dashboard, assets, inventory, etc.)
│   │   ├── components/         # UI components
│   │   ├── lib/               # API client, utilities
│   │   └── store/             # State management
│   ├── public/                # Static assets, logo
│   ├── Dockerfile
│   └── package.json
│
├── backend/                    # FastAPI Backend
│   ├── app/
│   │   ├── api/routes/        # API endpoints (22 route modules)
│   │   ├── models/            # Database models (16 models)
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Business logic (33 services)
│   │   └── workers/           # Background workers (scanner, scheduler)
│   ├── scripts/               # Database migrations
│   ├── Dockerfile             # Includes security tools
│   └── requirements.txt
│
├── db/init/                   # Database initialization
├── aws/                       # AWS deployment configs
│   ├── cloudformation/        # CloudFormation templates
│   ├── terraform/            # Terraform IaC
│   ├── ec2-single/           # Single EC2 setup
│   └── commoncrawl/          # S3 index setup
│
├── docker-compose.yml         # Container orchestration
├── DEPLOYMENT.md             # AWS deployment guide
├── Makefile                  # Development commands
└── README.md
```

## 📊 API Endpoints

All endpoints are prefixed with `/api/v1/`

### Core APIs

| Category | Endpoints | Description |
|----------|-----------|-------------|
| **Auth** | `/auth/login`, `/auth/me`, `/auth/logout` | Authentication |
| **Organizations** | `/organizations/` | Multi-tenant management |
| **Assets** | `/assets/`, `/assets/{id}`, `/assets/enrich-geolocation` | Asset CRUD + enrichment |
| **Vulnerabilities** | `/vulnerabilities/`, `/vulnerabilities/stats/*` | Findings + analytics |
| **Scans** | `/scans/`, `/scans/by-label` | Scan management |
| **Schedules** | `/scan-schedules/` | Automated scanning |

### Discovery APIs

| Endpoint | Description |
|----------|-------------|
| `/discovery/run` | Subdomain discovery |
| `/external-discovery/run` | External source discovery |
| `/external-discovery/enrich-dns` | DNS record enrichment |
| `/external-discovery/validate-domains` | Domain validation |
| `/netblocks/discover` | CIDR discovery by org name |

### Inventory APIs

| Endpoint | Description |
|----------|-------------|
| `/netblocks/` | CIDR block management |
| `/acquisitions/` | M&A tracking |
| `/acquisitions/import-from-tracxn` | Tracxn import |
| `/acquisitions/{id}/discover-domains` | Domain discovery for M&A |

### Other APIs

| Endpoint | Description |
|----------|-------------|
| `/screenshots/` | Screenshot management |
| `/ports/` | Port scan results |
| `/waybackurls/` | Historical URL fetching |
| `/labels/` | Asset labeling |
| `/tools/status` | Security tool status |

Full API documentation available at `/api/docs`

## 🔧 Useful Commands

All commands should be run from the application directory (`/opt/asm` on AWS):

```bash
# Navigate to app directory (AWS)
cd /opt/asm

# View logs
sudo docker compose logs -f
sudo docker compose logs -f backend

# Restart services
sudo docker compose restart

# Rebuild and restart (after code changes)
git pull && sudo docker compose up -d --build --force-recreate

# Access backend shell
sudo docker exec -it asm_backend bash

# Access database
sudo docker exec -it asm_database psql -U asm_user -d asm_db

# Update Nuclei templates
sudo docker exec asm_scanner nuclei -update-templates

# Clean up
sudo docker compose down -v
sudo docker system prune -a -f
```

## 🔒 Security Considerations

1. **Change default passwords** immediately after deployment
2. **Generate a secure SECRET_KEY**: `openssl rand -hex 32`
3. **Use HTTPS** in production (configure reverse proxy with SSL)
4. **Restrict CORS origins** to your frontend domain
5. **Enable DEBUG=false** in production
6. **Keep Nuclei templates updated** regularly
7. **Restrict security groups** to necessary IPs only
8. **Regular backups** of PostgreSQL data

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for Nuclei and security tools
- [tomnomnom](https://github.com/tomnomnom/waybackurls) for waybackurls
- [RedSiege](https://github.com/RedSiege) for EyeWitness
- [shadcn/ui](https://ui.shadcn.com/) for React components
- [crt.sh](https://crt.sh) for certificate transparency data
- [WhoisXML API](https://whoisxmlapi.com/) for DNS and WHOIS data
- [Tracxn](https://tracxn.com/) for M&A intelligence

---

<p align="center">
  <strong>Made with ❤️ by The Force Security</strong>
</p>
