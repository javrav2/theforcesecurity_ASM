# The Force Security - Attack Surface Management

<p align="center">
  <img src="frontend/public/logo.svg" alt="The Force Security Logo" width="120" height="120" style="filter: invert(1);">
</p>

<p align="center">
  <strong>A comprehensive Attack Surface Management (ASM) platform for security teams to discover, monitor, and manage their organization's external attack surface.</strong>
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
│  │  Port 3000  │    │  Port 8000  │    │  Port 5432  │    │  Port 6379  │  │
│  └─────────────┘    └──────┬──────┘    └─────────────┘    └─────────────┘  │
│                            │                                                │
│                            ▼                                                │
│              ┌─────────────────────────────┐                               │
│              │   Security Tools Suite      │                               │
│              │  • Nuclei (Vuln Scanner)    │                               │
│              │  • Subfinder (Subdomains)   │                               │
│              │  • HTTPX (HTTP Probing)     │                               │
│              │  • DNSX (DNS Toolkit)       │                               │
│              │  • Naabu (Port Scanner)     │                               │
│              │  • Katana (Web Crawler)     │                               │
│              │  • Masscan (Mass Scanner)   │                               │
│              │  • EyeWitness (Screenshots) │                               │
│              │  • WaybackURLs (Historical) │                               │
│              └─────────────────────────────┘                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### Frontend Dashboard
- **Modern React UI**: Built with Next.js 14, TypeScript, and Tailwind CSS
- **Real-time Dashboard**: Security metrics, vulnerability breakdown, quick actions
- **Organization Management**: Create and manage multiple organizations
- **Asset Explorer**: Searchable, filterable asset tables with CSV export
- **Vulnerability Viewer**: Severity-based filtering with detailed findings
- **Screenshot Gallery**: Visual snapshots of discovered web assets
- **Scan Management**: Create, monitor, and manage security scans
- **Port Scanner Results**: View open ports and services across assets
- **Wayback URLs**: Historical URL discovery with interesting pattern detection

### Backend Capabilities
- **Multi-tenant Architecture**: Support for multiple organizations with RBAC
- **Asset Discovery**: Track domains, subdomains, IPs, URLs, and more
- **Vulnerability Tracking**: Record, prioritize, and manage security findings
- **JWT Authentication**: Secure API with access tokens
- **Role-Based Access**: Admin, Analyst, and Viewer roles

### External Discovery (ASM Recon)
Automated discovery from multiple intelligence sources:

| Source | Description | API Key Required |
|--------|-------------|------------------|
| **Certificate Transparency (crt.sh)** | SSL/TLS certificate logs | ❌ Free |
| **Wayback Machine** | Historical URLs and subdomains | ❌ Free |
| **RapidDNS** | DNS enumeration | ❌ Free |
| **Microsoft 365** | Federated domain discovery | ❌ Free |
| **Common Crawl** | Web archive subdomain discovery | ❌ Free (S3 optional) |
| **AlienVault OTX** | Threat intelligence passive DNS | ✅ Free tier |
| **VirusTotal** | Subdomain database | ✅ Paid |
| **WhoisXML API** | IP ranges by organization name | ✅ Paid |
| **Whoxy** | Reverse WHOIS by registration email | ✅ Paid |

### Wayback URLs Feature
Fetch historical URLs from the [Wayback Machine](https://web.archive.org) using [waybackurls](https://github.com/tomnomnom/waybackurls):
- Discover old/forgotten endpoints
- Find API endpoints with parameters
- Detect backup files, configs, and sensitive data
- Automatic detection of interesting patterns (admin, api, .env, .sql, etc.)
- File extension analysis
- Export results to JSON

### Security Tools Integration
| Tool | Description | Use Case |
|------|-------------|----------|
| **Nuclei** | Vulnerability scanner | CVE detection, misconfiguration |
| **Subfinder** | Subdomain discovery | Passive enumeration |
| **HTTPX** | HTTP probing toolkit | Web server detection |
| **DNSX** | DNS toolkit | DNS resolution |
| **Naabu** | Port scanner | Service discovery |
| **Katana** | Web crawler | URL discovery |
| **Masscan** | Mass port scanner | Large-scale scanning |
| **EyeWitness** | Screenshot capture | Visual reconnaissance |
| **WaybackURLs** | Historical URL fetcher | Attack surface history |

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | Next.js 14, TypeScript, Tailwind CSS, shadcn/ui |
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2.0 |
| **Database** | PostgreSQL 15 |
| **Cache** | Redis 7 |
| **Auth** | JWT (python-jose), bcrypt |
| **Container** | Docker, Docker Compose |

## 🚀 Quick Start (Docker Compose)

### Prerequisites
- Docker and Docker Compose installed
- Git
- 30GB+ disk space (recommended)

### 1. Clone the Repository

```bash
git clone https://github.com/javrav2/theforcesecurity_ASM.git ~/asm
cd ~/asm
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
FRONTEND_PORT=3000
DB_PORT=5432
REDIS_PORT=6379

# Settings
DEBUG=false
EOF
```

Generate a secure secret key:
```bash
openssl rand -hex 32
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
        username='admin',  # username is required for JWT subject
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
| **Frontend Dashboard** | `http://localhost:3000` |
| **Backend API** | `http://localhost:8000` |
| **API Documentation** | `http://localhost:8000/api/docs` |

**Default Login:**
- Email: `admin@theforce.security`
- Password: `admin123`

⚠️ **Change the default password immediately!**

## ⚙️ Configuring API Keys

To enable paid discovery sources, configure API keys in the **Settings** page:

1. Navigate to **Settings** in the sidebar
2. Select your organization
3. Enter API keys for:
   - **VirusTotal** - Get key at [virustotal.com](https://www.virustotal.com/gui/join-us)
   - **WhoisXML API** - Get key at [whoisxmlapi.com](https://whoisxmlapi.com/)
   - **AlienVault OTX** - Get key at [otx.alienvault.com](https://otx.alienvault.com/api) (free)
   - **Whoxy** - Get key at [whoxy.com](https://www.whoxy.com/)

4. For **WhoisXML**: Add organization names (e.g., "Rockwell Automation") to discover IP ranges
5. For **Whoxy**: Add registration emails to discover domains

## ☁️ AWS Deployment

### Quick Deploy with CloudFormation

The fastest way to deploy on AWS with full SQS support for async scan processing:

```bash
# Deploy the stack (creates EC2, SQS, VPC, IAM roles)
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

# Get the public IP and SQS URL
aws cloudformation describe-stacks --stack-name asm-platform \
  --query 'Stacks[0].Outputs' --output table

# SSH and complete setup
ssh -i your-key.pem ubuntu@<PUBLIC_IP>
cd /opt/asm
git clone https://github.com/javrav2/theforcesecurity_ASM.git .
./aws/ec2-single/setup.sh
```

### What CloudFormation Creates

| Resource | Description |
|----------|-------------|
| EC2 Instance | Ubuntu 22.04 with Docker |
| SQS Queue | For async scan job processing |
| IAM Role | EC2 permissions for SQS |
| VPC + Subnet | Isolated network |
| Security Group | Ports 22, 80, 443 |
| Elastic IP | Static public IP |

### Manual EC2 Deployment

1. **Launch EC2 Instance**
   - AMI: Ubuntu 22.04 LTS
   - Instance Type: t3.large (2 vCPU, 8GB RAM)
   - Storage: 50GB gp3
   - Security Group: Allow ports 22, 80, 443

2. **Install Docker**
   ```bash
   curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker $USER
   # Log out and back in
   ```

3. **Clone and Deploy**
   ```bash
   git clone https://github.com/javrav2/theforcesecurity_ASM.git /opt/asm
   cd /opt/asm
   ./aws/ec2-single/setup.sh
   ```

### SQS Configuration (Recommended for Production)

For reliable async scan processing, configure AWS SQS:

1. **Create SQS Queue**
   ```bash
   aws sqs create-queue \
     --queue-name asm-scan-jobs \
     --attributes VisibilityTimeout=3600
   ```

2. **Add to Environment**
   ```bash
   # Add to /opt/asm/.env
   SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT/asm-scan-jobs
   AWS_REGION=us-east-1
   ```

3. **Restart Services**
   ```bash
   docker compose down && docker compose up -d
   ```

### Scan Processing Modes

| Mode | When Used | How It Works |
|------|-----------|--------------|
| **SQS Mode** | `SQS_QUEUE_URL` is set | Scanner polls SQS for jobs |
| **Database Mode** | `SQS_QUEUE_URL` not set | Scanner polls DB for pending scans |

Both modes work - SQS is recommended for production reliability.

### Common Crawl S3 Index (Fast Subdomain Lookups)

For faster subdomain discovery, set up an S3-backed Common Crawl index:

```
┌─────────────────┐     Monthly      ┌──────────────────┐
│  Common Crawl   │ ───────────────► │    S3 Bucket     │
│   Index API     │   update-index   │  domains.txt.gz  │
└─────────────────┘                  └────────┬─────────┘
                                              │
                                              │ sync_from_s3()
                                              ▼
                                     ┌──────────────────┐
                                     │  ASM Backend     │
                                     │  Local Cache     │
                                     │  ~100ms lookups  │
                                     └──────────────────┘
```

**1. Create S3 Bucket**
```bash
cd /opt/asm/aws/commoncrawl
chmod +x setup-s3.sh
./setup-s3.sh asm-commoncrawl-yourorg us-east-1
```

**2. Build Initial Index** (takes 10-30 minutes)
```bash
pip install boto3 httpx
python update-index.py --bucket asm-commoncrawl-yourorg
```

**3. Configure Environment**
```bash
# Add to /opt/asm/.env
CC_S3_BUCKET=asm-commoncrawl-yourorg
```

**4. Schedule Monthly Updates**
```bash
# Add to crontab
0 0 1 * * cd /opt/asm/aws/commoncrawl && python update-index.py >> /var/log/cc-update.log 2>&1
```

**5. Restart Services**
```bash
docker compose down && docker compose up -d
```

**Benefits:**
- **Speed**: ~100ms lookups vs 30-60s API queries
- **Historical data**: Find forgotten/legacy subdomains
- **Offline capable**: Works even if Common Crawl API is down
- **Example**: Query `rockwellautomation.com` → finds all subdomains from web crawl history

See [aws/commoncrawl/README.md](aws/commoncrawl/README.md) for detailed setup instructions.

### Access Your Deployment

| Service | URL |
|---------|-----|
| Frontend | `http://YOUR_IP` |
| API | `http://YOUR_IP:8000` |
| API Docs | `http://YOUR_IP:8000/api/docs` |

See [aws/ec2-single/README.md](aws/ec2-single/README.md) for detailed AWS deployment instructions.

## 📁 Project Structure

```
theforcesecurity_ASM/
├── frontend/                    # Next.js Frontend
│   ├── src/
│   │   ├── app/                # Pages (dashboard, assets, discovery, wayback, etc.)
│   │   ├── components/         # UI components
│   │   ├── lib/               # API client, utilities
│   │   └── store/             # State management
│   ├── public/                # Static assets, logo
│   ├── Dockerfile
│   └── package.json
│
├── backend/                    # FastAPI Backend
│   ├── app/
│   │   ├── api/routes/        # API endpoints
│   │   ├── models/            # Database models
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Business logic (discovery, waybackurls, etc.)
│   │   └── workers/           # Background workers
│   ├── Dockerfile             # Includes security tools
│   └── requirements.txt
│
├── db/init/                   # Database initialization
├── aws/                       # AWS deployment configs
│   ├── terraform/            # Terraform IaC
│   └── ec2-single/           # Single EC2 setup
│
├── docker-compose.yml         # Container orchestration
├── Makefile                  # Development commands
└── README.md
```

## 🔧 Useful Commands

```bash
# View logs
sudo docker compose logs -f
sudo docker compose logs -f backend
sudo docker compose logs -f frontend

# Restart services
sudo docker compose restart

# Stop all services
sudo docker compose down

# Rebuild and restart
sudo docker compose up -d --build

# Access backend shell
sudo docker exec -it asm_backend bash

# Access database
sudo docker exec -it asm_database psql -U asm_user -d asm_db

# Check container status
sudo docker ps

# Clean up (removes volumes)
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

## 📊 API Endpoints

All endpoints are prefixed with `/api/v1/`

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login and get token |
| GET | `/api/v1/auth/me` | Get current user |
| POST | `/api/v1/auth/logout` | Logout |

### Organizations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/organizations/` | List organizations |
| POST | `/api/v1/organizations/` | Create organization |
| GET | `/api/v1/organizations/{id}` | Get organization |
| DELETE | `/api/v1/organizations/{id}` | Delete organization |

### Assets
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/assets/` | List assets |
| GET | `/api/v1/assets/{id}` | Get asset details |
| POST | `/api/v1/assets/enrich-geolocation` | Enrich with geo data |

### Findings (Vulnerabilities)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/vulnerabilities/` | List findings |
| GET | `/api/v1/vulnerabilities/stats/summary` | Get summary stats |
| POST | `/api/v1/vulnerabilities/` | Create finding |

### Scans
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/scans/` | List scans |
| POST | `/api/v1/scans/` | Create new scan |
| POST | `/api/v1/scans/by-label` | Create scan by asset labels |

### Discovery
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/discovery/run` | Run subdomain discovery |
| POST | `/api/v1/external-discovery/run` | External discovery (CT, Wayback, Whoxy) |
| GET | `/api/v1/external-discovery/services` | List available sources |

### Screenshots
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/screenshots/` | List screenshots |
| GET | `/api/v1/screenshots/image/{id}` | Get screenshot image |
| POST | `/api/v1/screenshots/capture/asset/{id}` | Capture screenshot |

### Netblocks / CIDR
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/netblocks/` | List netblocks |
| POST | `/api/v1/netblocks/discover` | Discover netblocks by org name |
| GET | `/api/v1/netblocks/summary` | Get netblock summary |

### Wayback URLs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/waybackurls/status` | Check tool status |
| POST | `/api/v1/waybackurls/fetch` | Fetch URLs for single domain |
| POST | `/api/v1/waybackurls/fetch/organization` | Fetch URLs for all org assets |

Full API documentation available at `/api/docs`

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for Nuclei and security tools
- [tomnomnom](https://github.com/tomnomnom/waybackurls) for waybackurls
- [RedSiege](https://github.com/RedSiege) for EyeWitness
- [shadcn/ui](https://ui.shadcn.com/) for React components
- [crt.sh](https://crt.sh) for certificate transparency data
- ASM Recon methodology for discovery script design
