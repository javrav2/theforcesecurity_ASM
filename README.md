# The Force Security - Attack Surface Management

A comprehensive Attack Surface Management (ASM) platform for security teams to discover, monitor, and manage their organization's external attack surface.

## Features

### Core Capabilities
- **Multi-tenant Architecture**: Support for multiple organizations with role-based access control
- **Asset Discovery & Management**: Track domains, subdomains, IPs, URLs, certificates, and more
- **Vulnerability Tracking**: Record, prioritize, and manage security vulnerabilities
- **Scan Management**: Create and manage discovery and vulnerability scans
- **JWT Authentication**: Secure API authentication with access and refresh tokens
- **Role-Based Access Control**: Admin, Analyst, and Viewer roles with granular permissions

### Discovery Features
- **Full Domain Discovery**: Enter a domain (e.g., `rockwellautomation.com`) and automatically discover:
  - DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - Subdomains via certificate transparency logs (crt.sh)
  - Subdomains via common name brute-forcing
  - IP address resolution
  - HTTP/HTTPS endpoint probing

### Technology Fingerprinting
- **Wappalyzer-style Detection**: Identify web technologies including:
  - CMS platforms, Web frameworks, Web servers, E-commerce platforms
  - Analytics tools, CDN providers, Security tools, and 50+ more

### Nuclei Integration
Integrated with [ProjectDiscovery's Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner:

- **Configurable Scan Profiles**: Pre-built and custom scan profiles
- **Severity Filtering**: Scan for critical, high, medium, low, or info findings
- **Template Tags**: Filter by CVE, RCE, SQLi, XSS, misconfiguration, etc.
- **Asset Labeling**: Automatically tag assets with discovered vulnerabilities
- **CVE Tracking**: Link findings to CVE IDs with CVSS scores

### ProjectDiscovery Tools Suite
All [ProjectDiscovery](https://github.com/projectdiscovery) tools are integrated:

| Tool | Description | Endpoint |
|------|-------------|----------|
| **nuclei** | Vulnerability scanner | `POST /api/v1/nuclei/scan` |
| **subfinder** | Subdomain discovery | `POST /api/v1/nuclei/subfinder/{domain}` |
| **httpx** | HTTP probing toolkit | `POST /api/v1/nuclei/httpx` |
| **dnsx** | DNS toolkit | `POST /api/v1/nuclei/dnsx` |
| **naabu** | Port scanner | `POST /api/v1/nuclei/naabu` |
| **katana** | Web crawler | `POST /api/v1/nuclei/katana` |

## Tech Stack

- **Backend**: Python 3.11, FastAPI
- **Database**: PostgreSQL 15
- **Cache/Queue**: Redis 7
- **Authentication**: JWT (python-jose), bcrypt
- **ORM**: SQLAlchemy 2.0
- **Security Tools**: Nuclei, subfinder, httpx, dnsx, naabu, katana
- **Containerization**: Docker, Docker Compose

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/theforcesecurity_ASM.git
cd theforcesecurity_ASM
```

### 2. Environment Configuration

Create a `.env` file in the project root:

```bash
# Database Configuration
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=your_secure_password_here
POSTGRES_DB=asm_db
DB_PORT=5432

# Backend Configuration
BACKEND_PORT=8000
DEBUG=false

# JWT Secret Key - GENERATE A SECURE KEY!
# Generate with: openssl rand -hex 32
SECRET_KEY=your-generated-secret-key-minimum-32-characters

# CORS Origins
CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]

# Redis
REDIS_PORT=6379

# Development Tools
ADMINER_PORT=8080
```

### 3. Start the Services

```bash
# Build and start (includes all ProjectDiscovery tools)
make build
make up

# Or with development tools (includes Adminer)
make dev
```

### 4. Initialize the Database

```bash
make init-db
```

This creates default users:
- **Admin**: username=`admin`, password=`changeme123`
- **Analyst**: username=`analyst`, password=`analyst123`
- **Viewer**: username=`viewer`, password=`viewer123`

⚠️ **Change these passwords immediately in production!**

### 5. Access the API

- **API Documentation**: http://localhost:8000/api/docs
- **Alternative Docs**: http://localhost:8000/api/redoc
- **Adminer (dev only)**: http://localhost:8080

## Scan Profiles

Pre-configured scan profiles for different use cases:

| Profile | Description | Severity |
|---------|-------------|----------|
| **Quick Scan** | Fast scan for critical issues | Critical, High |
| **Full Scan** | Comprehensive vulnerability assessment | All |
| **CVE Only** | Focus on known CVEs | Critical, High, Medium |
| **Misconfiguration** | Exposed services and misconfigs | All |
| **Technology Detection** | Identify tech stack only | Info |
| **Discovery Only** | Asset discovery without vuln scanning | N/A |
| **Passive Recon** | Passive reconnaissance only | N/A |

## Usage Examples

### Full Domain Discovery

```bash
# 1. Login to get token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=changeme123"

# 2. Start discovery
curl -X POST "http://localhost:8000/api/v1/discovery/full" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "rockwellautomation.com",
    "organization_id": 1,
    "include_subdomains": true,
    "include_technology_scan": true
  }'
```

### Run Nuclei Vulnerability Scan

```bash
# Using default profile
curl -X POST "http://localhost:8000/api/v1/nuclei/scan" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com", "https://www.example.com"],
    "organization_id": 1,
    "create_labels": true
  }'

# Using specific profile
curl -X POST "http://localhost:8000/api/v1/nuclei/scan" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com"],
    "organization_id": 1,
    "profile_id": 3,
    "severity": ["critical", "high"],
    "tags": ["cve", "rce"]
  }'
```

### Run Individual ProjectDiscovery Tools

```bash
# Subdomain enumeration with subfinder
curl -X POST "http://localhost:8000/api/v1/nuclei/subfinder/example.com" \
  -H "Authorization: Bearer TOKEN"

# HTTP probing with httpx
curl -X POST "http://localhost:8000/api/v1/nuclei/httpx" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com", "www.example.com"]}'

# Port scanning with naabu
curl -X POST "http://localhost:8000/api/v1/nuclei/naabu" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.1"], "top_ports": 1000}'

# DNS resolution with dnsx
curl -X POST "http://localhost:8000/api/v1/nuclei/dnsx" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'

# Web crawling with katana
curl -X POST "http://localhost:8000/api/v1/nuclei/katana" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["https://example.com"], "depth": 3}'
```

### Check Tool Installation Status

```bash
curl -X GET "http://localhost:8000/api/v1/nuclei/tools/status" \
  -H "Authorization: Bearer TOKEN"
```

### Create Custom Scan Profile

```bash
curl -X POST "http://localhost:8000/api/v1/nuclei/profiles" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom CVE Scan",
    "description": "Custom profile for specific CVEs",
    "nuclei_severity": ["critical", "high"],
    "nuclei_tags": ["cve", "cve2023", "cve2024"],
    "nuclei_rate_limit": 100,
    "enable_vulnerability_scan": true
  }'
```

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login and get tokens |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| GET | `/api/v1/auth/me` | Get current user info |

### Discovery
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/discovery/full` | Full domain discovery |
| GET | `/api/v1/discovery/progress/{scan_id}` | Get discovery progress |
| POST | `/api/v1/discovery/dns/{domain}` | DNS enumeration |
| POST | `/api/v1/discovery/subdomains/{domain}` | Subdomain discovery |
| POST | `/api/v1/discovery/technology` | Technology fingerprinting |

### Nuclei & ProjectDiscovery
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/nuclei/tools/status` | Check tool installation |
| POST | `/api/v1/nuclei/tools/update-templates` | Update Nuclei templates |
| GET | `/api/v1/nuclei/profiles` | List scan profiles |
| POST | `/api/v1/nuclei/profiles` | Create scan profile |
| GET | `/api/v1/nuclei/profiles/{id}` | Get scan profile |
| PUT | `/api/v1/nuclei/profiles/{id}` | Update scan profile |
| DELETE | `/api/v1/nuclei/profiles/{id}` | Delete scan profile |
| POST | `/api/v1/nuclei/scan` | Run Nuclei scan |
| GET | `/api/v1/nuclei/scan/{id}/findings` | Get scan findings |
| GET | `/api/v1/nuclei/tags` | Get available Nuclei tags |
| POST | `/api/v1/nuclei/subfinder/{domain}` | Run subfinder |
| POST | `/api/v1/nuclei/httpx` | Run httpx |
| POST | `/api/v1/nuclei/dnsx` | Run dnsx |
| POST | `/api/v1/nuclei/naabu` | Run naabu |
| POST | `/api/v1/nuclei/katana` | Run katana |

### Assets
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/assets` | List assets |
| POST | `/api/v1/assets` | Create asset |
| GET | `/api/v1/assets/{id}` | Get asset |
| PUT | `/api/v1/assets/{id}` | Update asset |
| DELETE | `/api/v1/assets/{id}` | Delete asset |

### Vulnerabilities
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/vulnerabilities` | List vulnerabilities |
| POST | `/api/v1/vulnerabilities` | Create vulnerability |
| GET | `/api/v1/vulnerabilities/{id}` | Get vulnerability |
| PUT | `/api/v1/vulnerabilities/{id}` | Update vulnerability |
| DELETE | `/api/v1/vulnerabilities/{id}` | Delete vulnerability |

## Asset Labeling

When running Nuclei scans with `create_labels: true`, assets are automatically tagged with:

- **Severity labels**: `vuln:critical`, `vuln:high`, `vuln:medium`, `vuln:low`
- **CVE labels**: `CVE-2023-XXXXX`, `CVE-2024-XXXXX`
- **Template tags**: `nuclei:cve`, `nuclei:rce`, `nuclei:sqli`, etc.
- **Risk scores**: Updated based on highest severity finding

## Project Structure

```
theforcesecurity_ASM/
├── backend/
│   ├── app/
│   │   ├── api/routes/
│   │   │   ├── discovery.py     # Discovery endpoints
│   │   │   ├── nuclei.py        # Nuclei & PD tools endpoints
│   │   │   └── ...
│   │   ├── models/
│   │   │   ├── scan_profile.py  # Scan profile model
│   │   │   └── ...
│   │   ├── services/
│   │   │   ├── nuclei_service.py        # Nuclei integration
│   │   │   ├── projectdiscovery_service.py  # PD tools
│   │   │   ├── discovery_service.py     # Orchestration
│   │   │   └── ...
│   │   └── main.py
│   ├── Dockerfile              # Includes PD tools installation
│   └── requirements.txt
├── docker-compose.yml
├── Makefile
└── README.md
```

## Development

### Useful Commands

```bash
make help      # Show all available commands
make logs      # View container logs
make shell     # Open shell in backend container
make db-shell  # Open PostgreSQL shell
make status    # Show service status
make clean     # Remove all containers and volumes
```

### Running Tests

```bash
make test
```

## AWS Deployment

For production deployments, this platform is designed to run on AWS with the following architecture:

### Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CloudFront    │────▶│       ALB       │────▶│   ECS Fargate   │
│   (Optional)    │     │                 │     │   (API Tasks)   │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                        ┌────────────────────────────────┼────────────────────────────────┐
                        │                                │                                │
               ┌────────▼────────┐            ┌─────────▼─────────┐           ┌──────────▼──────────┐
               │  RDS PostgreSQL │            │   ElastiCache     │           │       SQS           │
               │  (Aurora)       │            │   (Redis)         │           │   (Job Queue)       │
               └─────────────────┘            └───────────────────┘           └──────────┬──────────┘
                                                                                         │
                                              ┌──────────────────────────────────────────┼──────────────────────────────────────────┐
                                              │                                          │                                          │
                                     ┌────────▼────────┐                       ┌─────────▼─────────┐                       ┌────────▼────────┐
                                     │   ECS EC2       │                       │   ECS EC2         │                       │   ECS EC2       │
                                     │ Scanner Worker  │                       │ Scanner Worker    │                       │ Scanner Worker  │
                                     │ (Nuclei, Nmap)  │                       │                   │                       │                 │
                                     └─────────────────┘                       └───────────────────┘                       └─────────────────┘
```

### AWS Services Used

| Service | Purpose | Configuration |
|---------|---------|---------------|
| **ECS Fargate** | API containers | Stateless, auto-scaling |
| **ECS EC2** | Scanner workers | Full network access for scanning |
| **RDS Aurora** | PostgreSQL database | Serverless v2, auto-scaling |
| **ElastiCache** | Redis for caching/sessions | Single node or cluster |
| **SQS** | Job queue for async scans | With dead-letter queue |
| **ALB** | Load balancer | HTTPS termination |
| **ECR** | Container registry | Image scanning enabled |
| **Secrets Manager** | Credentials storage | Automatic rotation |
| **CloudWatch** | Logging and monitoring | Container insights |

### Deployment Steps

#### 1. Prerequisites

```bash
# Install required tools
brew install terraform awscli

# Configure AWS credentials
aws configure

# Verify access
aws sts get-caller-identity
```

#### 2. Configure Terraform Variables

```bash
cd aws/terraform

# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
vim terraform.tfvars
```

Required variables:
```hcl
aws_region   = "us-east-1"
environment  = "prod"
db_password  = "YOUR_SECURE_DB_PASSWORD"
jwt_secret   = "YOUR_SECURE_JWT_SECRET"  # openssl rand -hex 32
```

#### 3. Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Apply changes
terraform apply
```

#### 4. Build and Push Docker Images

```bash
cd aws/scripts
chmod +x deploy.sh

# Build and push all images
./deploy.sh build prod

# Or deploy everything
./deploy.sh all prod
```

#### 5. Run Database Migrations

```bash
./deploy.sh migrate
```

#### 6. Verify Deployment

```bash
# Get ALB DNS name
terraform output alb_dns_name

# Test API
curl http://YOUR_ALB_DNS:8080/health
curl http://YOUR_ALB_DNS:8080/docs
```

### AWS Cost Estimation

| Component | Configuration | Est. Monthly Cost |
|-----------|---------------|-------------------|
| ECS Fargate (API) | 2x 0.5 vCPU, 1GB RAM | $35-50 |
| ECS EC2 (Scanners) | 2x t3.medium | $60-80 |
| RDS Aurora Serverless | 0.5-4 ACU | $50-200 |
| ElastiCache | cache.t3.micro | $15 |
| ALB | Standard | $20 |
| SQS | Usage-based | $1-5 |
| Data Transfer | Varies | $10-50 |
| **Total** | | **$190-400/month** |

*Costs vary based on usage, region, and scanning volume.*

### Production Checklist

- [ ] Enable HTTPS on ALB with ACM certificate
- [ ] Configure CloudFront for caching (optional)
- [ ] Set up WAF rules for API protection
- [ ] Enable RDS backup retention (7+ days)
- [ ] Configure CloudWatch alarms for:
  - API response times
  - Scanner worker failures
  - Database connections
  - SQS queue depth
- [ ] Set up VPC Flow Logs
- [ ] Enable AWS Config for compliance
- [ ] Configure IAM policies (least privilege)
- [ ] Set up automated Nuclei template updates

### Alternative: Quick Deploy with Docker Compose

For smaller deployments or testing, you can run on a single EC2 instance:

```bash
# Launch t3.large or larger EC2 instance with Docker

# Clone repository
git clone https://github.com/yourusername/theforcesecurity_ASM.git
cd theforcesecurity_ASM

# Configure environment
cp .env.example .env
vim .env

# Start services
docker-compose up -d

# Initialize database
docker-compose exec backend python -m app.scripts.init_db
```

## Security Considerations

1. **Change default passwords** immediately after deployment
2. **Generate a secure SECRET_KEY**: `openssl rand -hex 32`
3. **Use HTTPS** in production (ALB + ACM certificate)
4. **Restrict CORS origins** to your frontend domain
5. **Enable DEBUG=false** in production
6. **Rate limit API endpoints** in production
7. **Keep Nuclei templates updated**: `POST /api/v1/nuclei/tools/update-templates`
8. **Restrict scanner security groups** to only necessary egress
9. **Enable AWS GuardDuty** for threat detection
10. **Use VPC endpoints** for AWS service access

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for Nuclei and the security tools suite
- [Wappalyzer](https://github.com/tomnomnom/wappalyzer) for technology fingerprinting patterns
- [crt.sh](https://crt.sh) for certificate transparency data
