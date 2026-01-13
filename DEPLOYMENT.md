# ASM Platform - AWS Deployment Guide

<p align="center">
  <img src="frontend/public/logo.svg" alt="The Force Security Logo" width="100" height="100">
</p>

<p align="center">
  <strong>Complete guide to deploying the Attack Surface Management platform on AWS</strong>
</p>

---

## 📋 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Prerequisites](#-prerequisites)
- [Deployment Options](#-deployment-options)
  - [Option 1: CloudFormation (Recommended)](#option-1-cloudformation-recommended)
  - [Option 2: Manual EC2 Setup](#option-2-manual-ec2-setup)
- [Post-Installation](#-post-installation)
- [SSL/HTTPS Setup](#-sslhttps-setup)
- [SQS Configuration](#-sqs-configuration-optional)
- [Common Crawl S3 Index](#-common-crawl-s3-index-optional)
- [Management Commands](#-management-commands)
- [Troubleshooting](#-troubleshooting)
- [Security Hardening](#-security-hardening)
- [Cost Estimate](#-cost-estimate)
- [Cleanup](#-cleanup)

---

## 🏗️ Architecture Overview

### AWS Infrastructure Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     AWS Cloud (us-east-1)                                    │
│                                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              EC2 Instance (t3.large)                                    │ │
│  │                              Ubuntu 22.04 + Docker                                      │ │
│  │                                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────┐   │ │
│  │  │                            Docker Compose Stack                                  │   │ │
│  │  │                                                                                  │   │ │
│  │  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐   │   │ │
│  │  │   │   Frontend   │    │   Backend    │    │   Scanner    │    │   Redis     │   │   │ │
│  │  │   │   Next.js    │───▶│   FastAPI    │◀───│   Worker     │◀──▶│   Cache     │   │   │ │
│  │  │   │   :80        │    │   :8000      │    │              │    │   :6379     │   │   │ │
│  │  │   └──────────────┘    └──────┬───────┘    └──────┬───────┘    └─────────────┘   │   │ │
│  │  │                              │                    │                              │   │ │
│  │  │                              ▼                    │                              │   │ │
│  │  │                       ┌──────────────┐            │                              │   │ │
│  │  │                       │  PostgreSQL  │            │                              │   │ │
│  │  │                       │  Database    │            │                              │   │ │
│  │  │                       │   :5432      │            │                              │   │ │
│  │  │                       └──────────────┘            │                              │   │ │
│  │  │                                                   │                              │   │ │
│  │  │   ┌─────────────────────────────────────────────────────────────────────────┐   │   │ │
│  │  │   │                    Security Tools Suite                                  │   │   │ │
│  │  │   │  • Nuclei (Vulnerability Scanner)    • Masscan (Port Scanner)           │   │   │ │
│  │  │   │  • Subfinder (Subdomain Discovery)   • Nmap (Service Detection)         │   │   │ │
│  │  │   │  • HTTPX (HTTP Probing)              • EyeWitness (Screenshots)         │   │   │ │
│  │  │   │  • DNSX (DNS Resolver)               • WaybackURLs (Historical URLs)    │   │   │ │
│  │  │   │  • Naabu (Port Scanner)              • Katana (Web Crawler)             │   │   │ │
│  │  │   └─────────────────────────────────────────────────────────────────────────┘   │   │ │
│  │  └──────────────────────────────────────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘ │
│                    │                                              │                          │
│                    │ Poll/Send Messages                           │ Sync Index               │
│                    ▼                                              ▼                          │
│  ┌─────────────────────────────────┐          ┌─────────────────────────────────────────┐   │
│  │          Amazon SQS             │          │              Amazon S3                   │   │
│  │   asm-scan-jobs                 │          │   asm-commoncrawl-theforce              │   │
│  │                                 │          │                                          │   │
│  │   • Async scan job queue        │          │   • Common Crawl subdomain index        │   │
│  │   • Visibility: 3600s           │          │   • Historical web crawl data           │   │
│  │   • Retention: 14 days          │          │   • ~100ms subdomain lookups            │   │
│  └─────────────────────────────────┘          └─────────────────────────────────────────┘   │
│                                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                               Security Group                                             │ │
│  │   Inbound Rules:                                                                        │ │
│  │   • SSH (22)    ─────────────  Your IP/32                                               │ │
│  │   • HTTP (80)   ─────────────  0.0.0.0/0  (Frontend)                                    │ │
│  │   • HTTPS (443) ─────────────  0.0.0.0/0  (SSL - optional)                              │ │
│  │   • TCP (8000)  ─────────────  0.0.0.0/0  (Backend API)                                 │ │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           │ HTTPS API Calls
                                           ▼
              ┌─────────────────────────────────────────────────────────────────┐
              │                    External APIs (Configured)                    │
              │                                                                  │
              │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
              │   │ VirusTotal  │  │   Whoxy     │  │  WhoisXML   │             │
              │   │ Subdomains  │  │ Rev. WHOIS  │  │ Netblocks/  │             │
              │   │             │  │             │  │ DNS Enrich  │             │
              │   └─────────────┘  └─────────────┘  └─────────────┘             │
              │                                                                  │
              │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
              │   │   Tracxn    │  │    crt.sh   │  │   Wayback   │             │
              │   │   M&A Data  │  │   (Free)    │  │   (Free)    │             │
              │   └─────────────┘  └─────────────┘  └─────────────┘             │
              └─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    User     │     │  Frontend   │     │   Backend   │     │   Scanner   │
│  (Browser)  │     │  (Next.js)  │     │  (FastAPI)  │     │  (Worker)   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │  1. Login/Navigate│                   │                   │
       │──────────────────▶│                   │                   │
       │                   │  2. API Request   │                   │
       │                   │──────────────────▶│                   │
       │                   │                   │                   │
       │                   │                   │  3. Create Scan   │
       │                   │                   │   (to SQS Queue)  │
       │                   │                   │──────────────────▶│
       │                   │                   │                   │
       │                   │                   │                   │  4. Run Tools
       │                   │                   │                   │  ┌──────────┐
       │                   │                   │                   │──│  Nuclei  │
       │                   │                   │                   │  │ Subfinder│
       │                   │                   │                   │  │  Naabu   │
       │                   │                   │                   │  └──────────┘
       │                   │                   │                   │
       │                   │                   │  5. Store Results │
       │                   │                   │◀──────────────────│
       │                   │                   │                   │
       │                   │  6. Return Data   │                   │
       │                   │◀──────────────────│                   │
       │  7. Display       │                   │                   │
       │◀──────────────────│                   │                   │
```

### Component Summary

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Frontend** | Next.js 14, React, Tailwind CSS | Dashboard UI, asset explorer, scan management |
| **Backend** | FastAPI, Python 3.11, SQLAlchemy | REST API, authentication, business logic |
| **Scanner** | Python worker + CLI tools | Async scan execution, vulnerability detection |
| **Database** | PostgreSQL 15 | Asset storage, findings, user management |
| **Cache** | Redis 7 | Session cache, job queue, rate limiting |
| **SQS** | Amazon SQS | Reliable async scan job processing |
| **S3** | Amazon S3 | Common Crawl subdomain index storage |

### AWS Resources

| Resource | Name/ID | Purpose |
|----------|---------|---------|
| **EC2 Instance** | t3.large | Application host |
| **SQS Queue** | `asm-scan-jobs` | Async scan processing |
| **S3 Bucket** | `asm-commoncrawl-theforce` | Subdomain index |
| **Security Group** | Ports 22, 80, 443, 8000 | Network access control |

---

## 🔧 Prerequisites

Before deploying, ensure you have:

- [ ] AWS Account with appropriate permissions
- [ ] AWS CLI installed and configured (`aws configure`)
- [ ] EC2 Key Pair created in your target region
- [ ] Your public IP address (for SSH access restriction)

### Minimum Instance Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 2 vCPU | 4 vCPU |
| **RAM** | 8 GB | 16 GB |
| **Storage** | 30 GB | 50 GB+ |
| **Instance Type** | t3.large | t3.xlarge |

---

## 🚀 Deployment Options

### Option 1: CloudFormation (Recommended)

The fastest way to deploy with automatic resource creation including EC2, VPC, SQS, IAM roles, and security groups.

#### Step 1: Deploy the CloudFormation Stack

```bash
aws cloudformation create-stack \
  --stack-name asm-platform \
  --template-body file://aws/ec2-single/cloudformation.yml \
  --parameters \
    ParameterKey=KeyName,ParameterValue=YOUR_KEY_PAIR_NAME \
    ParameterKey=InstanceType,ParameterValue=t3.large \
    ParameterKey=VolumeSize,ParameterValue=50 \
    ParameterKey=AllowedSSHCIDR,ParameterValue=YOUR_IP/32 \
  --capabilities CAPABILITY_IAM
```

> 💡 Replace `YOUR_KEY_PAIR_NAME` with your EC2 key pair name and `YOUR_IP/32` with your public IP (find it at https://ifconfig.me)

#### Step 2: Wait for Stack Creation

```bash
# Wait for completion (~10 minutes)
aws cloudformation wait stack-create-complete --stack-name asm-platform

# Get the outputs (Public IP, SQS URL, etc.)
aws cloudformation describe-stacks --stack-name asm-platform \
  --query 'Stacks[0].Outputs' --output table
```

#### Step 3: SSH and Complete Setup

```bash
# SSH into the instance
ssh -i your-key.pem ubuntu@PUBLIC_IP_FROM_OUTPUT

# Clone the repository
cd /opt/asm
git clone https://github.com/javrav2/theforcesecurity_ASM.git .

# Run the setup script
chmod +x aws/ec2-single/setup.sh
./aws/ec2-single/setup.sh
```

#### What CloudFormation Creates

| Resource | Description |
|----------|-------------|
| ✅ VPC + Subnet | Isolated network with public subnet |
| ✅ EC2 Instance | Ubuntu 22.04 with Docker pre-configured |
| ✅ SQS Queue | For async scan job processing |
| ✅ IAM Role | EC2 permissions for SQS access |
| ✅ Security Group | Ports 22, 80, 443 open |
| ✅ Elastic IP | Static public IP address |
| ✅ CloudWatch Alarms | Basic monitoring |

---

### Option 2: Manual EC2 Setup

For more control over the deployment process.

#### Step 1: Launch EC2 Instance

1. Go to **EC2 Console** → **Launch Instance**
2. Configure:

| Setting | Value |
|---------|-------|
| **Name** | `asm-platform` |
| **AMI** | Ubuntu Server 22.04 LTS |
| **Instance Type** | t3.large |
| **Key Pair** | Select or create one |
| **Storage** | 50 GB gp3 |

3. **Security Group Rules:**

| Type | Port | Source |
|------|------|--------|
| SSH | 22 | Your IP/32 |
| HTTP | 80 | 0.0.0.0/0 |
| HTTPS | 443 | 0.0.0.0/0 |
| Custom TCP | 8000 | 0.0.0.0/0 |

4. Launch the instance and note the **Public IP**

#### Step 2: SSH Into Your Instance

```bash
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

#### Step 3: Install Docker

```bash
# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Add your user to the docker group
sudo usermod -aG docker $USER

# IMPORTANT: Log out and back in for group changes to take effect
exit
```

SSH back in after logging out:

```bash
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

#### Step 4: Clone the Repository

```bash
# Create application directory
sudo mkdir -p /opt/asm
sudo chown $USER:$USER /opt/asm

# Clone the repository
git clone https://github.com/javrav2/theforcesecurity_ASM.git /opt/asm
cd /opt/asm
```

#### Step 5: Create Environment File

```bash
# Get your EC2 public IP
PUBLIC_IP=$(curl -s ifconfig.me)

# Generate secure secrets
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)

# Create .env file
cat > .env << EOF
# =============================================================================
# ASM Platform - Production Configuration
# =============================================================================

# Database Configuration
POSTGRES_USER=asm_user
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=asm_db
DB_PORT=5432

# Security - KEEP THIS SECRET!
SECRET_KEY=${SECRET_KEY}

# Ports
BACKEND_PORT=8000
FRONTEND_PORT=80
REDIS_PORT=6379

# Settings
DEBUG=false

# Frontend API URL (update with your domain if using one)
NEXT_PUBLIC_API_URL=http://${PUBLIC_IP}:8000

# CORS Origins
CORS_ORIGINS=["http://localhost","http://localhost:80","http://localhost:3000","http://${PUBLIC_IP}","http://${PUBLIC_IP}:80","http://${PUBLIC_IP}:3000"]

# AWS SQS (Optional - leave empty to use database polling)
SQS_QUEUE_URL=
AWS_REGION=us-east-1
EOF

# Secure the file
chmod 600 .env

echo "Environment file created with PUBLIC_IP: ${PUBLIC_IP}"
```

#### Step 6: Build and Start Services

```bash
# Build and start all services (this takes 10-15 minutes on first run)
sudo docker compose up -d --build

# Watch the build progress
sudo docker compose logs -f

# Press Ctrl+C to exit logs when services are running
```

#### Step 7: Verify Services Are Running

```bash
# Check all containers are running
sudo docker compose ps

# Expected output:
# NAME            STATUS
# asm_backend     Up (healthy)
# asm_frontend    Up
# asm_database    Up (healthy)
# asm_redis       Up (healthy)
# asm_scanner     Up
```

#### Step 8: Create Admin User

```bash
sudo docker exec asm_backend python -c "
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

---

## ✅ Post-Installation

### Access Your Application

| Service | URL |
|---------|-----|
| **Frontend Dashboard** | `http://YOUR_EC2_IP` |
| **Backend API** | `http://YOUR_EC2_IP:8000` |
| **API Documentation** | `http://YOUR_EC2_IP:8000/api/docs` |
| **Health Check** | `http://YOUR_EC2_IP:8000/health` |

### Default Credentials

| Field | Value |
|-------|-------|
| **Email** | `admin@theforce.security` |
| **Password** | `admin123` |

⚠️ **IMPORTANT: Change the default password immediately after first login!**

### Verify Everything Works

1. Open `http://YOUR_EC2_IP` in your browser
2. Login with the default credentials
3. Navigate to **Organizations** and create your first organization
4. Go to **Discovery** to start finding assets

---

## 🔒 SSL/HTTPS Setup

### Option 1: Let's Encrypt (Free)

```bash
# Install Certbot
sudo apt update
sudo apt install -y certbot

# Stop services temporarily
cd /opt/asm
sudo docker compose down

# Get certificate (replace with your domain)
sudo certbot certonly --standalone -d your-domain.com

# Create SSL directory
mkdir -p /opt/asm/ssl

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/asm/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/asm/ssl/
sudo chown $USER:$USER /opt/asm/ssl/*.pem

# Restart services
sudo docker compose up -d
```

### Option 2: AWS Certificate Manager + ALB

For production deployments with custom domains:

1. Request a certificate in **ACM**
2. Create an **Application Load Balancer**
3. Attach the ACM certificate to the ALB
4. Point the ALB to your EC2 instance

---

## 📬 SQS Configuration (Optional)

For reliable async scan processing in production:

### Create SQS Queue

```bash
aws sqs create-queue \
  --queue-name asm-scan-jobs \
  --attributes VisibilityTimeout=3600,MessageRetentionPeriod=1209600
```

### Add to Environment

```bash
# Get the queue URL
SQS_URL=$(aws sqs get-queue-url --queue-name asm-scan-jobs --query 'QueueUrl' --output text)

# Add to .env
echo "SQS_QUEUE_URL=${SQS_URL}" >> /opt/asm/.env
echo "AWS_REGION=us-east-1" >> /opt/asm/.env

# Restart services
cd /opt/asm
sudo docker compose down && sudo docker compose up -d
```

### Verify SQS Connection

```bash
# Check scanner logs for SQS connection
sudo docker compose logs scanner | grep -i sqs

# Should show: "SQS client initialized for queue: https://sqs..."
```

---

## 🕸️ Common Crawl S3 Index (Optional)

For faster subdomain discovery using historical web crawl data:

### Setup

```bash
cd /opt/asm/aws/commoncrawl

# Create S3 bucket
chmod +x setup-s3.sh
./setup-s3.sh asm-commoncrawl-yourorg us-east-1

# Build initial index (takes 10-30 minutes)
pip install boto3 httpx
python update-index.py --bucket asm-commoncrawl-yourorg

# Add to environment
echo "CC_S3_BUCKET=asm-commoncrawl-yourorg" >> /opt/asm/.env

# Restart services
cd /opt/asm
sudo docker compose down && sudo docker compose up -d
```

### Benefits

- **Speed**: ~100ms lookups vs 30-60s API queries
- **Historical data**: Find forgotten/legacy subdomains
- **Offline capable**: Works even if Common Crawl API is down

---

## 🛠️ Management Commands

### Viewing Logs

```bash
cd /opt/asm

# All services
sudo docker compose logs -f

# Specific service
sudo docker compose logs -f backend
sudo docker compose logs -f frontend
sudo docker compose logs -f scanner
sudo docker compose logs -f db
```

### Service Management

```bash
cd /opt/asm

# Check status
sudo docker compose ps

# Restart all services
sudo docker compose restart

# Restart specific service
sudo docker compose restart backend

# Stop all services
sudo docker compose down

# Start all services
sudo docker compose up -d

# Rebuild and restart (after code changes)
sudo docker compose up -d --build
```

### Database Operations

```bash
# Access PostgreSQL shell
sudo docker exec -it asm_database psql -U asm_user -d asm_db

# Backup database
sudo docker exec asm_database pg_dump -U asm_user asm_db > backup_$(date +%Y%m%d).sql

# Restore database
cat backup.sql | sudo docker exec -i asm_database psql -U asm_user -d asm_db
```

### Container Shell Access

```bash
# Backend shell
sudo docker exec -it asm_backend bash

# Scanner shell
sudo docker exec -it asm_scanner bash

# Redis CLI
sudo docker exec -it asm_redis redis-cli
```

### Update Nuclei Templates

```bash
sudo docker exec asm_scanner nuclei -update-templates
```

---

## 🔍 Troubleshooting

### Container Not Starting

```bash
# Check container logs
sudo docker compose logs backend

# Check if ports are in use
sudo netstat -tlnp | grep -E '80|8000|5432|6379'

# Restart Docker
sudo systemctl restart docker
```

### Database Connection Issues

```bash
# Check database is running
sudo docker compose ps db

# Test database connection
sudo docker exec asm_database psql -U asm_user -d asm_db -c "SELECT 1"

# Check database logs
sudo docker compose logs db
```

### Scanner Not Processing Jobs

```bash
# Check scanner status
sudo docker compose ps scanner

# View scanner logs
sudo docker compose logs --tail=100 scanner

# Check SQS configuration
sudo docker compose exec scanner env | grep SQS

# Restart scanner
sudo docker compose restart scanner
```

### Frontend Not Loading

```bash
# Check frontend logs
sudo docker compose logs frontend

# Verify NEXT_PUBLIC_API_URL in .env matches your server
grep NEXT_PUBLIC_API_URL .env

# Rebuild frontend with correct URL
sudo docker compose up -d --build frontend
```

### "No such container" Error

```bash
# List all containers
sudo docker ps -a

# If containers don't exist, start them
sudo docker compose up -d

# If Docker isn't running
sudo systemctl start docker
```

### Permission Denied for Port Scanning

The scanner container needs `NET_RAW` capability. Verify in `docker-compose.yml`:

```yaml
scanner:
  cap_add:
    - NET_RAW
    - NET_ADMIN
```

---

## 🔐 Security Hardening

### Immediate Actions

- [ ] **Change default admin password** - Do this first!
- [ ] **Restrict SSH access** - Only allow your IP in security group
- [ ] **Generate new SECRET_KEY** - `openssl rand -hex 32`
- [ ] **Set DEBUG=false** - Already set if you followed this guide

### Production Recommendations

- [ ] **Enable HTTPS** - Use Let's Encrypt or ACM
- [ ] **Use IAM roles** - Instead of access keys for AWS services
- [ ] **Enable CloudTrail** - For audit logging
- [ ] **Set up VPC Flow Logs** - For network monitoring
- [ ] **Regular updates** - `sudo apt update && sudo apt upgrade -y`
- [ ] **Backup database** - Set up automated backups
- [ ] **Monitor resources** - Set up CloudWatch alarms

### Security Group Best Practices

| Port | Access |
|------|--------|
| 22 (SSH) | Your IP only |
| 80 (HTTP) | 0.0.0.0/0 (redirect to HTTPS) |
| 443 (HTTPS) | 0.0.0.0/0 |
| 8000 (API) | Internal only or via ALB |
| 5432 (PostgreSQL) | Internal only |
| 6379 (Redis) | Internal only |

---

## 💰 Cost Estimate

### Monthly Costs (us-east-1)

| Component | Specification | Monthly Cost |
|-----------|---------------|--------------|
| EC2 | t3.large (2 vCPU, 8GB RAM) | ~$60 |
| EBS | 50GB gp3 | ~$5 |
| Elastic IP | 1 | ~$4 |
| SQS | ~10,000 requests | ~$0.01 |
| Data Transfer | ~50GB out | ~$5 |
| **Total** | | **~$75/month** |

### Cost Optimization Tips

- Use **Reserved Instances** for 30-60% savings
- Use **Spot Instances** for non-production
- Schedule instance stop during off-hours
- Use **t3.medium** for light usage

---

## 🧹 Cleanup

### Delete CloudFormation Stack

```bash
aws cloudformation delete-stack --stack-name asm-platform
aws cloudformation wait stack-delete-complete --stack-name asm-platform
```

### Manual Cleanup

```bash
# Stop and remove containers
cd /opt/asm
sudo docker compose down -v

# Remove images
sudo docker system prune -a -f

# Remove application directory
sudo rm -rf /opt/asm
```

### AWS Resources to Delete

1. ☐ EC2 Instance
2. ☐ EBS Volumes
3. ☐ Elastic IP
4. ☐ SQS Queue
5. ☐ Security Groups
6. ☐ IAM Roles
7. ☐ S3 Buckets (if using Common Crawl)

---

## 📚 Additional Resources

- [Main README](README.md) - Full feature documentation
- [AWS EC2 Single Instance Guide](aws/ec2-single/README.md) - Detailed EC2 setup
- [Common Crawl Setup](aws/commoncrawl/README.md) - S3 index configuration
- [API Documentation](http://YOUR_IP:8000/api/docs) - Interactive API docs

---

## 🆘 Getting Help

If you encounter issues:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review container logs: `sudo docker compose logs -f`
3. Verify environment variables: `cat .env`
4. Check service health: `sudo docker compose ps`

---

<p align="center">
  <strong>Made with ❤️ by The Force Security</strong>
</p>

