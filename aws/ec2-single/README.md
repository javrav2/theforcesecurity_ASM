# ASM Platform - Single EC2 Instance Deployment

The simplest way to run the ASM platform on AWS. All components run on a single EC2 instance using Docker Compose.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      EC2 Instance (t3.large)                │
│                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐│
│  │  Nginx  │──│ FastAPI │──│  Redis  │  │    Scanner      ││
│  │  :80    │  │  :8000  │  │  :6379  │  │  (Background)   ││
│  └─────────┘  └─────────┘  └─────────┘  └─────────────────┘│
│       │            │                                        │
│       │      ┌─────┴─────┐                                 │
│       │      │PostgreSQL │                                 │
│       │      │  :5432    │                                 │
│       │      └───────────┘                                 │
│       │                                                     │
│  ┌────┴────┐                                               │
│  │   EBS   │  (50GB gp3)                                   │
│  │ Storage │                                                │
│  └─────────┘                                                │
└─────────────────────────────────────────────────────────────┘
         │
    ┌────┴────┐
    │Elastic  │
    │   IP    │
    └─────────┘
```

## Cost

| Component | Specification | Monthly Cost |
|-----------|--------------|--------------|
| EC2 | t3.large (2 vCPU, 8GB RAM) | ~$60 |
| EBS | 50GB gp3 | ~$5 |
| Elastic IP | 1 | $3.65 |
| Data Transfer | ~50GB out | ~$5 |
| **Total** | | **~$75/month** |

*Costs based on us-east-1. On-demand pricing. Use Reserved Instances or Spot for savings.*

## Quick Start

### Option 1: AWS Console (Manual)

1. **Launch EC2 Instance**
   - AMI: Ubuntu 22.04 LTS
   - Instance Type: t3.large (minimum)
   - Storage: 50GB gp3
   - Security Group: Allow ports 22, 80, 443

2. **SSH and Setup**
   ```bash
   ssh -i your-key.pem ubuntu@your-instance-ip
   
   # Clone repository
   git clone https://github.com/yourusername/theforcesecurity_ASM.git /opt/asm
   cd /opt/asm
   
   # Run setup
   chmod +x aws/ec2-single/setup.sh
   ./aws/ec2-single/setup.sh
   ```

### Option 2: CloudFormation (Automated)

```bash
# Deploy stack
aws cloudformation create-stack \
  --stack-name asm-platform \
  --template-body file://aws/ec2-single/cloudformation.yml \
  --parameters \
    ParameterKey=KeyName,ParameterValue=your-key-pair \
    ParameterKey=InstanceType,ParameterValue=t3.large \
    ParameterKey=AllowedSSHCIDR,ParameterValue=YOUR_IP/32 \
  --capabilities CAPABILITY_IAM

# Wait for completion
aws cloudformation wait stack-create-complete --stack-name asm-platform

# Get outputs
aws cloudformation describe-stacks --stack-name asm-platform --query 'Stacks[0].Outputs'

# SSH and complete setup
ssh -i your-key.pem ubuntu@<PublicIP>
cd /opt/asm
git clone https://github.com/yourusername/theforcesecurity_ASM.git .
./aws/ec2-single/setup.sh
```

### Option 3: AWS CLI (Quick)

```bash
# Launch instance
aws ec2 run-instances \
  --image-id ami-0c7217cdde317cfec \
  --instance-type t3.large \
  --key-name your-key-pair \
  --security-group-ids sg-xxx \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":50,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ASM-Platform}]'
```

## Post-Installation

### Access the Platform

```bash
# API Documentation
http://YOUR_IP/docs

# Health Check
http://YOUR_IP/health

# Login
curl -X POST "http://YOUR_IP/api/v1/auth/login" \
  -d "username=admin&password=changeme123"
```

### Default Credentials

| User | Password | Role |
|------|----------|------|
| admin | changeme123 | Admin |
| analyst | analyst123 | Analyst |
| viewer | viewer123 | Viewer |

⚠️ **Change these immediately!**

### Management Commands

```bash
cd /opt/asm

# View status
./manage.sh status

# View logs
./manage.sh logs

# Backup database
./manage.sh backup

# Update Nuclei templates
./manage.sh update-nuclei

# Check health
./manage.sh health

# Setup SSL
./manage.sh ssl-setup your-domain.com your-email@domain.com
```

## SSL Setup (HTTPS)

### Option 1: Let's Encrypt (Free)

```bash
./manage.sh ssl-setup asm.yourdomain.com admin@yourdomain.com
```

### Option 2: AWS Certificate Manager + ALB

For production with custom domain:

1. Create ACM certificate
2. Create Application Load Balancer
3. Point ALB to EC2 instance
4. Update Route53 DNS

## Scaling Up

When you outgrow a single instance:

1. **Vertical Scaling**: Upgrade to t3.xlarge, m5.large, etc.
2. **Add RDS**: Move PostgreSQL to RDS for better reliability
3. **Add ElastiCache**: Move Redis to ElastiCache
4. **Full AWS Setup**: Use the Terraform configuration in `aws/terraform/`

## Monitoring

### CloudWatch Metrics

The CloudFormation template sets up alarms for:
- CPU > 80%
- Disk > 80%

### Manual Monitoring

```bash
# Real-time stats
docker stats

# Check logs
./manage.sh logs

# System health
htop
df -h
free -h
```

## Backup & Recovery

### Automated Backups

Set up cron job:
```bash
# Daily backup at 2 AM
0 2 * * * /opt/asm/manage.sh backup
```

### Manual Backup

```bash
./manage.sh backup
# Backup saved to /opt/asm/backups/
```

### Restore

```bash
./manage.sh restore /opt/asm/backups/asm_backup_20240115_020000.sql.gz
```

### Backup to S3

```bash
# Upload backups to S3
aws s3 sync /opt/asm/backups/ s3://your-bucket/asm-backups/
```

## Security Hardening

1. **Restrict SSH Access**
   ```bash
   # Update security group to only allow your IP
   aws ec2 authorize-security-group-ingress \
     --group-id sg-xxx \
     --protocol tcp \
     --port 22 \
     --cidr YOUR_IP/32
   ```

2. **Enable Fail2ban**
   ```bash
   sudo apt install fail2ban
   sudo systemctl enable fail2ban
   ```

3. **Update Regularly**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ./manage.sh update
   ```

4. **Enable AWS Systems Manager**
   - No SSH keys needed
   - Audit logging
   - Patch management

## Troubleshooting

### Services Not Starting

```bash
# Check Docker
sudo systemctl status docker

# Check containers
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs
```

### Database Connection Issues

```bash
# Check database
docker compose -f docker-compose.prod.yml logs db

# Restart database
docker compose -f docker-compose.prod.yml restart db
```

### Out of Disk Space

```bash
# Check disk
df -h

# Clean Docker
docker system prune -a

# Clean old backups
ls -la /opt/asm/backups/
```

### Memory Issues

```bash
# Check memory
free -h

# Upgrade instance type if needed
# Or add swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Cleanup

### Delete CloudFormation Stack

```bash
aws cloudformation delete-stack --stack-name asm-platform
```

### Manual Cleanup

1. Terminate EC2 instance
2. Delete EBS volumes
3. Release Elastic IP
4. Delete security groups













