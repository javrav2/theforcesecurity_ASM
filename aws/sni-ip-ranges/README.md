# SNI IP Ranges S3 Index

This directory contains scripts to set up and maintain a pre-processed SNI IP Ranges index in S3 for fast cloud asset discovery.

## What is SNI IP Ranges?

[kaeferjaeger.gay](https://kaeferjaeger.gay/?dir=sni-ip-ranges) maintains a dataset of SSL/TLS certificates collected by scanning cloud provider IP ranges. This reveals:

- **Domains hosted on AWS, Azure, GCP, Oracle, DigitalOcean**
- **Hidden assets** not visible through DNS enumeration
- **IP addresses** associated with each domain
- **Cloud infrastructure** details

## Why S3-Backed Index?

The raw data files are large (~500MB+ compressed). By pre-processing and storing in S3:

- **Fast lookups**: Binary search on local cached file (~100ms)
- **Keyword search**: Find "rockwellautomation" across all cloud providers
- **IP mapping**: Know which cloud IPs host which domains
- **Weekly updates**: Source data updated periodically

## Architecture

```
┌──────────────────────┐     Weekly      ┌──────────────────┐
│   kaeferjaeger.gay   │ ───────────────►│    S3 Bucket     │
│   sni-ip-ranges/     │  update-index   │  domains.txt.gz  │
│   - amazon/          │                 │  domain-ip-map   │
│   - google/          │                 │  metadata.json   │
│   - microsoft/       │                 └────────┬─────────┘
│   - oracle/          │                          │
│   - digitalocean/    │                          │ sync_from_s3()
└──────────────────────┘                          ▼
                                         ┌──────────────────┐
                                         │  ASM Backend     │
                                         │  Local Cache     │
                                         │  Binary Search   │
                                         └──────────────────┘
```

## Setup

### 1. Create S3 Bucket

```bash
# Use same bucket as Common Crawl, or create new one
aws s3 mb s3://my-asm-data --region us-east-1
```

### 2. Configure Environment

Add to your `.env` file:

```bash
SNI_S3_BUCKET=my-asm-data
# Or reuse CC bucket:
# CC_S3_BUCKET=my-asm-data

AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
```

### 3. Build Initial Index

```bash
# Install dependencies
pip install boto3 httpx

# Run the update script (uses large .txt files by default)
python update-index.py --bucket my-asm-data

# Use smaller JSON files instead (faster but less complete data)
python update-index.py --bucket my-asm-data --use-json

# Process only specific providers
python update-index.py --bucket my-asm-data --providers amazon,google
```

**Expected Duration:**
- With `--use-txt` (default): 30-60 minutes per provider (large files ~100-500MB each)
- With `--use-json`: 5-15 minutes total (smaller files)

**Source Files:**
| File Type | Size | Data |
|-----------|------|------|
| `ipv4_merged_sni.txt` | 100-500 MB each | IP + all domains on same line |
| `ipv4_merged_sni.json.gz` | 10-50 MB each | Compressed JSON structure |

### 4. Schedule Weekly Updates

**Option A: Cron on EC2**
```bash
0 0 * * 0 cd /opt/asm/aws/sni-ip-ranges && python update-index.py --bucket my-asm-data >> /var/log/sni-update.log 2>&1
```

**Option B: EventBridge + Lambda**
```bash
# Create Lambda from update-index.py
# Set up EventBridge rule: rate(7 days)
```

**Option C: Docker scheduled task**
```bash
# Add to docker-compose.yml scheduler service
```

## Usage

### API Endpoints

```bash
# Sync S3 index to local cache
curl -X POST "http://localhost:8000/api/v1/sni-discovery/sync" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"force": false}'

# Search for organization
curl -X POST "http://localhost:8000/api/v1/sni-discovery/search/organization" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "organization_name": "rockwellautomation",
    "primary_domain": "rockwellautomation.com",
    "keywords": ["rockwell", "allen-bradley"]
  }'

# Import discovered assets
curl -X POST "http://localhost:8000/api/v1/sni-discovery/import-to-assets" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "organization_name": "rockwellautomation",
    "primary_domain": "rockwellautomation.com"
  }'
```

### CLI Testing

```bash
# Test search
python update-index.py --bucket my-asm-data \
  --test-search "rockwellautomation" \
  --test-domain "rockwellautomation.com"
```

## Index Format

Domains are stored in **reversed format** for fast prefix matching:

```
# Original: www.rockwellautomation.com
# Stored:   com,rockwellautomation,www

# This allows binary search for all subdomains
# by searching for prefix "com,rockwellautomation,"
```

## S3 Structure

```
s3://your-bucket/
└── sni-ip-ranges/
    ├── domains.txt.gz         # All domains (reversed, sorted, gzipped)
    ├── domain-ip-map.json.gz  # Domain → {ips, provider} mapping
    └── metadata.json          # Index metadata
```

## Estimated Sizes

| Metric | Value |
|--------|-------|
| Total domains | 5-20 million |
| Domains file | 50-200 MB compressed |
| Mapping file | 100-500 MB compressed |
| Memory usage | ~1-2 GB when loaded |
| Lookup time | <100ms |
| Build time | 5-15 minutes |

## Cloud Providers

| Provider | Directory | Description |
|----------|-----------|-------------|
| Amazon AWS | `amazon/` | EC2, Lambda, CloudFront, etc. |
| Google Cloud | `google/` | GCE, Cloud Run, Cloud Functions |
| Microsoft Azure | `microsoft/` | VMs, App Service, Functions |
| Oracle Cloud | `oracle/` | OCI Compute, Object Storage |
| DigitalOcean | `digitalocean/` | Droplets, App Platform |

## Files

| File | Description |
|------|-------------|
| `update-index.py` | Build index and upload to S3 |
| `README.md` | This file |

## IAM Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket",
                "arn:aws:s3:::your-bucket/sni-ip-ranges/*"
            ]
        }
    ]
}
```

## Troubleshooting

### Index not loading
```bash
# Check if index exists in S3
aws s3 ls s3://your-bucket/sni-ip-ranges/

# Check metadata
aws s3 cp s3://your-bucket/sni-ip-ranges/metadata.json -
```

### Download failures
```bash
# Test direct download from source (JSON - smaller)
curl -I https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.json.gz

# Test TXT file (large - check headers only)
curl -I https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.txt
```

### Large file download timeouts
The `.txt` files can be 100-500MB each. If downloads fail:

1. **Check network speed** - Need stable connection for 30-60 minute downloads
2. **Use EC2 in same region** - Download from an EC2 instance for faster speeds
3. **Try one provider at a time**:
   ```bash
   python update-index.py --bucket my-bucket --providers amazon
   python update-index.py --bucket my-bucket --providers google
   # etc.
   ```
4. **Fall back to JSON files** (less data but much faster):
   ```bash
   python update-index.py --bucket my-bucket --use-json
   ```

### Memory issues
Increase container memory or use streaming search instead of loading all into memory.

### Large file sizes
The TXT source files are:
- `amazon/ipv4_merged_sni.txt` - ~200-400 MB
- `google/ipv4_merged_sni.txt` - ~100-200 MB  
- `microsoft/ipv4_merged_sni.txt` - ~150-300 MB
- `oracle/ipv4_merged_sni.txt` - ~50-100 MB
- `digitalocean/ipv4_merged_sni.txt` - ~20-50 MB

The script uses streaming downloads to avoid memory issues.

## Source Data

The data comes from [kaeferjaeger.gay](https://kaeferjaeger.gay/?dir=sni-ip-ranges), which scans cloud provider IP ranges and collects SSL/TLS certificate information. The data is updated periodically.

**Last updated:** Check `metadata.json` for version timestamp.
