# Common Crawl S3 Index

This directory contains scripts to set up and maintain a pre-processed Common Crawl domain index in S3 for fast subdomain lookups.

## Why S3-Backed Index?

Common Crawl maintains billions of crawled URLs. Querying their API is slow (can take 30-60+ seconds). By pre-processing and storing the domain index in S3:

- **Fast lookups**: Binary search on local cached file (~100ms)
- **Offline capable**: Works even if CC API is down
- **Historical data**: Find forgotten/legacy subdomains
- **Cost effective**: Query once, cache forever

## Architecture

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
                                     │  Binary Search   │
                                     └──────────────────┘
```

## Setup

### 1. Create S3 Bucket

```bash
# Using the provided script
./setup-s3.sh my-asm-commoncrawl us-east-1

# Or manually
aws s3 mb s3://my-asm-commoncrawl --region us-east-1
```

### 2. Configure Environment

Add to your `.env` file:

```bash
CC_S3_BUCKET=my-asm-commoncrawl
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
```

### 3. Build Initial Index

```bash
# Install dependencies
pip install boto3 httpx

# Run the update script
python update-index.py --bucket my-asm-commoncrawl

# This takes 10-30 minutes depending on how many domains you collect
```

### 4. Schedule Monthly Updates

Common Crawl releases new data monthly. Set up a scheduled task:

**Option A: EventBridge + Lambda**
```bash
# Create Lambda from update-index.py
# Set up EventBridge rule: rate(30 days)
```

**Option B: Cron on EC2**
```bash
# Add to crontab
0 0 1 * * cd /opt/asm/aws/commoncrawl && python update-index.py >> /var/log/cc-update.log 2>&1
```

**Option C: ECS Scheduled Task**
```yaml
# In your task definition, run update-index.py monthly
```

## Usage in API

Once configured, the ASM platform will automatically use the S3-backed index:

```bash
# Full discovery includes Common Crawl
curl -X POST "http://localhost:8000/api/v1/external-discovery/run" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"domain": "rockwellautomation.com", "organization_id": 1}'

# Or query Common Crawl directly
curl -X POST "http://localhost:8000/api/v1/external-discovery/run/source" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"domain": "rockwellautomation.com", "source": "commoncrawl", "organization_id": 1}'
```

## Index Format

The domain index uses reversed domain format for fast prefix matching:

```
# Original: www.rockwellautomation.com
# Stored:   com,rockwellautomation,www

# This allows binary search for all subdomains of rockwellautomation.com
# by searching for prefix "com,rockwellautomation,"
```

## Files

| File | Description |
|------|-------------|
| `setup-s3.sh` | Create and configure S3 bucket |
| `update-index.py` | Build/update the domain index |
| `README.md` | This file |

## S3 Bucket Structure

```
s3://your-bucket/
└── commoncrawl/
    ├── domains.txt.gz           # Current index (gzipped, ~500MB)
    ├── domains-2024-01.txt.gz   # Monthly backup
    ├── domains-2024-02.txt.gz   # Monthly backup
    └── metadata.json            # Index metadata
```

## Estimated Sizes

| Metric | Value |
|--------|-------|
| Domains indexed | 10-50 million |
| Compressed size | 200-500 MB |
| Uncompressed | 1-3 GB |
| Memory usage | ~2 GB when loaded |
| Lookup time | <100ms |

## IAM Policy

The application needs these S3 permissions:

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
                "arn:aws:s3:::your-bucket/commoncrawl/*"
            ]
        }
    ]
}
```

## Troubleshooting

### Index not loading
```bash
# Check if index exists in S3
aws s3 ls s3://your-bucket/commoncrawl/

# Check metadata
aws s3 cp s3://your-bucket/commoncrawl/metadata.json -
```

### Sync failing
```bash
# Check IAM permissions
aws s3 cp s3://your-bucket/commoncrawl/metadata.json /tmp/test.json

# Check environment variables
echo $CC_S3_BUCKET
```

### Memory issues
If the index is too large for your container:
1. Increase container memory limits
2. Reduce `max_domains` in update-index.py
3. Use streaming search instead of loading all into memory

