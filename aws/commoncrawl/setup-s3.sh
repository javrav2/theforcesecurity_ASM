#!/bin/bash
# =============================================================================
# Setup S3 Bucket for Common Crawl Index
# =============================================================================
# This script creates an S3 bucket to store the pre-processed Common Crawl
# domain index for fast subdomain lookups.
#
# Usage:
#   ./setup-s3.sh my-asm-commoncrawl-bucket us-east-1
# =============================================================================

set -e

BUCKET_NAME="${1:-asm-commoncrawl-$(date +%Y%m%d)}"
REGION="${2:-us-east-1}"

echo "Creating S3 bucket: $BUCKET_NAME in $REGION"

# Create bucket
if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION"
else
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" \
        --create-bucket-configuration LocationConstraint="$REGION"
fi

# Enable versioning (for rollback capability)
aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled

# Add lifecycle rule to clean old versions after 30 days
cat > /tmp/lifecycle.json << 'EOF'
{
    "Rules": [
        {
            "ID": "CleanOldVersions",
            "Status": "Enabled",
            "Filter": {
                "Prefix": "commoncrawl/"
            },
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 30
            }
        }
    ]
}
EOF

aws s3api put-bucket-lifecycle-configuration \
    --bucket "$BUCKET_NAME" \
    --lifecycle-configuration file:///tmp/lifecycle.json

rm /tmp/lifecycle.json

# Block public access
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo ""
echo "✅ S3 bucket created successfully!"
echo ""
echo "Bucket: $BUCKET_NAME"
echo "Region: $REGION"
echo ""
echo "Add this to your .env file:"
echo "  CC_S3_BUCKET=$BUCKET_NAME"
echo "  AWS_REGION=$REGION"
echo ""
echo "Next steps:"
echo "  1. Run the index builder to populate the bucket"
echo "  2. Set up EventBridge rule for monthly updates"
echo ""

