#!/bin/bash
# =============================================================================
# ASM Platform - AWS Deployment Script
# =============================================================================
# 
# Usage:
#   ./deploy.sh [api|scanner|all] [environment]
#
# Examples:
#   ./deploy.sh all prod        # Deploy all services to production
#   ./deploy.sh api staging     # Deploy only API to staging
#   ./deploy.sh scanner prod    # Deploy only scanner workers
# =============================================================================

set -euo pipefail

# Configuration
COMPONENT="${1:-all}"
ENVIRONMENT="${2:-prod}"
AWS_REGION="${AWS_REGION:-us-east-1}"
PROJECT_NAME="${PROJECT_NAME:-asm}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

log "Deploying to AWS Account: ${AWS_ACCOUNT_ID}"
log "Region: ${AWS_REGION}"
log "Environment: ${ENVIRONMENT}"
log "Component: ${COMPONENT}"

# Login to ECR
log "Logging into ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REGISTRY}

# Build and push API image
build_api() {
    log "Building API image..."
    
    cd ../../backend
    
    docker build \
        --platform linux/amd64 \
        -t ${PROJECT_NAME}/api:latest \
        -t ${PROJECT_NAME}/api:${ENVIRONMENT}-$(git rev-parse --short HEAD) \
        -f Dockerfile \
        .
    
    # Tag for ECR
    docker tag ${PROJECT_NAME}/api:latest ${ECR_REGISTRY}/${PROJECT_NAME}/api:latest
    docker tag ${PROJECT_NAME}/api:latest ${ECR_REGISTRY}/${PROJECT_NAME}/api:${ENVIRONMENT}-$(git rev-parse --short HEAD)
    
    log "Pushing API image to ECR..."
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/api:latest
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/api:${ENVIRONMENT}-$(git rev-parse --short HEAD)
    
    cd ../aws/scripts
}

# Build and push Scanner image
build_scanner() {
    log "Building Scanner image..."
    
    cd ../../backend
    
    docker build \
        --platform linux/amd64 \
        -t ${PROJECT_NAME}/scanner:latest \
        -t ${PROJECT_NAME}/scanner:${ENVIRONMENT}-$(git rev-parse --short HEAD) \
        -f Dockerfile.scanner \
        .
    
    # Tag for ECR
    docker tag ${PROJECT_NAME}/scanner:latest ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:latest
    docker tag ${PROJECT_NAME}/scanner:latest ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:${ENVIRONMENT}-$(git rev-parse --short HEAD)
    
    log "Pushing Scanner image to ECR..."
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:latest
    docker push ${ECR_REGISTRY}/${PROJECT_NAME}/scanner:${ENVIRONMENT}-$(git rev-parse --short HEAD)
    
    cd ../aws/scripts
}

# Deploy API service
deploy_api() {
    log "Deploying API service..."
    
    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service ${PROJECT_NAME}-api \
        --force-new-deployment \
        --region ${AWS_REGION}
    
    log "Waiting for API deployment to stabilize..."
    aws ecs wait services-stable \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${PROJECT_NAME}-api \
        --region ${AWS_REGION}
    
    log "API deployment complete!"
}

# Deploy Scanner service
deploy_scanner() {
    log "Deploying Scanner service..."
    
    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service ${PROJECT_NAME}-scanner \
        --force-new-deployment \
        --region ${AWS_REGION}
    
    log "Waiting for Scanner deployment to stabilize..."
    aws ecs wait services-stable \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${PROJECT_NAME}-scanner \
        --region ${AWS_REGION}
    
    log "Scanner deployment complete!"
}

# Run database migrations
run_migrations() {
    log "Running database migrations..."
    
    # Get task definition ARN
    TASK_DEF=$(aws ecs describe-services \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${PROJECT_NAME}-api \
        --query 'services[0].taskDefinition' \
        --output text \
        --region ${AWS_REGION})
    
    # Get subnets and security groups from service
    NETWORK_CONFIG=$(aws ecs describe-services \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${PROJECT_NAME}-api \
        --query 'services[0].networkConfiguration.awsvpcConfiguration' \
        --region ${AWS_REGION})
    
    SUBNETS=$(echo $NETWORK_CONFIG | jq -r '.subnets | join(",")')
    SECURITY_GROUPS=$(echo $NETWORK_CONFIG | jq -r '.securityGroups | join(",")')
    
    # Run migration task
    aws ecs run-task \
        --cluster ${PROJECT_NAME}-cluster \
        --task-definition ${TASK_DEF} \
        --network-configuration "awsvpcConfiguration={subnets=[${SUBNETS}],securityGroups=[${SECURITY_GROUPS}],assignPublicIp=DISABLED}" \
        --overrides '{"containerOverrides":[{"name":"api","command":["python","-m","alembic","upgrade","head"]}]}' \
        --region ${AWS_REGION}
    
    log "Migrations started"
}

# Main deployment logic
case ${COMPONENT} in
    api)
        build_api
        deploy_api
        ;;
    scanner)
        build_scanner
        deploy_scanner
        ;;
    all)
        build_api
        build_scanner
        deploy_api
        deploy_scanner
        ;;
    migrate)
        run_migrations
        ;;
    build)
        build_api
        build_scanner
        ;;
    *)
        error "Unknown component: ${COMPONENT}. Use: api, scanner, all, migrate, or build"
        ;;
esac

log "Deployment complete!"

# Print service URLs
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --names ${PROJECT_NAME}-alb \
    --query 'LoadBalancers[0].DNSName' \
    --output text \
    --region ${AWS_REGION} 2>/dev/null || echo "ALB not found")

if [ "${ALB_DNS}" != "ALB not found" ]; then
    log "API is available at: http://${ALB_DNS}:8080"
    log "API Docs: http://${ALB_DNS}:8080/docs"
fi















