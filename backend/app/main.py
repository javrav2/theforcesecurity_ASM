"""Main FastAPI application entry point."""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.db.database import engine, Base
from app.api.routes import auth, users, organizations, assets, vulnerabilities, scans, discovery, nuclei, ports

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
# The Force Security - Attack Surface Management API

A comprehensive platform for discovering and managing your organization's external attack surface.

## Features

- **Asset Discovery**: Automatically discover domains, subdomains, IPs, and URLs
- **Port & Service Tracking**: Track exposed ports with port-protocol-service structure
- **Technology Fingerprinting**: Identify web technologies using Wappalyzer-style detection
- **Vulnerability Scanning**: Run Nuclei scans with configurable profiles
- **ProjectDiscovery Tools**: Integrated subfinder, httpx, dnsx, naabu, katana
- **Multi-tenant**: Support for multiple organizations with RBAC

## Port & Service Reporting

Track and report on exposed services with structured data:
- **Format**: `port-protocol-service` (e.g., `443-tcp-https`, `22-tcp-ssh`)
- **Reports**: Distribution by port, service, risky ports summary
- **Risk Flagging**: Automatic flagging of dangerous ports
    """,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(users.router, prefix=settings.API_PREFIX)
app.include_router(organizations.router, prefix=settings.API_PREFIX)
app.include_router(assets.router, prefix=settings.API_PREFIX)
app.include_router(vulnerabilities.router, prefix=settings.API_PREFIX)
app.include_router(scans.router, prefix=settings.API_PREFIX)
app.include_router(discovery.router, prefix=settings.API_PREFIX)
app.include_router(nuclei.router, prefix=settings.API_PREFIX)
app.include_router(ports.router, prefix=settings.API_PREFIX)


@app.get("/")
def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "Attack Surface Management API with Nuclei Integration",
        "docs": "/api/docs"
    }


@app.get("/health")
def health_check():
    """Health check endpoint for container orchestration."""
    return {"status": "healthy"}


@app.get("/api/v1")
def api_info():
    """API information endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "endpoints": {
            "auth": f"{settings.API_PREFIX}/auth",
            "users": f"{settings.API_PREFIX}/users",
            "organizations": f"{settings.API_PREFIX}/organizations",
            "assets": f"{settings.API_PREFIX}/assets",
            "ports": f"{settings.API_PREFIX}/ports",
            "vulnerabilities": f"{settings.API_PREFIX}/vulnerabilities",
            "scans": f"{settings.API_PREFIX}/scans",
            "discovery": f"{settings.API_PREFIX}/discovery",
            "nuclei": f"{settings.API_PREFIX}/nuclei",
        },
        "port_service_features": {
            "list_ports": "GET /api/v1/ports - List all port services",
            "by_asset": "GET /api/v1/ports/report/by-asset/{id} - Ports for specific asset",
            "port_distribution": "GET /api/v1/ports/report/distribution/ports - Port distribution",
            "service_distribution": "GET /api/v1/ports/report/distribution/services - Service distribution",
            "risky_ports": "GET /api/v1/ports/report/risky - Risky ports report",
            "summary": "GET /api/v1/ports/report/summary - Comprehensive summary",
            "search": "POST /api/v1/ports/search - Advanced port search",
        }
    }


@app.on_event("startup")
async def startup_event():
    """Run on application startup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("API documentation available at /api/docs")
    
    # Check ProjectDiscovery tools installation
    from app.services.nuclei_service import NucleiService
    from app.services.projectdiscovery_service import ProjectDiscoveryService
    
    nuclei = NucleiService()
    pd_tools = ProjectDiscoveryService()
    
    if nuclei.check_installation():
        logger.info("✓ Nuclei is installed")
    else:
        logger.warning("✗ Nuclei is not installed - vulnerability scanning unavailable")
    
    tools_status = pd_tools.check_tools()
    for tool, installed in tools_status.items():
        if installed:
            logger.info(f"✓ {tool} is installed")
        else:
            logger.warning(f"✗ {tool} is not installed")


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown."""
    logger.info("Shutting down application")
