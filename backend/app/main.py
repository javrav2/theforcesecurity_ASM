"""Main FastAPI application entry point."""

import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import or_

from app.core.config import settings
from app.db.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.models.netblock import Netblock  # Import to ensure table creation
from app.api.routes import auth, users, organizations, assets, vulnerabilities, scans, discovery, nuclei, ports, screenshots, external_discovery, waybackurls, netblocks, labels, scan_schedules, tools, sni_discovery, scan_config, acquisitions, remediation, exceptions

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

# Configure CORS - allow all origins for flexibility with different deployment scenarios
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins - required for dynamic IP/hostname access
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
app.include_router(screenshots.router, prefix=settings.API_PREFIX)
app.include_router(external_discovery.router, prefix=settings.API_PREFIX)
app.include_router(waybackurls.router, prefix=settings.API_PREFIX)
app.include_router(netblocks.router, prefix=settings.API_PREFIX)
app.include_router(labels.router, prefix=settings.API_PREFIX)
app.include_router(scan_schedules.router, prefix=settings.API_PREFIX)
app.include_router(tools.router, prefix=settings.API_PREFIX)
app.include_router(sni_discovery.router, prefix=settings.API_PREFIX)
app.include_router(scan_config.router, prefix=settings.API_PREFIX)
app.include_router(acquisitions.router, prefix=settings.API_PREFIX)
app.include_router(remediation.router, prefix=settings.API_PREFIX)
app.include_router(exceptions.router, prefix=settings.API_PREFIX)


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
            "screenshots": f"{settings.API_PREFIX}/screenshots",
            "external_discovery": f"{settings.API_PREFIX}/external-discovery",
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
    
    # Check EyeWitness installation
    from app.services.eyewitness_service import get_eyewitness_service
    eyewitness = get_eyewitness_service()
    ew_status = eyewitness.check_installation()
    if ew_status["installed"]:
        logger.info("✓ EyeWitness is installed")
    else:
        logger.warning(f"✗ EyeWitness is not installed - screenshots unavailable: {ew_status.get('error', '')}")

    ensure_default_admin()


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown."""
    logger.info("Shutting down application")


def ensure_default_admin():
    """Ensure a known-good admin account exists and is usable."""
    default_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@theforce.security")
    default_username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

    db = SessionLocal()
    try:
        user = (
            db.query(User)
            .filter(or_(User.username == default_username, User.email == default_email))
            .first()
        )

        if not user:
            user = User(
                email=default_email,
                username=default_username,
                hashed_password=get_password_hash(default_password),
                full_name="System Administrator",
                role=UserRole.ADMIN,
                is_superuser=True,
                is_active=True,
            )
            db.add(user)
            db.commit()
            logger.info("Created default admin user with configured credentials.")
            return

        updated = False
        if not user.username:
            user.username = default_username
            updated = True
        if not user.email:
            user.email = default_email
            updated = True
        if not user.is_superuser:
            user.is_superuser = True
            updated = True
        if not user.is_active:
            user.is_active = True
            updated = True
        if user.role != UserRole.ADMIN:
            user.role = UserRole.ADMIN
            updated = True

        if updated:
            db.add(user)
            db.commit()
            logger.info("Default admin user validated/updated with configured credentials.")
        else:
            logger.info("Default admin user already valid.")
    except Exception as exc:  # pragma: no cover - startup logging path
        logger.error(f"Failed to ensure default admin user: {exc}")
    finally:
        db.close()
