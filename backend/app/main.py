"""Main FastAPI application entry point."""

import logging
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.db.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.models.netblock import Netblock  # Import to ensure table creation
from app.api.routes import auth, users, organizations, assets, vulnerabilities, scans, discovery, nuclei, ports, screenshots, external_discovery, waybackurls, netblocks, labels, scan_schedules, tools, endpoints, sni_discovery, scan_config, acquisitions, oracle

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
- **Aegis Oracle**: OPES exploitability scoring, attack-path classification, analyst briefs
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


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_error_handler(request: Request, exc: SQLAlchemyError):
    logger.error("Database error on %s: %s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "A database error occurred."})


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "An internal server error occurred."})


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
app.include_router(endpoints.router, prefix=settings.API_PREFIX)
app.include_router(sni_discovery.router, prefix=settings.API_PREFIX)
app.include_router(scan_config.router, prefix=settings.API_PREFIX)
app.include_router(acquisitions.router, prefix=settings.API_PREFIX)
app.include_router(oracle.router, prefix=settings.API_PREFIX)


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
            "oracle": f"{settings.API_PREFIX}/oracle",
        },
    }


@app.on_event("startup")
async def startup_event():
    """Run on application startup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("API documentation available at /api/docs")

    # Apply Oracle schema migrations so the Go service's tables exist
    apply_oracle_migrations()

    # Check ProjectDiscovery tools installation
    from app.services.nuclei_service import NucleiService
    from app.services.projectdiscovery_service import ProjectDiscoveryService

    nuclei_svc = NucleiService()
    pd_tools = ProjectDiscoveryService()

    if nuclei_svc.check_installation():
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
        logger.warning(f"✗ EyeWitness is not installed: {ew_status.get('error', '')}")

    ensure_default_admin()


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown."""
    logger.info("Shutting down application")


def apply_oracle_migrations():
    """Ensure the oracle schema and its tables exist.

    The Go aegis-oracle service expects these tables but does not create them
    itself. We create them idempotently at startup so a fresh DB just works.
    """
    from sqlalchemy import text
    ddl_statements = [
        "CREATE SCHEMA IF NOT EXISTS oracle",
        """
        CREATE TABLE IF NOT EXISTS oracle.cves (
            cve_id              text PRIMARY KEY,
            published           timestamptz,
            modified            timestamptz,
            description         text NOT NULL DEFAULT '',
            cvss_v3_score       real,
            cvss_v3_vector      text NOT NULL DEFAULT '',
            cvss_v2_score       real,
            cvss_v2_vector      text NOT NULL DEFAULT '',
            epss_score          real,
            epss_percentile     real,
            kev_listed          boolean NOT NULL DEFAULT false,
            kev_date_added      date,
            cwe_ids             text[] NOT NULL DEFAULT '{}',
            affected_products   jsonb NOT NULL DEFAULT '[]',
            references_         jsonb NOT NULL DEFAULT '[]',
            raw_nvd             jsonb,
            fetched_at          timestamptz NOT NULL DEFAULT now(),
            created_at          timestamptz NOT NULL DEFAULT now(),
            updated_at          timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oracle.cve_intrinsic_analyses (
            id                      bigserial PRIMARY KEY,
            cve_id                  text NOT NULL REFERENCES oracle.cves(cve_id) ON DELETE CASCADE,
            remote_triggerability   text NOT NULL DEFAULT '',
            exploit_complexity      text NOT NULL DEFAULT '',
            attacker_capability     text NOT NULL DEFAULT '',
            attack_path_class       text NOT NULL DEFAULT '',
            lateral_movement        text NOT NULL DEFAULT '',
            preconditions           jsonb NOT NULL DEFAULT '[]',
            cvss_reconciliation     jsonb,
            attack_chain_summary    text NOT NULL DEFAULT '',
            analyst_brief           jsonb,
            detection_signals       jsonb NOT NULL DEFAULT '[]',
            rationale               text NOT NULL DEFAULT '',
            confidence              text NOT NULL DEFAULT '',
            prompt_version          text NOT NULL DEFAULT '',
            llm_model               text NOT NULL DEFAULT '',
            created_at              timestamptz NOT NULL DEFAULT now(),
            updated_at              timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oracle.assets (
            asset_id        text PRIMARY KEY,
            hostname        text NOT NULL DEFAULT '',
            ip_addresses    text[] NOT NULL DEFAULT '{}',
            ports           jsonb NOT NULL DEFAULT '[]',
            technologies    text[] NOT NULL DEFAULT '{}',
            network_zone    text NOT NULL DEFAULT '',
            signals_hash    text NOT NULL DEFAULT '',
            created_at      timestamptz NOT NULL DEFAULT now(),
            updated_at      timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oracle.findings (
            finding_id              text PRIMARY KEY,
            cve_id                  text,
            asset_id                text,
            cve_hash                text NOT NULL DEFAULT '',
            asset_hash              text NOT NULL DEFAULT '',
            signals_hash            text NOT NULL DEFAULT '',
            evaluator_version       text NOT NULL DEFAULT '',
            preconditions_evaluated jsonb NOT NULL DEFAULT '[]',
            opes                    jsonb NOT NULL DEFAULT '{}',
            cvss_reconciliation     jsonb,
            analyst_brief           jsonb,
            attack_path_class       text NOT NULL DEFAULT '',
            lateral_movement_potential text NOT NULL DEFAULT '',
            recommendation_text     text NOT NULL DEFAULT '',
            verification_tasks      jsonb NOT NULL DEFAULT '[]',
            confidence              text NOT NULL DEFAULT '',
            priority_rationale      text NOT NULL DEFAULT '',
            status                  text NOT NULL DEFAULT 'open'
                                    CHECK (status IN ('open','verifying','suppressed','fixed','superseded')),
            created_at              timestamptz NOT NULL DEFAULT now(),
            updated_at              timestamptz NOT NULL DEFAULT now()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oracle.module_state (
            module      text PRIMARY KEY,
            last_run    timestamptz,
            state       jsonb NOT NULL DEFAULT '{}'
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oracle.raw_kev (
            cve_id          text PRIMARY KEY,
            date_added      date,
            vendor_project  text,
            product         text,
            vulnerability_name text,
            short_description text,
            required_action text,
            due_date        date,
            notes           text,
            fetched_at      timestamptz NOT NULL DEFAULT now()
        )
        """,
        # Idempotently add columns that older migrations may have omitted
        "ALTER TABLE oracle.findings ADD COLUMN IF NOT EXISTS cvss_reconciliation jsonb",
        "ALTER TABLE oracle.findings ADD COLUMN IF NOT EXISTS analyst_brief jsonb",
    ]

    try:
        with engine.connect() as conn:
            for stmt in ddl_statements:
                try:
                    conn.execute(text(stmt))
                except Exception as e:
                    logger.warning("oracle migration stmt skipped: %s", e)
            conn.commit()
        logger.info("Oracle schema migrations applied.")
    except Exception as exc:
        logger.error("Oracle schema migrations failed (non-fatal): %s", exc)


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
            logger.info("Default admin user validated/updated.")
        else:
            logger.info("Default admin user already valid.")
    except Exception as exc:
        logger.error(f"Failed to ensure default admin user: {exc}")
    finally:
        db.close()
