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
from app.models.finding_exception import FindingException  # Required for Vulnerability relationship resolution
from app.api.routes import auth, users, organizations, assets, vulnerabilities, scans, discovery, nuclei, ports, screenshots, external_discovery, waybackurls, netblocks, labels, scan_schedules, tools, sni_discovery, scan_config, acquisitions, oracle, agent

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
app.include_router(sni_discovery.router, prefix=settings.API_PREFIX)
app.include_router(scan_config.router, prefix=settings.API_PREFIX)
app.include_router(acquisitions.router, prefix=settings.API_PREFIX)
app.include_router(oracle.router, prefix=settings.API_PREFIX)
app.include_router(agent.router, prefix=settings.API_PREFIX)


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
    """Ensure the oracle schema and its tables exist with the correct structure.

    Uses CREATE TABLE IF NOT EXISTS so it is safe to run on every startup.
    Column names and types exactly match what the Go aegis-oracle service
    reads/writes (see aegis-oracle/internal/store/pg/store.go).
    """
    from sqlalchemy import text

    # Each statement is run independently so one failure does not block others.
    ddl_statements = [
        "CREATE SCHEMA IF NOT EXISTS oracle",

        # Raw ingest tables
        """CREATE TABLE IF NOT EXISTS oracle.raw_cvelistv5 (
            cve_id     text        NOT NULL,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            payload    jsonb       NOT NULL,
            PRIMARY KEY (cve_id, fetched_at)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_nvd (
            cve_id     text        NOT NULL,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            payload    jsonb       NOT NULL,
            PRIMARY KEY (cve_id, fetched_at)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_osv (
            osv_id     text        NOT NULL,
            cve_id     text,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            payload    jsonb       NOT NULL,
            PRIMARY KEY (osv_id, fetched_at)
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_raw_osv_cve_idx ON oracle.raw_osv (cve_id) WHERE cve_id IS NOT NULL",
        """CREATE TABLE IF NOT EXISTS oracle.raw_epss (
            cve_id     text         NOT NULL,
            scored_on  date         NOT NULL,
            score      numeric(5,4) NOT NULL,
            percentile numeric(5,4) NOT NULL,
            PRIMARY KEY (cve_id, scored_on)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_kev (
            cve_id          text PRIMARY KEY,
            added_on        date NOT NULL DEFAULT CURRENT_DATE,
            vendor          text,
            product         text,
            required_action text,
            ransomware_use  boolean,
            fetched_at      timestamptz NOT NULL DEFAULT now()
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_pocs (
            cve_id     text        NOT NULL,
            source     text        NOT NULL,
            url        text        NOT NULL,
            title      text,
            stars      int,
            pushed_at  timestamptz,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (cve_id, source, url)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_hackerone_reports (
            report_id    text PRIMARY KEY,
            cve_id       text,
            url          text NOT NULL,
            title        text,
            cvss_vector  text,
            cvss_score   numeric(3,1),
            severity     text,
            reporter     text,
            team         text,
            disclosed_at timestamptz,
            body_text    text,
            fetched_at   timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_raw_hackerone_cve_idx ON oracle.raw_hackerone_reports (cve_id) WHERE cve_id IS NOT NULL",

        # Canonical CVE table — column names must match store.go SELECT/INSERT
        """CREATE TABLE IF NOT EXISTS oracle.cves (
            cve_id               text PRIMARY KEY,
            published_at         timestamptz NOT NULL DEFAULT now(),
            modified_at          timestamptz NOT NULL DEFAULT now(),
            description          text NOT NULL DEFAULT '',
            cwes                 text[] NOT NULL DEFAULT '{}',
            cpes                 jsonb NOT NULL DEFAULT '[]',
            cvss_vectors         jsonb NOT NULL DEFAULT '[]',
            reference_urls       text[] NOT NULL DEFAULT '{}',
            epss_score           numeric(5,4),
            epss_percentile      numeric(5,4),
            in_kev               boolean NOT NULL DEFAULT false,
            kev_added_on         date,
            nuclei_template      text,
            poc_count            int NOT NULL DEFAULT 0,
            primary_source       text NOT NULL DEFAULT 'cve.org',
            adp_enrichment       jsonb,
            ghsa_id              text,
            osv_ids              text[] NOT NULL DEFAULT '{}',
            source_versions      jsonb NOT NULL DEFAULT '{}',
            intrinsic_input_hash text,
            updated_at           timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_cves_modified_at_idx ON oracle.cves (modified_at DESC)",
        "CREATE INDEX IF NOT EXISTS oracle_cves_kev_idx ON oracle.cves (in_kev) WHERE in_kev",
        "CREATE INDEX IF NOT EXISTS oracle_cves_epss_high_idx ON oracle.cves (epss_score DESC) WHERE epss_score > 0.5",

        """CREATE TABLE IF NOT EXISTS oracle.reference_content (
            url           text PRIMARY KEY,
            cve_ids       text[] NOT NULL DEFAULT '{}',
            source_kind   text NOT NULL DEFAULT '',
            content_text  text,
            content_hash  text NOT NULL DEFAULT '',
            http_status   int,
            fetched_at    timestamptz NOT NULL DEFAULT now(),
            fetch_error   text
        )""",

        """CREATE TABLE IF NOT EXISTS oracle.exploitation_observations (
            cve_id        text NOT NULL,
            source        text NOT NULL,
            first_seen_at timestamptz NOT NULL DEFAULT now(),
            evidence_url  text,
            notes         text,
            PRIMARY KEY (cve_id, source)
        )""",

        # Phase A intrinsic analyses
        """CREATE TABLE IF NOT EXISTS oracle.cve_intrinsic_analyses (
            cve_id                text NOT NULL,
            input_hash            text NOT NULL,
            prompt_version        text NOT NULL,
            llm_provider          text NOT NULL DEFAULT '',
            llm_model             text NOT NULL DEFAULT '',
            remote_triggerability text NOT NULL DEFAULT '',
            exploit_complexity    text NOT NULL DEFAULT '',
            attacker_capability   text NOT NULL DEFAULT '',
            preconditions         jsonb NOT NULL DEFAULT '[]',
            cvss_reconciliation   jsonb NOT NULL DEFAULT '{}',
            attack_chain_summary  text NOT NULL DEFAULT '',
            detection_signals     jsonb NOT NULL DEFAULT '[]',
            rationale             text NOT NULL DEFAULT '',
            confidence            text NOT NULL DEFAULT '',
            token_usage           jsonb,
            cost_usd              numeric(8,4),
            created_at            timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (cve_id, input_hash, prompt_version)
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_cve_intrinsic_latest_idx ON oracle.cve_intrinsic_analyses (cve_id, created_at DESC)",

        # Knowledge base
        """CREATE TABLE IF NOT EXISTS oracle.cwe_profiles (
            cwe_id             text PRIMARY KEY,
            name               text NOT NULL DEFAULT '',
            abstraction        text NOT NULL DEFAULT '',
            parent_cwes        text[] NOT NULL DEFAULT '{}',
            exploit_archetypes jsonb NOT NULL DEFAULT '[]',
            ecosystem_notes    jsonb NOT NULL DEFAULT '{}',
            framework_notes    jsonb NOT NULL DEFAULT '{}',
            detection_signals  jsonb NOT NULL DEFAULT '[]',
            curator_notes      text,
            source_refs        text[] NOT NULL DEFAULT '{}',
            last_reviewed_at   timestamptz,
            reviewed_by        text,
            yaml_hash          text NOT NULL DEFAULT '',
            loaded_at          timestamptz NOT NULL DEFAULT now()
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.dev_patterns (
            pattern_id            text PRIMARY KEY,
            cwe_ids               text[] NOT NULL DEFAULT '{}',
            ecosystem             text NOT NULL DEFAULT '',
            framework             text,
            library               text,
            pattern_name          text NOT NULL DEFAULT '',
            summary               text NOT NULL DEFAULT '',
            exploit_preconditions jsonb NOT NULL DEFAULT '[]',
            code_indicators       text[] NOT NULL DEFAULT '{}',
            config_indicators     text[] NOT NULL DEFAULT '{}',
            runtime_indicators    text[] NOT NULL DEFAULT '{}',
            attacker_capability   text NOT NULL DEFAULT '',
            remote_triggerability text NOT NULL DEFAULT '',
            vulnerable_example    text,
            secure_example        text,
            remediation_summary   text NOT NULL DEFAULT '',
            references_           text[] NOT NULL DEFAULT '{}',
            related_cves          text[] NOT NULL DEFAULT '{}',
            curator               text NOT NULL DEFAULT '',
            reviewed_at           timestamptz NOT NULL DEFAULT now(),
            yaml_hash             text NOT NULL DEFAULT '',
            loaded_at             timestamptz NOT NULL DEFAULT now()
        )""",

        # Assets
        """CREATE TABLE IF NOT EXISTS oracle.assets (
            asset_id     text PRIMARY KEY,
            tenant_id    text,
            hostname     text,
            ip           inet,
            open_ports   int[] NOT NULL DEFAULT '{}',
            signals      jsonb NOT NULL DEFAULT '{}',
            signals_hash text NOT NULL DEFAULT '',
            criticality  text NOT NULL DEFAULT 'unknown',
            exposure     text NOT NULL DEFAULT 'unknown',
            source       text NOT NULL DEFAULT 'asm',
            updated_at   timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_assets_signals_gin ON oracle.assets USING gin (signals jsonb_path_ops)",

        # Findings (Phase B output)
        """CREATE TABLE IF NOT EXISTS oracle.findings (
            finding_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            cve_id                  text NOT NULL,
            asset_id                text NOT NULL,
            intrinsic_input_hash    text NOT NULL DEFAULT '',
            asset_signals_hash      text NOT NULL DEFAULT '',
            evaluator_version       text NOT NULL DEFAULT '',
            preconditions_evaluated jsonb NOT NULL DEFAULT '[]',
            opes_score              numeric(3,1) NOT NULL DEFAULT 0,
            opes_category           text NOT NULL DEFAULT 'P4',
            opes_label              text NOT NULL DEFAULT '',
            opes_components         jsonb NOT NULL DEFAULT '{}',
            opes_top_contributors   jsonb NOT NULL DEFAULT '[]',
            opes_dampener           text,
            opes_override           text,
            confidence              text NOT NULL DEFAULT 'low',
            priority_rationale      text NOT NULL DEFAULT '',
            recommendation_text     text NOT NULL DEFAULT '',
            cvss_reconciliation     jsonb,
            analyst_brief           jsonb,
            status                  text NOT NULL DEFAULT 'open',
            superseded_by           uuid,
            created_at              timestamptz NOT NULL DEFAULT now(),
            updated_at              timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_findings_open_priority_idx ON oracle.findings (opes_category, created_at DESC) WHERE status = 'open'",
        "CREATE INDEX IF NOT EXISTS oracle_findings_asset_open_idx ON oracle.findings (asset_id) WHERE status = 'open'",
        "CREATE INDEX IF NOT EXISTS oracle_findings_cve_idx ON oracle.findings (cve_id)",

        # Verification tasks
        """CREATE TABLE IF NOT EXISTS oracle.verification_tasks (
            task_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_id           uuid NOT NULL,
            precondition_id      text NOT NULL DEFAULT '',
            task_kind            text NOT NULL DEFAULT 'manual',
            command              text,
            expected_signal_path text NOT NULL DEFAULT '',
            expected_match       text,
            external_ref         text,
            status               text NOT NULL DEFAULT 'open',
            resolution_notes     text,
            signal_value         text,
            created_at           timestamptz NOT NULL DEFAULT now(),
            resolved_at          timestamptz
        )""",

        # Module state
        """CREATE TABLE IF NOT EXISTS oracle.module_state (
            module_name text NOT NULL,
            key         text NOT NULL,
            value       jsonb NOT NULL DEFAULT '{}',
            updated_at  timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (module_name, key)
        )""",
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
