"""
Project / Organization scan and agent settings (per-org).

Stores 180+ configurable parameters per organization, grouped by module.
Each module's config is a JSON object; workers and the agent read these at runtime.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


# Module names for project settings (per-org)
MODULE_TARGET = "target"
MODULE_PORT_SCANNER = "port_scanner"
MODULE_HTTP_PROBER = "http_prober"
MODULE_WAPPALYZER = "wappalyzer"
MODULE_BANNER_GRABBING = "banner_grabbing"
MODULE_KATANA = "katana"
MODULE_PASSIVE_URL = "passive_url"
MODULE_API_DISCOVERY = "api_discovery"
MODULE_NUCLEI = "nuclei"
MODULE_CVE_ENRICHMENT = "cve_enrichment"
MODULE_MITRE_MAPPING = "mitre_mapping"
MODULE_SECURITY_CHECKS = "security_checks"
MODULE_AGENT = "agent"
MODULE_SCAN_TOGGLES = "scan_toggles"

ALL_MODULES = [
    MODULE_TARGET,
    MODULE_PORT_SCANNER,
    MODULE_HTTP_PROBER,
    MODULE_WAPPALYZER,
    MODULE_BANNER_GRABBING,
    MODULE_KATANA,
    MODULE_PASSIVE_URL,
    MODULE_API_DISCOVERY,
    MODULE_NUCLEI,
    MODULE_CVE_ENRICHMENT,
    MODULE_MITRE_MAPPING,
    MODULE_SECURITY_CHECKS,
    MODULE_AGENT,
    MODULE_SCAN_TOGGLES,
]


def default_target_config():
    return {
        "target_domain": None,
        "subdomain_list": [],
        "verify_domain_ownership": False,
        "use_tor": False,
        "use_bruteforce": True,
    }


def default_port_scanner_config():
    return {
        "scan_type": "c",  # CONNECT (c) vs SYN (s)
        "top_ports": 1000,
        "custom_ports": [],
        "rate_limit": 1000,
        "thread_count": 25,
        "cdn_exclusion": True,
        "passive_shodan": False,
        "skip_host_discovery": False,
    }


def default_http_prober_config():
    return {
        "follow_redirects": True,
        "max_redirects": 5,
        "timeout": 10,
        "rate_limit": 150,
        "status_code_probe": True,
        "tech_detection": True,
        "tls_probe": True,
        "favicon_hash": True,
        "jarm_fingerprint": False,
        "asn_cdn_detection": True,
        "include_response_body": False,
        "custom_headers": {},
    }


def default_wappalyzer_config():
    return {
        "enabled": True,
        "min_confidence_threshold": 0,  # 0-100
        "require_html": False,  # Skip if no HTML body
        "auto_update_npm": False,
        "cache_ttl_seconds": 86400,  # 24h
    }


def default_banner_grabbing_config():
    return {
        "enabled": True,
        "timeout_seconds": 5,
        "thread_count": 10,
        "max_banner_length": 1024,
    }


def default_katana_config():
    return {
        "enabled": True,
        "crawl_depth": 3,
        "max_urls_per_domain": 500,
        "js_rendering": False,
        "scope": "subdomain",  # exact_domain | root_domain | subdomain
        "rate_limit": 150,
        "exclude_patterns": [],  # or use 100+ default patterns
    }


def default_passive_url_config():
    return {
        "enabled": True,
        "providers": ["wayback", "commoncrawl"],
        "max_urls_per_domain": 10000,
        "year_range": None,
        "verify_with_httpx": True,
        "httpx_rate_limit": 150,
        "dead_endpoint_filter": True,
        "file_extension_blacklist": [],
    }


def default_api_discovery_config():
    return {
        "enabled": False,
        "wordlist": "routes-small",
        "rate_limit": 100,
        "connection_count": 5,
        "status_code_whitelist": [200, 201, 204],
        "min_content_length": 0,
        "method_detection": "options",
    }


def default_nuclei_config():
    return {
        "severity": ["critical", "high", "medium", "low", "info"],
        "dast_mode": False,
        "template_include": [],
        "template_exclude": [],
        "exclude_tags": [],
        "rate_limit": 150,
        "concurrency": 25,
        "bulk_size": 25,
        "timeout": 10,
        "interactsh": False,
        "headless": False,
        "follow_redirects": True,
        "template_auto_update": True,
    }


def default_cve_enrichment_config():
    return {
        "enabled": True,
        "data_source": "nvd",  # nvd | vulners
        "max_cves_per_finding": 10,
        "min_cvss_score": 0,
        "api_keys": {},
    }


def default_mitre_mapping_config():
    return {
        "auto_update": True,
        "cwe_inclusion": True,
        "capec_inclusion": True,
        "cache_ttl_seconds": 86400,
    }


def default_security_checks_config():
    return {
        "network_exposure": True,
        "tls_certificate": True,
        "cert_expiry_days": 30,
        "security_headers": True,
        "authentication_checks": True,
        "dns_security": True,
        "exposed_services": True,
        "application_checks": True,
    }


def default_agent_config():
    return {
        "llm_provider": "anthropic",  # openai | anthropic (Claude)
        "llm_model": "claude-sonnet-4-20250514",
        "max_iterations": 100,
        "require_approval_exploitation": True,
        "require_approval_post_exploitation": True,
        "activate_post_exploitation": True,
        "post_exploitation_type": "stateless",  # stateful | stateless
        "lhost": None,
        "lport": 4444,
        "bind_port_on_target": 4444,
        "payload_use_https": False,
        "custom_system_prompts": {},
        "tool_output_max_chars": 8000,
        "execution_trace_memory": 100,
        "brute_force_max_attempts": 3,
    }


def default_scan_toggles_config():
    """Module enable/disable with dependency resolution (parent off => children off)."""
    return {
        "domain_discovery": True,
        "port_scan": True,
        "http_probe": True,
        "resource_enum": True,  # Katana, ParamSpider, Wayback
        "vuln_scan": True,
    }


def get_default_config(module: str) -> dict:
    """Return default config for a module."""
    defaults = {
        MODULE_TARGET: default_target_config,
        MODULE_PORT_SCANNER: default_port_scanner_config,
        MODULE_HTTP_PROBER: default_http_prober_config,
        MODULE_WAPPALYZER: default_wappalyzer_config,
        MODULE_BANNER_GRABBING: default_banner_grabbing_config,
        MODULE_KATANA: default_katana_config,
        MODULE_PASSIVE_URL: default_passive_url_config,
        MODULE_API_DISCOVERY: default_api_discovery_config,
        MODULE_NUCLEI: default_nuclei_config,
        MODULE_CVE_ENRICHMENT: default_cve_enrichment_config,
        MODULE_MITRE_MAPPING: default_mitre_mapping_config,
        MODULE_SECURITY_CHECKS: default_security_checks_config,
        MODULE_AGENT: default_agent_config,
        MODULE_SCAN_TOGGLES: default_scan_toggles_config,
    }
    fn = defaults.get(module)
    return fn() if fn else {}


class ProjectSettings(Base):
    """
    Per-organization project settings (per-org).
    One row per (organization_id, module); config is JSON.
    """

    __tablename__ = "project_settings"
    __table_args__ = (UniqueConstraint("organization_id", "module", name="uq_project_settings_org_module"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    organization = relationship("Organization", backref="project_settings")
    module = Column(String(64), nullable=False, index=True)
    config = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ProjectSettings org={self.organization_id} module={self.module}>"

    @classmethod
    def get_config(cls, db, organization_id: int, module: str) -> dict:
        """Get config for org+module; merge with defaults."""
        row = db.query(cls).filter(
            cls.organization_id == organization_id,
            cls.module == module,
        ).first()
        default = get_default_config(module)
        if not row or not row.config:
            return default
        merged = dict(default)
        for k, v in row.config.items():
            merged[k] = v
        return merged

    @classmethod
    def set_config(cls, db, organization_id: int, module: str, config: dict) -> "ProjectSettings":
        """Set config for org+module (partial update merged with existing)."""
        row = db.query(cls).filter(
            cls.organization_id == organization_id,
            cls.module == module,
        ).first()
        current = get_default_config(module)
        if row and row.config:
            current.update(row.config)
        current.update(config)
        if not row:
            row = cls(organization_id=organization_id, module=module, config=current)
            db.add(row)
        else:
            row.config = current
        db.flush()
        return row

    @classmethod
    def ensure_defaults(cls, db, organization_id: int) -> None:
        """Ensure all modules have a row for this org (with defaults)."""
        for module in ALL_MODULES:
            existing = db.query(cls).filter(
                cls.organization_id == organization_id,
                cls.module == module,
            ).first()
            if not existing:
                db.add(cls(
                    organization_id=organization_id,
                    module=module,
                    config=get_default_config(module),
                ))
        db.commit()
