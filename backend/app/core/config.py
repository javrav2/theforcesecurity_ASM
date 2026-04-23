"""Application configuration settings."""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache
from typing import Optional


def _strip_api_key(v: Optional[str]) -> Optional[str]:
    """Strip whitespace and optional surrounding quotes from API keys (avoids 401s)."""
    if v is None or not isinstance(v, str):
        return v
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        v = v[1:-1].strip()
    return v if v else None


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = "The Force Security ASM"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = "postgresql://asm_user:asm_password@db:5432/asm_db"
    
    # JWT Authentication
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost",
        "http://localhost:80",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://44.211.198.211",
        "http://44.211.198.211:80",
        "http://44.211.198.211:3000",
        "http://44.211.198.211:8000",
        "https://aegis.theforcesecurity.io",
    ]
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100
    
    # ProjectDiscovery Cloud API Key (for Chaos subdomain dataset)
    PDCP_API_KEY: str = ""
    
    # AI Agent Configuration (default: Claude)
    # Supported providers: "openai", "anthropic"
    AI_PROVIDER: str = "anthropic"
    
    # OpenAI Configuration
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o"
    
    # Anthropic/Claude Configuration (default agent)
    # Use key from https://console.anthropic.com (API keys) — NOT Claude Code / Cursor keys
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"

    @field_validator("ANTHROPIC_API_KEY", "OPENAI_API_KEY", mode="before")
    @classmethod
    def strip_api_keys(cls, v: Optional[str]) -> Optional[str]:
        return _strip_api_key(v)
    
    # Agent settings (overridable per-org via project_settings.agent)
    AGENT_MAX_ITERATIONS: int = 100
    AGENT_MAX_OUTPUT_TOKENS: int = 4096  # Max tokens for LLM response (Claude/OpenAI); increase for long answers (e.g. 8192, 16384, 64000)
    AGENT_TOOL_OUTPUT_MAX_CHARS: int = 20000  # RedAmon-style default; truncation for LLM context
    AGENT_REST_MAX_ITERATIONS: int = 15  # Cap per REST request to avoid proxy timeouts
    AGENT_REQUEST_TIMEOUT_SECONDS: int = 660  # Hard timeout for a single agent REST call (11 min, covers Nuclei 10-min max + LLM overhead)

    # ---- Aegis Lictor / Censor / Augur (deterministic guard layer) ----
    # Lictor pre/post tool-execution hooks. Disabling skips ALL guards (not recommended).
    AGENT_LICTOR_ENABLED: bool = True
    # Restrict tool targets to assets in the calling org. Off by default to keep
    # ad-hoc recon usable; flip on for production multi-tenant deployments.
    AGENT_ENFORCE_ORG_SCOPE: bool = False
    # Per-(org, tool) token-bucket rate limit.
    AGENT_TOOL_RATE_CAPACITY: int = 30      # burst size
    AGENT_TOOL_RATE_PER_MINUTE: int = 30    # sustained refill
    # Censor input-validation gate (rejects malformed args before subprocess spawn).
    AGENT_CENSOR_ENABLED: bool = True
    # Augur output interpreter (smart nuclei/nmap/ffuf/etc filtering + next-step pivots).
    AGENT_AUGUR_ENABLED: bool = True
    # Verbose mode keeps the raw scanner output in addition to Augur's reading.
    AGENT_AUGUR_VERBOSE: bool = False

    # Optional: Tavily API for agent web search (CVE/exploit research). Get key at tavily.com
    TAVILY_API_KEY: Optional[str] = None
    
    # Neo4j Graph Database Configuration
    NEO4J_URI: str = "bolt://neo4j:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "neo4j_password"
    
    # GitHub Secret Scanning Configuration
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_SECRET_SCAN_ENABLED: bool = True
    
    # MITRE ATT&CK Enrichment
    MITRE_ENRICHMENT_ENABLED: bool = True

    # Delphi (CISA KEV + FIRST EPSS) Enrichment
    DELPHI_ENRICHMENT_ENABLED: bool = True
    DELPHI_REFRESH_HOURS: int = 24  # Re-fetch KEV + EPSS after this many hours
    DELPHI_AUTO_ENRICH_ON_INGEST: bool = True  # Enrich CVEs during ingestion pipeline
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()






