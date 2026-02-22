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
        "http://3.88.188.178",
        "http://3.88.188.178:80",
        "http://3.88.188.178:3000",
        "http://54.175.202.243",
        "http://54.175.202.243:80",
        "http://54.175.202.243:3000",
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
    AGENT_TOOL_OUTPUT_MAX_CHARS: int = 20000  # RedAmon-style default; truncation for LLM context

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
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()






