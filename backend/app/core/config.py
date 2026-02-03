"""Application configuration settings."""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


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
    
    # AI Agent Configuration
    # Supported providers: "openai", "anthropic"
    AI_PROVIDER: str = "openai"
    
    # OpenAI Configuration
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o"
    
    # Anthropic/Claude Configuration
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    
    # Agent settings
    AGENT_MAX_ITERATIONS: int = 15
    AGENT_TOOL_OUTPUT_MAX_CHARS: int = 10000
    
    # Neo4j Graph Database Configuration
    NEO4J_URI: str = "bolt://neo4j:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "neo4j_password"
    
    # GitHub Secret Scanning Configuration
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_SECRET_SCAN_ENABLED: bool = True
    
    # GVM/OpenVAS Configuration
    GVM_SOCKET_PATH: str = "/run/gvmd/gvmd.sock"
    GVM_USERNAME: str = "admin"
    GVM_PASSWORD: str = "admin"
    GVM_SCAN_CONFIG: str = "Full and fast"
    GVM_ENABLED: bool = False
    
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






