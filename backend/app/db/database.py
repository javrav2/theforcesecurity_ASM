"""Database connection and session management."""

import logging
from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import Pool

from app.core.config import settings

logger = logging.getLogger(__name__)

# Create database engine with robust connection handling
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Verify connection is alive before using
    pool_size=10,
    max_overflow=20,
    pool_reset_on_return='rollback',  # Ensure clean state when connection returns to pool
    pool_recycle=1800,  # Recycle connections every 30 minutes to prevent stale connections
)


@event.listens_for(Pool, "checkout")
def check_connection(dbapi_connection, connection_record, connection_proxy):
    """
    Ensure connection is in a clean transaction state when checked out from pool.
    
    This handles edge cases where pool_reset_on_return didn't properly clean the connection.
    """
    try:
        # Execute a rollback to ensure clean transaction state
        cursor = dbapi_connection.cursor()
        cursor.execute("ROLLBACK")
        cursor.close()
    except Exception:
        # If rollback fails, the pool_pre_ping will handle reconnection
        pass


# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        # Ensure we start with a clean transaction state
        # This handles cases where connection pool returns a connection with a failed transaction
        try:
            db.rollback()
        except Exception:
            pass
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

















