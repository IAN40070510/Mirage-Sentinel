"""Database session and connection management"""

import os
import time
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool

# Global state
_engine = None
_SessionLocal = None
_is_real_db_enabled = False


def init_db():
    """Initialize database connection if DATABASE_URL is provided"""
    global _engine, _SessionLocal, _is_real_db_enabled
    database_url = os.getenv("DATABASE_URL", "").strip()
    max_retries = int(os.getenv("DB_INIT_RETRIES", "30"))
    retry_interval = float(os.getenv("DB_INIT_RETRY_INTERVAL", "2"))

    if not database_url:
        _is_real_db_enabled = False
        return False

    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            # Create engine for PostgreSQL (or other DB)
            _engine = create_engine(
                database_url,
                poolclass=NullPool,  # Disable connection pooling for simplicity
                echo=False,  # Set True to see SQL queries
            )
            _SessionLocal = sessionmaker(
                autocommit=False, autoflush=False, bind=_engine
            )

            # Test connection
            with _engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            _is_real_db_enabled = True
            print("[DB] Connected to PostgreSQL database")
            return True
        except Exception as e:
            last_error = e
            print(f"[DB] Connection attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(retry_interval)

    print(f"[DB] Failed to connect to PostgreSQL after retries: {last_error}")
    _is_real_db_enabled = False
    return False


def get_db() -> Session:
    """Get database session if real DB is enabled"""
    if not _is_real_db_enabled or _SessionLocal is None:
        return None
    return _SessionLocal()


def is_real_db_enabled() -> bool:
    """Check if real database is enabled"""
    return _is_real_db_enabled


def create_tables():
    """Create all tables in the database"""
    if not _is_real_db_enabled or _engine is None:
        return False

    from .models import Base

    Base.metadata.create_all(bind=_engine)
    print("[DB] Created all tables")
    return True
