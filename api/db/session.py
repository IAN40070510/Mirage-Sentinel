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


def seed_banking_demo_data() -> bool:
    """Seed minimal banking demo data into real DB (idempotent)."""
    if not _is_real_db_enabled or _SessionLocal is None:
        return False

    from .models import User, Account, Beneficiary

    demo_user_id = os.getenv("BANKING_DEMO_USER_ID", "CIF000001001").strip()
    demo_user_name = os.getenv("BANKING_DEMO_USER_NAME", "Demo User").strip()
    demo_user_email = os.getenv(
        "BANKING_DEMO_USER_EMAIL", "demo.user@mirage.local"
    ).strip()
    demo_account_id = os.getenv("BANKING_DEMO_ACCOUNT_ID", "ACCOD48PUCAEHKH").strip()

    db = _SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == demo_user_id).first()
        if not user:
            user = User(
                user_id=demo_user_id,
                name=demo_user_name,
                email=demo_user_email,
            )
            db.add(user)

        account = (
            db.query(Account).filter(Account.account_id == demo_account_id).first()
        )
        if not account:
            account = Account(
                account_id=demo_account_id,
                user_id=demo_user_id,
                account_type="Checking",
                currency="USD",
                balance=182700.46,
                status="ACTIVE",
                open_date="2021-03-27",
            )
            db.add(account)

        beneficiary = (
            db.query(Beneficiary)
            .filter(
                Beneficiary.user_id == demo_user_id,
                Beneficiary.account_id == "MERNGTU3WAVTQJF",
            )
            .first()
        )
        if not beneficiary:
            db.add(
                Beneficiary(
                    user_id=demo_user_id,
                    nickname="Primary Merchant",
                    bank_code="812",
                    account_id="MERNGTU3WAVTQJF",
                    beneficiary_name="Demo Beneficiary",
                )
            )

        db.commit()
        print(f"[DB] Banking demo seed ready for user: {demo_user_id}")
        return True
    except Exception as e:
        db.rollback()
        print(f"[DB] Failed to seed banking demo data: {e}")
        return False
    finally:
        db.close()
