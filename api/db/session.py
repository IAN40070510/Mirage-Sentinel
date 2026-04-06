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
DEFAULT_CURRENCY = "TWD"


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


def ensure_real_db_enabled() -> bool:
    """Ensure the real database is initialized; retry lazily if startup missed it."""
    global _is_real_db_enabled
    if _is_real_db_enabled:
        return True

    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        return False

    return init_db()


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
    demo_beneficiary_user_id = os.getenv(
        "BANKING_DEMO_BENEFICIARY_USER_ID", "CIF000009999"
    ).strip()
    demo_beneficiary_user_name = os.getenv(
        "BANKING_DEMO_BENEFICIARY_USER_NAME", "External Beneficiary"
    ).strip()
    demo_beneficiary_user_email = os.getenv(
        "BANKING_DEMO_BENEFICIARY_USER_EMAIL", "external.beneficiary@mirage.local"
    ).strip()
    demo_beneficiary_account_id = os.getenv(
        "BANKING_DEMO_BENEFICIARY_ACCOUNT_ID", "MERNGTU3WAVTQJF"
    ).strip()

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
                currency=DEFAULT_CURRENCY,
                balance=5680000,
                status="ACTIVE",
                open_date="2021-03-27",
            )
            db.add(account)
        elif (account.currency or "").upper() == "USD" and abs(
            float(account.balance) - 182700.46
        ) < 0.0001:
            account.currency = DEFAULT_CURRENCY
            account.balance = 5680000

        beneficiary_user = (
            db.query(User).filter(User.user_id == demo_beneficiary_user_id).first()
        )
        if not beneficiary_user:
            beneficiary_user = User(
                user_id=demo_beneficiary_user_id,
                name=demo_beneficiary_user_name,
                email=demo_beneficiary_user_email,
            )
            db.add(beneficiary_user)

        beneficiary_account = (
            db.query(Account)
            .filter(Account.account_id == demo_beneficiary_account_id)
            .first()
        )
        if not beneficiary_account:
            beneficiary_account = Account(
                account_id=demo_beneficiary_account_id,
                user_id=demo_beneficiary_user_id,
                account_type="Checking",
                currency=DEFAULT_CURRENCY,
                balance=0,
                status="ACTIVE",
                open_date="2021-03-27",
            )
            db.add(beneficiary_account)

        beneficiary = (
            db.query(Beneficiary)
            .filter(
                Beneficiary.user_id == demo_user_id,
                Beneficiary.account_id == demo_beneficiary_account_id,
            )
            .first()
        )
        if not beneficiary:
            db.add(
                Beneficiary(
                    user_id=demo_user_id,
                    nickname="Primary Merchant",
                    bank_code="812",
                    account_id=demo_beneficiary_account_id,
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
