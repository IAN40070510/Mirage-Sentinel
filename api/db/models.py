"""SQLAlchemy ORM Models for Mirage-Sentinel Banking API"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    DateTime,
    Integer,
    ForeignKey,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    accounts = relationship("Account", back_populates="user")
    beneficiaries = relationship("Beneficiary", back_populates="user")


class Account(Base):
    __tablename__ = "accounts"

    account_id = Column(String(50), primary_key=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=False)
    account_type = Column(String(50), default="Checking")
    currency = Column(String(10), default="TWD")
    balance = Column(Integer, default=0)
    status = Column(String(20), default="ACTIVE")
    open_date = Column(String(20))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="accounts")
    transactions = relationship(
        "Transaction",
        foreign_keys="Transaction.from_account",
        back_populates="from_account_obj",
    )


class Transaction(Base):
    __tablename__ = "transactions"

    tx_id = Column(String(50), primary_key=True)
    from_account = Column(String(50), ForeignKey("accounts.account_id"), nullable=False)
    to_account = Column(String(50), ForeignKey("accounts.account_id"), nullable=False)
    amount = Column(Integer, nullable=False)
    currency = Column(String(10), default="TWD")
    fee = Column(Integer, default=0)
    status = Column(String(20), default="SUCCESS")
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    from_account_obj = relationship(
        "Account", foreign_keys=[from_account], back_populates="transactions"
    )


class Beneficiary(Base):
    __tablename__ = "beneficiaries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=False)
    nickname = Column(String(100), nullable=False)
    bank_code = Column(String(10), nullable=False)
    account_id = Column(String(50), index=True)
    beneficiary_name = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="beneficiaries")


class Idempotency(Base):
    __tablename__ = "idempotency"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), nullable=False)
    idempotency_key = Column(String(100), nullable=False)
    tx_id = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("user_id", "idempotency_key", name="uq_idempotency_user_key"),
    )
