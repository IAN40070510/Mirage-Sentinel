"""Database operations for Banking API"""

from datetime import datetime
import re
from faker import Faker

from .models import Account, Transaction, Beneficiary, Idempotency
from .session import get_db, is_real_db_enabled


faker_zh_tw = Faker("zh_TW")


def _build_traditional_chinese_name(user_id: str) -> str:
    digits = "".join(ch for ch in user_id if ch.isdigit())
    seed_value = int(digits or "1")
    faker_zh_tw.seed_instance(seed_value)
    return faker_zh_tw.name()


def _is_legacy_numeric_name(name: str | None) -> bool:
    if not name:
        return True
    return bool(re.fullmatch(r"客戶\d+", name.strip()))


class DBOperations:
    """Wrapper for database operations with fallback to None if DB not enabled"""

    @staticmethod
    def get_user_accounts(user_id: str) -> list[dict] | None:
        """Get all accounts for a user"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            accounts = db.query(Account).filter(Account.user_id == user_id).all()
            result = []
            for acc in accounts:
                result.append(
                    {
                        "account_id": acc.account_id,
                        "customer_name": acc.user.name if acc.user else "Unknown",
                        "account_type": acc.account_type,
                        "currency": acc.currency,
                        "balance": acc.balance,
                        "status": acc.status,
                        "open_date": acc.open_date,
                        "created_at": (
                            acc.created_at.isoformat() if acc.created_at else None
                        ),
                    }
                )
            return result
        finally:
            db.close()

    @staticmethod
    def ensure_user_account(user_id: str) -> dict | None:
        """Ensure a user and a default account exist (idempotent)."""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            from .models import User

            user = db.query(User).filter(User.user_id == user_id).first()
            if not user:
                user = User(
                    user_id=user_id,
                    name=_build_traditional_chinese_name(user_id),
                    email=f"{user_id.lower()}@mirage.local",
                )
                db.add(user)
            elif _is_legacy_numeric_name(user.name):
                # Migrate old placeholder names like 客戶000001112 to faker zh_TW names.
                user.name = _build_traditional_chinese_name(user_id)

            account = db.query(Account).filter(Account.user_id == user_id).first()
            if not account:
                digits = "".join(ch for ch in user_id if ch.isdigit())
                account_id = f"ACC{digits.zfill(12)[-12:]}"
                account = Account(
                    account_id=account_id,
                    user_id=user_id,
                    account_type="Checking",
                    currency="USD",
                    balance=182700.46,
                    status="ACTIVE",
                    open_date=datetime.utcnow().date().isoformat(),
                )
                db.add(account)

            db.commit()

            return {
                "user_id": user.user_id,
                "account_id": account.account_id,
                "currency": account.currency,
                "balance": account.balance,
                "status": account.status,
                "open_date": account.open_date,
            }
        except Exception:
            db.rollback()
            return None
        finally:
            db.close()

    @staticmethod
    def get_account_balance(account_id: str, user_id: str) -> dict | None:
        """Get account balance"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            account = (
                db.query(Account)
                .filter(Account.account_id == account_id, Account.user_id == user_id)
                .first()
            )

            if not account:
                return None

            return {
                "account_id": account.account_id,
                "customer_name": account.user.name if account.user else "Unknown",
                "currency": account.currency,
                "balance": account.balance,
                "status": account.status,
                "created_at": (
                    account.created_at.isoformat() if account.created_at else None
                ),
            }
        finally:
            db.close()

    @staticmethod
    def get_account_transactions(
        account_id: str, user_id: str, limit: int = 20
    ) -> list[dict] | None:
        """Get transactions for an account"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            transactions = (
                db.query(Transaction)
                .filter(
                    (Transaction.from_account == account_id)
                    | (Transaction.to_account == account_id)
                )
                .order_by(Transaction.created_at.desc())
                .limit(limit)
                .all()
            )

            result = []
            for tx in transactions:
                result.append(
                    {
                        "tx_id": tx.tx_id,
                        "from_account": tx.from_account,
                        "to_account": tx.to_account,
                        "amount": tx.amount,
                        "currency": tx.currency,
                        "fee": tx.fee,
                        "status": tx.status,
                        "note": tx.note,
                        "created_at": (
                            tx.created_at.isoformat() if tx.created_at else None
                        ),
                    }
                )
            return result
        finally:
            db.close()

    @staticmethod
    def get_user_beneficiaries(user_id: str) -> list[dict] | None:
        """Get beneficiaries for a user"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            beneficiaries = (
                db.query(Beneficiary).filter(Beneficiary.user_id == user_id).all()
            )
            result = []
            for ben in beneficiaries:
                result.append(
                    {
                        "id": ben.id,
                        "nickname": ben.nickname,
                        "bank_code": ben.bank_code,
                        "account_id": ben.account_id,
                        "beneficiary_name": ben.beneficiary_name,
                        "created_at": (
                            ben.created_at.isoformat() if ben.created_at else None
                        ),
                    }
                )
            return result
        finally:
            db.close()

    @staticmethod
    def create_beneficiary(
        user_id: str,
        nickname: str,
        bank_code: str,
        account_id: str,
        beneficiary_name: str,
    ) -> dict | None:
        """Create a new beneficiary"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            # Check if already exists
            existing = (
                db.query(Beneficiary)
                .filter(
                    Beneficiary.user_id == user_id, Beneficiary.account_id == account_id
                )
                .first()
            )

            if existing:
                return None

            ben = Beneficiary(
                user_id=user_id,
                nickname=nickname,
                bank_code=bank_code,
                account_id=account_id,
                beneficiary_name=beneficiary_name,
            )
            db.add(ben)
            db.commit()
            db.refresh(ben)

            return {
                "id": ben.id,
                "account_id": ben.account_id,
                "beneficiary_name": ben.beneficiary_name,
                "created_at": ben.created_at.isoformat() if ben.created_at else None,
            }
        except Exception:
            db.rollback()
            return None
        finally:
            db.close()

    @staticmethod
    def transfer_money(
        user_id: str,
        from_account: str,
        to_account: str,
        amount: float,
        fee: float,
        note: str,
    ) -> dict | None:
        """Execute a transfer transaction"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            # Verify from_account ownership
            from_acc = (
                db.query(Account)
                .filter(Account.account_id == from_account, Account.user_id == user_id)
                .first()
            )

            if not from_acc:
                return None

            # Get to_account (may belong to another user)
            to_acc = db.query(Account).filter(Account.account_id == to_account).first()
            if not to_acc:
                return None

            # Check balance
            total_debit = amount + fee
            if from_acc.balance < total_debit:
                return None

            # Update balances
            from_acc.balance -= total_debit
            to_acc.balance += amount

            # Create transaction record
            import uuid

            tx = Transaction(
                tx_id=f"TX-{uuid.uuid4().hex[:12].upper()}",
                from_account=from_account,
                to_account=to_account,
                amount=amount,
                fee=fee,
                currency=from_acc.currency,
                status="SUCCESS",
                note=note,
            )

            db.add(tx)
            db.commit()
            db.refresh(tx)

            return {
                "tx_id": tx.tx_id,
                "from_account": tx.from_account,
                "to_account": tx.to_account,
                "amount": tx.amount,
                "fee": tx.fee,
                "currency": tx.currency,
                "status": tx.status,
                "created_at": tx.created_at.isoformat() if tx.created_at else None,
                "new_balance": from_acc.balance,
            }
        except Exception:
            db.rollback()
            return None
        finally:
            db.close()

    @staticmethod
    def record_idempotency(user_id: str, idempotency_key: str, tx_id: str) -> bool:
        """Record an idempotent transaction"""
        if not is_real_db_enabled():
            return False

        db = get_db()
        if not db:
            return False

        try:
            idempotent = Idempotency(
                user_id=user_id,
                idempotency_key=idempotency_key,
                tx_id=tx_id,
            )
            db.add(idempotent)
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False
        finally:
            db.close()

    @staticmethod
    def get_idempotent_transaction(user_id: str, idempotency_key: str) -> str | None:
        """Get a transaction by idempotency key"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            result = (
                db.query(Idempotency)
                .filter(
                    Idempotency.user_id == user_id,
                    Idempotency.idempotency_key == idempotency_key,
                )
                .first()
            )

            return result.tx_id if result else None
        finally:
            db.close()

    @staticmethod
    def get_transaction_by_id(tx_id: str) -> dict | None:
        """Get a transaction by tx_id"""
        if not is_real_db_enabled():
            return None

        db = get_db()
        if not db:
            return None

        try:
            tx = db.query(Transaction).filter(Transaction.tx_id == tx_id).first()
            if not tx:
                return None
            return {
                "tx_id": tx.tx_id,
                "from_account": tx.from_account,
                "to_account": tx.to_account,
                "amount": tx.amount,
                "currency": tx.currency,
                "fee": tx.fee,
                "status": tx.status,
                "created_at": tx.created_at.isoformat() if tx.created_at else None,
                "note": tx.note,
            }
        finally:
            db.close()
