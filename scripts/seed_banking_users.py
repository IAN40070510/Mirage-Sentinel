import argparse
import csv
import os
import sys
import zipfile
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.db.models import User, Account
from api.db.session import init_db, create_tables, get_db, is_real_db_enabled


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed banking users/accounts into real PostgreSQL database"
    )
    parser.add_argument("--start", type=int, required=True, help="Start CIF numeric id")
    parser.add_argument("--end", type=int, required=True, help="End CIF numeric id")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Commit every N records (default: 1000)",
    )
    parser.add_argument(
        "--initial-balance",
        type=float,
        default=182700.46,
        help="Initial account balance",
    )
    parser.add_argument(
        "--archive-zip",
        type=str,
        default=os.path.join("scripts", "data", "archive.zip"),
        help="Path to archive.zip used for realistic seed templates",
    )
    return parser.parse_args()


def build_user_id(number: int) -> str:
    return f"CIF{number:09d}"


def build_account_id(number: int) -> str:
    return f"ACC{number:012d}"


def _load_archive_templates(archive_zip_path: str) -> tuple[list[dict], list[dict]]:
    """Load customer/account templates from archive.zip. Returns empty lists on failure."""
    if not os.path.exists(archive_zip_path):
        print(
            f"[seed] archive not found: {archive_zip_path}. Fallback to generated data."
        )
        return [], []

    customers_csv = "banking_dataset_kaggle/data/csv/customers.csv"
    accounts_csv = "banking_dataset_kaggle/data/csv/accounts.csv"

    try:
        with zipfile.ZipFile(archive_zip_path) as zf:
            customers_text = zf.read(customers_csv).decode("utf-8")
            accounts_text = zf.read(accounts_csv).decode("utf-8")

        customers = list(csv.DictReader(customers_text.splitlines()))
        accounts = list(csv.DictReader(accounts_text.splitlines()))
        print(
            f"[seed] loaded archive templates customers={len(customers)}, accounts={len(accounts)}"
        )
        return customers, accounts
    except Exception as e:
        print(
            f"[seed] failed to read archive templates: {e}. Fallback to generated data."
        )
        return [], []


def run() -> int:
    args = parse_args()

    if args.start < 1 or args.end < args.start:
        print("[seed] Invalid range: start must be >= 1 and end >= start")
        return 1

    if not init_db() or not is_real_db_enabled():
        print("[seed] Database not available. Please check DATABASE_URL.")
        return 1

    create_tables()
    customer_templates, account_templates = _load_archive_templates(args.archive_zip)

    db = get_db()
    if db is None:
        print("[seed] Unable to create database session")
        return 1

    total = args.end - args.start + 1
    created_users = 0
    created_accounts = 0

    try:
        for idx, number in enumerate(range(args.start, args.end + 1), start=1):
            user_id = build_user_id(number)
            account_id = build_account_id(number)

            customer_template = (
                customer_templates[(idx - 1) % len(customer_templates)]
                if customer_templates
                else None
            )
            account_template = (
                account_templates[(idx - 1) % len(account_templates)]
                if account_templates
                else None
            )

            user_name = f"客戶{number:09d}"
            user_email = f"{user_id.lower()}@mirage.local"
            if customer_template:
                first_name = (customer_template.get("first_name") or "").strip()
                last_name = (customer_template.get("last_name") or "").strip()
                full_name = f"{first_name} {last_name}".strip()
                if full_name:
                    user_name = full_name
                email_candidate = (customer_template.get("email") or "").strip()
                if email_candidate:
                    user_email = f"{user_id.lower()}-{email_candidate}"

            account_type = "Checking"
            balance = args.initial_balance
            open_date = datetime.utcnow().date().isoformat()
            if account_template:
                account_type = (
                    account_template.get("account_type") or "Checking"
                ).strip() or "Checking"
                try:
                    balance = float(
                        account_template.get("balance_usd") or args.initial_balance
                    )
                except Exception:
                    balance = args.initial_balance
                open_date_candidate = (account_template.get("open_date") or "").strip()
                if open_date_candidate:
                    open_date = open_date_candidate

            user = db.query(User).filter(User.user_id == user_id).first()
            if not user:
                user = User(
                    user_id=user_id,
                    name=user_name,
                    email=user_email,
                )
                db.add(user)
                created_users += 1

            account = db.query(Account).filter(Account.account_id == account_id).first()
            if not account:
                account = Account(
                    account_id=account_id,
                    user_id=user_id,
                    account_type=account_type,
                    currency="USD",
                    balance=balance,
                    status="ACTIVE",
                    open_date=open_date,
                )
                db.add(account)
                created_accounts += 1

            if idx % args.batch_size == 0:
                db.commit()
                print(
                    f"[seed] progress {idx}/{total}, created_users={created_users}, created_accounts={created_accounts}"
                )

        db.commit()
        print(
            f"[seed] done total={total}, created_users={created_users}, created_accounts={created_accounts}"
        )
        return 0
    except Exception as e:
        db.rollback()
        print(f"[seed] failed: {e}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(run())
