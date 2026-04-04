import argparse
import os
import sys
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
    return parser.parse_args()


def build_user_id(number: int) -> str:
    return f"CIF{number:09d}"


def build_account_id(number: int) -> str:
    return f"ACC{number:012d}"


def run() -> int:
    args = parse_args()

    if args.start < 1 or args.end < args.start:
        print("[seed] Invalid range: start must be >= 1 and end >= start")
        return 1

    if not init_db() or not is_real_db_enabled():
        print("[seed] Database not available. Please check DATABASE_URL.")
        return 1

    create_tables()

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

            user = db.query(User).filter(User.user_id == user_id).first()
            if not user:
                user = User(
                    user_id=user_id,
                    name=f"客戶{number:09d}",
                    email=f"{user_id.lower()}@mirage.local",
                )
                db.add(user)
                created_users += 1

            account = db.query(Account).filter(Account.account_id == account_id).first()
            if not account:
                account = Account(
                    account_id=account_id,
                    user_id=user_id,
                    account_type="Checking",
                    currency="USD",
                    balance=args.initial_balance,
                    status="ACTIVE",
                    open_date=datetime.utcnow().date().isoformat(),
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
