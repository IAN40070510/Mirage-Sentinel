import os
import sqlite3
from datetime import datetime


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "banking.db")


def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def setup_banking_db() -> None:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("PRAGMA journal_mode=WAL;")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            currency TEXT NOT NULL DEFAULT 'TWD',
            balance REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            from_account TEXT,
            to_account TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            fee REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            idempotency_key TEXT,
            note TEXT,
            FOREIGN KEY(from_account) REFERENCES accounts(account_id),
            FOREIGN KEY(to_account) REFERENCES accounts(account_id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS beneficiaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            nickname TEXT NOT NULL,
            bank_code TEXT NOT NULL,
            account_id TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS transfer_idempotency (
            user_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            tx_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_id, idempotency_key)
        )
        """
    )

    _seed_demo_data(cur)

    conn.commit()
    conn.close()


def _seed_demo_data(cur: sqlite3.Cursor) -> None:
    now = datetime.utcnow().isoformat(timespec="seconds")
    demo_accounts = [
        ("ACCT-1001", "user-001", "TWD", 125000.0, "ACTIVE", now),
        ("ACCT-1002", "user-001", "TWD", 8300.0, "ACTIVE", now),
        ("ACCT-2001", "user-002", "TWD", 90500.0, "ACTIVE", now),
    ]
    cur.executemany(
        """
        INSERT OR IGNORE INTO accounts(account_id, user_id, currency, balance, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        demo_accounts,
    )

    demo_beneficiaries = [
        ("user-001", "房租", "812", "ACCT-2001", now),
    ]
    cur.executemany(
        """
        INSERT OR IGNORE INTO beneficiaries(user_id, nickname, bank_code, account_id, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        demo_beneficiaries,
    )
