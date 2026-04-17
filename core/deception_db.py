import sqlite3
import json
import os
import logging
import time
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "mirage_memory.db")


def _migrate_attacker_ip_to_client_ip(conn: sqlite3.Connection):
    cursor = conn.execute("PRAGMA table_info(deception_memory)")
    columns = {row[1] for row in cursor.fetchall()}
    if "client_ip" not in columns and "attacker_ip" in columns:
        conn.execute(
            "ALTER TABLE deception_memory RENAME COLUMN attacker_ip TO client_ip"
        )
    if "principal_id" not in columns and "query_id" in columns:
        conn.execute(
            "ALTER TABLE deception_memory RENAME COLUMN query_id TO principal_id"
        )


def _ensure_column(conn: sqlite3.Connection, column_sql: str):
    column_name = column_sql.strip().split()[0]
    cursor = conn.execute("PRAGMA table_info(deception_memory)")
    columns = {row[1] for row in cursor.fetchall()}
    if column_name not in columns:
        conn.execute(f"ALTER TABLE deception_memory ADD COLUMN {column_sql}")


def _ensure_table_column(conn: sqlite3.Connection, table: str, column_sql: str):
    column_name = column_sql.strip().split()[0]
    cursor = conn.execute(f"PRAGMA table_info({table})")
    columns = {row[1] for row in cursor.fetchall()}
    if column_name not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_sql}")


def _ensure_unique_memory_key(conn: sqlite3.Connection):
    # 清理重複紀錄後建立唯一鍵，確保同一 client_ip + principal_id 只有一筆狀態
    conn.execute(
        """
        DELETE FROM deception_memory
        WHERE id NOT IN (
            SELECT MAX(id)
            FROM deception_memory
            GROUP BY client_ip, principal_id
        )
        """
    )

    index_name = "idx_deception_memory_client_query"
    index_list = conn.execute("PRAGMA index_list(deception_memory)").fetchall()
    existing_index = next((row for row in index_list if row[1] == index_name), None)
    if existing_index is not None:
        index_info = conn.execute(f"PRAGMA index_info({index_name})").fetchall()
        indexed_columns = [row[2] for row in index_info]
        if indexed_columns != ["client_ip", "principal_id"]:
            conn.execute(f"DROP INDEX IF EXISTS {index_name}")

    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_deception_memory_client_query ON deception_memory(client_ip, principal_id)"
    )


def setup_deception_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        # 主追蹤表：攻擊者基本信息
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deception_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                principal_id TEXT,
                fake_data_payload TEXT,
                last_vector TEXT,
                max_risk_seen INTEGER,
                interaction_count INTEGER DEFAULT 1,
                hits INTEGER DEFAULT 1,
                last_seen TEXT,
                fake_session_token TEXT,
                engagement_level INTEGER DEFAULT 1
            )
        """
        )
        # 假帳戶表：記錄攻擊者登入的假帳號和密碼
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fake_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                principal_id TEXT,
                fake_username TEXT,
                fake_password TEXT,
                fake_account_id TEXT,
                fake_balance REAL DEFAULT 50000.0,
                created_at TEXT,
                UNIQUE(client_ip, principal_id, fake_username)
            )
        """
        )
        # 與真實 users schema 對齊的鏡像表（避免欄位落差）
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mirror_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                principal_id TEXT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                account_number TEXT NOT NULL,
                balance REAL DEFAULT 50000.0,
                is_admin INTEGER DEFAULT 0,
                profile_picture TEXT,
                reset_pin TEXT,
                bio TEXT,
                is_suspended INTEGER DEFAULT 0,
                created_at TEXT
            )
            """
        )
        # 假轉帳表：記錄攻擊者的轉帳操作
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fake_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                principal_id TEXT,
                from_account TEXT,
                to_account TEXT,
                amount REAL,
                currency TEXT,
                transaction_id TEXT,
                description TEXT,
                status TEXT,
                created_at TEXT
            )
        """
        )
        # 假卡片表：記錄攻擊者新增的卡片
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fake_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                principal_id TEXT,
                card_number TEXT,
                card_holder TEXT,
                expiry TEXT,
                cvv TEXT,
                card_type TEXT,
                currency TEXT DEFAULT 'USD',
                card_limit REAL DEFAULT 0.0,
                current_balance REAL DEFAULT 0.0,
                is_frozen INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                last_used_at TEXT,
                created_at TEXT
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fake_card_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                principal_id TEXT,
                card_id INTEGER,
                amount REAL,
                merchant_name TEXT,
                transaction_type TEXT,
                status TEXT,
                description TEXT,
                created_at TEXT
            )
            """
        )
        _migrate_attacker_ip_to_client_ip(conn)
        _ensure_column(conn, "principal_id TEXT")
        _ensure_column(conn, "fake_data_payload TEXT")
        _ensure_column(conn, "last_vector TEXT")
        _ensure_column(conn, "max_risk_seen INTEGER")
        _ensure_column(conn, "interaction_count INTEGER DEFAULT 1")
        _ensure_column(conn, "hits INTEGER DEFAULT 1")
        _ensure_column(conn, "last_seen TEXT")
        _ensure_column(conn, "fake_session_token TEXT")
        _ensure_column(conn, "engagement_level INTEGER DEFAULT 1")
        _ensure_table_column(conn, "fake_accounts", "fake_balance REAL DEFAULT 50000.0")
        _ensure_table_column(conn, "fake_transactions", "description TEXT")
        _ensure_table_column(conn, "fake_cards", "currency TEXT DEFAULT 'USD'")
        _ensure_table_column(conn, "fake_cards", "card_limit REAL DEFAULT 0.0")
        _ensure_table_column(conn, "fake_cards", "current_balance REAL DEFAULT 0.0")
        _ensure_table_column(conn, "fake_cards", "is_frozen INTEGER DEFAULT 0")
        _ensure_table_column(conn, "fake_cards", "is_active INTEGER DEFAULT 1")
        _ensure_table_column(conn, "fake_cards", "last_used_at TEXT")
        _ensure_table_column(conn, "fake_card_transactions", "client_ip TEXT")
        _ensure_table_column(conn, "fake_card_transactions", "principal_id TEXT")
        _ensure_table_column(conn, "fake_card_transactions", "card_id INTEGER")
        _ensure_table_column(conn, "fake_card_transactions", "amount REAL")
        _ensure_table_column(conn, "fake_card_transactions", "merchant_name TEXT")
        _ensure_table_column(conn, "fake_card_transactions", "transaction_type TEXT")
        _ensure_table_column(conn, "fake_card_transactions", "status TEXT")
        _ensure_table_column(conn, "fake_card_transactions", "description TEXT")
        _ensure_table_column(conn, "fake_card_transactions", "created_at TEXT")
        _ensure_billing_tables(conn)
        _ensure_unique_memory_key(conn)
    logger.info(f"Deception Memory Engine Ready: {DB_PATH}")


def get_memory(client_ip: str, principal_id: str):
    """
    讀取記憶：回傳字典以供 main.py 計算滯留時間與深度
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT fake_data_payload, last_seen, interaction_count, hits
            FROM deception_memory
            WHERE client_ip = ? AND principal_id = ?
            ORDER BY last_seen DESC
            LIMIT 1
        """,
            (client_ip, principal_id),
        )
        result = cursor.fetchone()

        if result:
            return {
                "payload": json.loads(result[0]),
                "last_seen": result[1],
                "depth": result[2],
                "hits": result[3],
            }
    return None


def save_deception_state(
    client_ip: str,
    principal_id: str,
    vector: str,
    risk: int,
    payload: dict[str, Any] | None = None,
):
    """
    儲存或更新記憶：確保資料一致性 (Upsert 邏輯)
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    if payload is None:
        return

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO deception_memory (
                client_ip, principal_id, fake_data_payload, last_vector, max_risk_seen,
                interaction_count, hits, last_seen
            ) VALUES (?, ?, ?, ?, ?, 1, 1, ?)
            ON CONFLICT(client_ip, principal_id)
            DO UPDATE SET
                fake_data_payload = excluded.fake_data_payload,
                last_vector = excluded.last_vector,
                max_risk_seen = CASE
                    WHEN excluded.max_risk_seen > deception_memory.max_risk_seen THEN excluded.max_risk_seen
                    ELSE deception_memory.max_risk_seen
                END,
                interaction_count = deception_memory.interaction_count + 1,
                hits = deception_memory.hits + 1,
                last_seen = excluded.last_seen
            """,
            (
                client_ip,
                principal_id,
                json.dumps(payload, ensure_ascii=False),
                vector,
                risk,
                now,
            ),
        )


def get_attacker_intelligence(client_ip: str):
    """提取駭客畫像，供 AI 引擎參考"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT last_vector, max_risk_seen, interaction_count
            FROM deception_memory WHERE client_ip = ?
            ORDER BY last_seen DESC LIMIT 1
        """,
            (client_ip,),
        )
        result = cursor.fetchone()
        if result:
            return {"vector": result[0], "risk": result[1], "count": result[2]}
    return None


def create_fake_session_token(client_ip: str, principal_id: str) -> str:
    """為攻擊者生成並記錄假會話令牌"""
    import hashlib
    import secrets
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    random_suffix = secrets.token_hex(8)
    fake_token = f"mirage_session_{hashlib.sha256(f'{client_ip}|{principal_id}|{random_suffix}'.encode('utf-8')).hexdigest()[:16]}"
    
    with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO deception_memory (client_ip, principal_id, fake_session_token, engagement_level, last_seen, interaction_count, hits)
                VALUES (?, ?, ?, 1, ?, 0, 0)
                ON CONFLICT(client_ip, principal_id)
                DO UPDATE SET
                    fake_session_token = excluded.fake_session_token,
                    engagement_level = engagement_level + 1,
                    last_seen = excluded.last_seen
                """,
                (client_ip, principal_id, fake_token, now)
            )
    return fake_token


def get_fake_session(fake_session_token: str) -> dict[str, object] | None:
    """獲取攻擊者的假會話信息（以 token 為主，不再依賴 IP）"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT fake_session_token, principal_id, engagement_level, last_seen
            FROM deception_memory
            WHERE fake_session_token = ?
            """,
            (fake_session_token,)
        )
        result = cursor.fetchone()
        if result:
            return {
                "fake_session_token": result[0],
                "principal_id": result[1],
                "engagement_level": result[2],
                "last_seen": result[3]
            }
    return None


def record_fake_login(
    client_ip: str,
    principal_id: str,
    fake_username: str,
    fake_password: str,
    fake_account_id: str,
    balance: float = 50000.0,
    is_admin: bool = False,
    profile_picture: str | None = None,
    reset_pin: str | None = None,
    bio: str | None = None,
    is_suspended: bool = False,
) -> bool:
    """記錄攻擊者的假登入信息"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO fake_accounts (client_ip, principal_id, fake_username, fake_password, fake_account_id, fake_balance, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(client_ip, principal_id, fake_username)
                DO UPDATE SET
                    fake_password = excluded.fake_password,
                    fake_balance = excluded.fake_balance,
                    fake_account_id = excluded.fake_account_id
                """,
                (client_ip, principal_id, fake_username, fake_password, fake_account_id, balance, now)
            )
            conn.execute(
                """
                INSERT INTO mirror_users (
                    client_ip, principal_id, username, password, account_number,
                    balance, is_admin, profile_picture, reset_pin, bio, is_suspended, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ip,
                    principal_id,
                    fake_username,
                    fake_password,
                    fake_account_id,
                    float(balance),
                    1 if is_admin else 0,
                    profile_picture,
                    reset_pin,
                    bio,
                    1 if is_suspended else 0,
                    now,
                ),
            )
        return True
    except Exception as e:
        logger.error(f"Failed to record fake login: {e}")
        return False


def record_fake_transaction(
    client_ip: str,
    principal_id: str,
    from_account: str,
    to_account: str,
    amount: float,
    currency: str,
    transaction_id: str,
    description: str = "Transfer",
    status: str = "completed",
) -> bool:
    """記錄攻擊者的假轉帳信息"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO fake_transactions (client_ip, principal_id, from_account, to_account, amount, currency, transaction_id, description, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ip,
                    principal_id,
                    from_account,
                    to_account,
                    amount,
                    currency,
                    transaction_id,
                    description,
                    status,
                    now,
                )
            )
        return True
    except Exception as e:
        logger.error(f"Failed to record fake transaction: {e}")
        return False


def record_fake_card(
    client_ip: str,
    principal_id: str,
    card_number: str,
    card_holder: str,
    expiry: str,
    cvv: str,
    card_type: str,
    currency: str = "USD",
    card_limit: float = 0.0,
    current_balance: float = 0.0,
    is_frozen: bool = False,
) -> bool:
    """記錄攻擊者的假卡片信息"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    try:
        limit_value = float(card_limit)
        balance_value = float(current_balance)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO fake_cards (
                    client_ip, principal_id, card_number, card_holder, expiry, cvv,
                    card_type, currency, card_limit, current_balance, is_frozen,
                    is_active, last_used_at, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?)
                """,
                (
                    client_ip,
                    principal_id,
                    card_number,
                    card_holder,
                    expiry,
                    cvv,
                    card_type,
                    currency,
                    limit_value,
                    balance_value,
                    1 if is_frozen else 0,
                    now,
                )
            )
        return True
    except Exception as e:
        logger.error(f"Failed to record fake card: {e}")
        return False


def get_fake_account_for_attacker(client_ip: str, principal_id: str) -> dict[str, object] | None:
    """獲取攻擊者登入的假帳戶信息"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT username, password, account_number, balance
            FROM mirror_users
            WHERE principal_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (principal_id,),
        )
        result = cursor.fetchone()
        if result:
            return {
                "username": result[0],
                "password": result[1],
                "account_id": result[2],
                "balance": float(result[3]) if result[3] is not None else 50000.0,
            }

        cursor = conn.execute(
            """
            SELECT fake_username, fake_password, fake_account_id, fake_balance
            FROM fake_accounts
            WHERE principal_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (principal_id,)
        )
        result = cursor.fetchone()
        if not result:
            cursor = conn.execute(
                """
                SELECT fake_username, fake_password, fake_account_id, fake_balance
                FROM fake_accounts
                WHERE client_ip = ? AND principal_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (client_ip, principal_id),
            )
            result = cursor.fetchone()
        if result:
            return {
                "username": result[0],
                "password": result[1],
                "account_id": result[2],
                "balance": float(result[3]) if result[3] is not None else 50000.0,
            }
    return None


def get_fake_transactions_for_attacker(client_ip: str, principal_id: str) -> list[dict[str, object]]:
    """獲取攻擊者的假轉帳歷史"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT from_account, to_account, amount, currency, transaction_id, description, status, created_at
            FROM fake_transactions
            WHERE principal_id = ?
            ORDER BY created_at DESC
            """,
            (principal_id,)
        )
        results = cursor.fetchall()
        return [
            {
                "from_account": row[0],
                "to_account": row[1],
                "amount": row[2],
                "currency": row[3],
                "transaction_id": row[4],
                "description": row[5],
                "status": row[6],
                "created_at": row[7],
            }
            for row in results
        ]


def get_fake_cards_for_attacker(client_ip: str, principal_id: str) -> list[dict[str, object]]:
    """獲取攻擊者的假卡片"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            SELECT id, card_number, card_holder, expiry, cvv, card_type, currency, card_limit, current_balance, is_frozen, is_active, last_used_at, created_at
            FROM fake_cards
            WHERE client_ip = ? AND principal_id = ?
            ORDER BY created_at DESC
            """,
            (client_ip, principal_id)
        )
        results = cursor.fetchall()
        return [
            {
                "id": int(row[0]),
                "card_number": row[1],
                "card_holder": row[2],
                "expiry": row[3],
                "expiry_date": row[3],
                "cvv": row[4],
                "card_type": row[5],
                "currency": row[6] or "USD",
                "limit": float(row[7]) if row[7] is not None else 0.0,
                "balance": float(row[8]) if row[8] is not None else 0.0,
                "current_balance": float(row[8]) if row[8] is not None else 0.0,
                "is_frozen": bool(row[9]),
                "is_active": bool(row[10]) if row[10] is not None else True,
                "last_used_at": row[11],
                "created_at": row[12],
                # 與 dashboard.js 期待欄位對齊
                "currency_symbol": "$",
            }
            for row in results
        ]


def _get_fake_card_row(conn: sqlite3.Connection, client_ip: str, principal_id: str, card_id: int) -> tuple[Any, ...] | None:
    return conn.execute(
        """
        SELECT id, card_number, card_holder, expiry, cvv, card_type, currency, card_limit,
               current_balance, is_frozen, is_active, last_used_at, created_at
        FROM fake_cards
        WHERE id = ? AND client_ip = ? AND principal_id = ?
        """,
        (card_id, client_ip, principal_id),
    ).fetchone()


def fund_fake_card(
    client_ip: str,
    principal_id: str,
    card_id: int,
    usd_amount: float,
) -> dict[str, object]:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    amount_value = abs(float(usd_amount))

    with sqlite3.connect(DB_PATH) as conn:
        card = _get_fake_card_row(conn, client_ip, principal_id, card_id)
        if not card:
            raise ValueError("Card or account not found")

        if int(card[9] or 0):
            raise ValueError("Card is frozen")

        fake_account = conn.execute(
            """
            SELECT id, fake_account_id, fake_balance
            FROM fake_accounts
            WHERE principal_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (principal_id,),
        ).fetchone()
        if not fake_account:
            raise ValueError("Card or account not found")

        card_currency = str(card[6] or "USD")
        currency_rate = {
            "USD": 1.0,
            "EUR": 0.93,
            "GBP": 0.82,
            "JPY": 156.0,
        }.get(card_currency, 1.0)
        precision = 2 if card_currency not in {"JPY"} else 0
        converted_amount = round(amount_value * currency_rate, precision)

        main_balance = float(fake_account[2] or 0.0)
        if amount_value > main_balance:
            raise ValueError("Insufficient main balance")

        current_balance = float(card[8] or 0.0)
        card_limit = float(card[7] or 0.0)
        new_balance = current_balance + converted_amount
        if card_limit > 0 and new_balance > card_limit:
            raise ValueError("Funding would exceed the card limit")

        conn.execute("UPDATE fake_accounts SET fake_balance = fake_balance - ? WHERE id = ?", (amount_value, int(fake_account[0])))
        conn.execute(
            """
            UPDATE mirror_users
            SET balance = balance - ?
            WHERE id = (
                SELECT id FROM mirror_users
                WHERE principal_id = ?
                ORDER BY created_at DESC
                LIMIT 1
            )
            """,
            (amount_value, principal_id),
        )
        conn.execute(
            """
            UPDATE fake_cards
            SET current_balance = current_balance + ?, last_used_at = ?
            WHERE id = ?
            """,
            (converted_amount, now, card_id),
        )
        conn.execute(
            """
            INSERT INTO fake_card_transactions (
                client_ip, principal_id, card_id, amount, merchant_name,
                transaction_type, status, description, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (client_ip, principal_id, card_id, converted_amount, "Main Balance", "funding", "completed", f"Funded {card_currency} virtual card from main balance", now),
        )

    return {
        "card_id": card_id,
        "card_currency": card_currency,
        "card_type": card[5],
        "usd_amount": round(amount_value, 2),
        "converted_amount": converted_amount,
        "exchange_rate": currency_rate,
        "main_balance_after": round(main_balance - amount_value, 2),
        "card_balance_after": round(new_balance, precision),
    }


def toggle_fake_card_freeze(client_ip: str, principal_id: str, card_id: int) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        card = _get_fake_card_row(conn, client_ip, principal_id, card_id)
        if not card:
            raise ValueError("Card or account not found")
        new_value = 0 if int(card[9] or 0) else 1
        conn.execute("UPDATE fake_cards SET is_frozen = ? WHERE id = ?", (new_value, card_id))
        return bool(new_value)


def update_fake_card_limit(client_ip: str, principal_id: str, card_id: int, new_limit: float) -> float:
    with sqlite3.connect(DB_PATH) as conn:
        card = _get_fake_card_row(conn, client_ip, principal_id, card_id)
        if not card:
            raise ValueError("Card or account not found")
        limit_value = float(new_limit)
        if limit_value < 0:
            raise ValueError("Card limit must be non-negative")
        conn.execute("UPDATE fake_cards SET card_limit = ? WHERE id = ?", (limit_value, card_id))
        return limit_value


def get_fake_card_transactions(client_ip: str, principal_id: str, card_id: int) -> list[dict[str, object]]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT amount, merchant_name, transaction_type, status, description, created_at
            FROM fake_card_transactions
            WHERE client_ip = ? AND principal_id = ? AND card_id = ?
            ORDER BY created_at DESC
            """,
            (client_ip, principal_id, card_id),
        ).fetchall()
    return [
        {
            "amount": float(row[0] or 0.0),
            "merchant": row[1],
            "transaction_type": row[2],
            "status": row[3],
            "description": row[4],
            "timestamp": row[5],
        }
        for row in rows
    ]


def apply_fake_transfer(
    client_ip: str,
    principal_id: str,
    to_account: str,
    amount: float,
    currency: str,
    description: str,
    transaction_id: str,
) -> dict[str, object]:
    """Apply transfer within deception DB only and return updated fake balance."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    amount_value = abs(float(amount))
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT id, fake_account_id, fake_balance
            FROM fake_accounts
            WHERE principal_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (principal_id,),
        ).fetchone()

        if not row:
            fallback_account_id = f"ACC-{principal_id[:12]}"
            conn.execute(
                """
                INSERT INTO fake_accounts (client_ip, principal_id, fake_username, fake_password, fake_account_id, fake_balance, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (client_ip, principal_id, principal_id, "honeypot_default_password", fallback_account_id, 50000.0, now),
            )
            row = conn.execute(
                """
                SELECT id, fake_account_id, fake_balance
                FROM fake_accounts
                WHERE principal_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (principal_id,),
            ).fetchone()

        account_id = str(row[1])
        current_balance = float(row[2]) if row[2] is not None else 50000.0
        new_balance = max(current_balance - amount_value, 0.0)

        conn.execute(
            "UPDATE fake_accounts SET fake_balance = ? WHERE id = ?",
            (new_balance, row[0]),
        )
        conn.execute(
            """
            UPDATE mirror_users
            SET balance = ?
            WHERE id = (
                SELECT id
                FROM mirror_users
                WHERE principal_id = ?
                ORDER BY created_at DESC
                LIMIT 1
            )
            """,
            (new_balance, principal_id),
        )

        conn.execute(
            """
            INSERT INTO fake_transactions (client_ip, principal_id, from_account, to_account, amount, currency, transaction_id, description, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)
            """,
            (
                client_ip,
                principal_id,
                account_id,
                to_account,
                amount_value,
                currency,
                transaction_id,
                description,
                now,
            ),
        )

    return {
        "from_account": account_id,
        "to_account": to_account,
        "amount": amount_value,
        "currency": currency,
        "description": description,
        "transaction_id": transaction_id,
        "new_balance": new_balance,
    }


def _seed_fake_billing_data(conn: sqlite3.Connection) -> None:
    category_count = conn.execute("SELECT COUNT(1) FROM fake_bill_categories").fetchone()
    if int((category_count or [0])[0]) == 0:
        conn.executemany(
            """
            INSERT INTO fake_bill_categories (id, name, description, is_active)
            VALUES (?, ?, ?, 1)
            """,
            [
                (1, "Utilities", "Water, Electricity, Gas bills"),
                (2, "Telecommunications", "Mobile, Internet, Cable TV"),
                (3, "Insurance", "Insurance premium payments"),
                (4, "Credit Cards", "Credit card bill payments"),
            ],
        )

    biller_count = conn.execute("SELECT COUNT(1) FROM fake_billers").fetchone()
    if int((biller_count or [0])[0]) == 0:
        conn.executemany(
            """
            INSERT INTO fake_billers (
                id, category_id, name, account_number, description,
                minimum_amount, maximum_amount, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """,
            [
                (1, 1, "City Water Authority", "BILL-UTIL-001", "Water utility payments", 10.0, 5000.0),
                (2, 1, "National Power Grid", "BILL-UTIL-002", "Electricity utility payments", 10.0, 10000.0),
                (3, 2, "Global Telecom", "BILL-TEL-001", "Mobile and internet subscriptions", 5.0, 3000.0),
                (4, 3, "Secure Life Insurance", "BILL-INS-001", "Insurance premium payments", 20.0, 20000.0),
                (5, 4, "Universal Bank Card", "BILL-CC-001", "Credit card payments", 50.0, 50000.0),
            ],
        )


def _ensure_billing_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fake_bill_categories (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fake_billers (
            id INTEGER PRIMARY KEY,
            category_id INTEGER,
            name TEXT NOT NULL,
            account_number TEXT,
            description TEXT,
            minimum_amount REAL DEFAULT 0,
            maximum_amount REAL,
            is_active INTEGER DEFAULT 1
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fake_bill_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT,
            principal_id TEXT,
            biller_id INTEGER,
            amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            card_id INTEGER,
            reference_number TEXT,
            status TEXT DEFAULT 'completed',
            created_at TEXT,
            processed_at TEXT,
            description TEXT
        )
        """
    )
    _seed_fake_billing_data(conn)


def get_fake_bill_categories() -> list[dict[str, object]]:
    with sqlite3.connect(DB_PATH) as conn:
        _ensure_billing_tables(conn)
        rows = conn.execute(
            """
            SELECT id, name, description
            FROM fake_bill_categories
            WHERE is_active = 1
            ORDER BY id ASC
            """
        ).fetchall()
    return [
        {"id": int(row[0]), "name": row[1], "description": row[2]}
        for row in rows
    ]


def get_fake_billers_by_category(category_id: int) -> list[dict[str, object]]:
    with sqlite3.connect(DB_PATH) as conn:
        _ensure_billing_tables(conn)
        rows = conn.execute(
            """
            SELECT id, name, account_number, description, minimum_amount, maximum_amount
            FROM fake_billers
            WHERE category_id = ? AND is_active = 1
            ORDER BY id ASC
            """,
            (int(category_id),),
        ).fetchall()
    return [
        {
            "id": int(row[0]),
            "name": row[1],
            "account_number": row[2],
            "description": row[3],
            "minimum_amount": float(row[4] or 0.0),
            "maximum_amount": float(row[5]) if row[5] is not None else None,
        }
        for row in rows
    ]


def record_fake_bill_payment(
    client_ip: str,
    principal_id: str,
    biller_id: int,
    amount: float,
    payment_method: str,
    card_id: int | None,
    description: str,
) -> dict[str, object]:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    amount_value = abs(float(amount))
    method = str(payment_method or "balance")

    with sqlite3.connect(DB_PATH) as conn:
        _ensure_billing_tables(conn)

        biller_row = conn.execute(
            """
            SELECT b.account_number, b.name, c.name
            FROM fake_billers b
            JOIN fake_bill_categories c ON b.category_id = c.id
            WHERE b.id = ?
            """,
            (int(biller_id),),
        ).fetchone()
        if not biller_row:
            raise ValueError("Biller or user account not found")

        account_row = conn.execute(
            """
            SELECT id, fake_account_id, fake_balance
            FROM fake_accounts
            WHERE principal_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (principal_id,),
        ).fetchone()
        if not account_row:
            fallback_account_id = f"ACC-{principal_id[:12]}"
            conn.execute(
                """
                INSERT INTO fake_accounts (
                    client_ip, principal_id, fake_username, fake_password,
                    fake_account_id, fake_balance, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ip,
                    principal_id,
                    principal_id,
                    "honeypot_default_password",
                    fallback_account_id,
                    50000.0,
                    now,
                ),
            )
            account_row = conn.execute(
                """
                SELECT id, fake_account_id, fake_balance
                FROM fake_accounts
                WHERE principal_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (principal_id,),
            ).fetchone()

        account_id = str(account_row[1])
        current_balance = float(account_row[2]) if account_row[2] is not None else 50000.0
        card_row = None
        if method == "virtual_card":
            if card_id is None:
                raise ValueError("Card is required for virtual card payment")
            card_row = _get_fake_card_row(conn, client_ip, principal_id, int(card_id))
            if not card_row:
                raise ValueError("Card or user account not found")
            if int(card_row[9] or 0):
                raise ValueError("Card is frozen")
            card_balance = float(card_row[8] or 0.0)
            if amount_value > card_balance:
                raise ValueError("Insufficient card balance")
        elif method == "balance" and amount_value > current_balance:
            raise ValueError("Insufficient balance")

        new_balance = current_balance
        if method == "balance":
            new_balance = max(current_balance - amount_value, 0.0)
            conn.execute(
                "UPDATE fake_accounts SET fake_balance = ? WHERE id = ?",
                (new_balance, int(account_row[0])),
            )
            conn.execute(
                """
                UPDATE mirror_users
                SET balance = ?
                WHERE id = (
                    SELECT id
                    FROM mirror_users
                    WHERE principal_id = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                )
                """,
                (new_balance, principal_id),
            )
        elif method == "virtual_card" and card_row is not None:
            new_card_balance = max(float(card_row[8] or 0.0) - amount_value, 0.0)
            conn.execute(
                """
                UPDATE fake_cards
                SET current_balance = ?, last_used_at = ?
                WHERE id = ?
                """,
                (new_card_balance, now, int(card_row[0])),
            )
            conn.execute(
                """
                INSERT INTO fake_card_transactions (
                    client_ip, principal_id, card_id, amount, merchant_name,
                    transaction_type, status, description, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ip,
                    principal_id,
                    int(card_row[0]),
                    amount_value,
                    str(biller_row[1]),
                    "bill_payment",
                    "completed",
                    description or f"{biller_row[2]} payment to {biller_row[1]}",
                    now,
                ),
            )
            new_balance = new_card_balance

        reference = f"BILL{int(time.time())}"
        conn.execute(
            """
            INSERT INTO fake_bill_payments (
                client_ip, principal_id, biller_id, amount, payment_method,
                card_id, reference_number, status, created_at, processed_at, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?)
            """,
            (
                client_ip,
                principal_id,
                int(biller_id),
                amount_value,
                method,
                int(card_id) if card_id is not None else None,
                reference,
                now,
                now,
                description or "Bill Payment",
            ),
        )

        txn_description = description or f"{biller_row[2]} payment to {biller_row[1]}"
        conn.execute(
            """
            INSERT INTO fake_transactions (
                client_ip, principal_id, from_account, to_account, amount,
                currency, transaction_id, description, status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'USD', ?, ?, 'completed', ?)
            """,
            (
                client_ip,
                principal_id,
                account_id,
                str(biller_row[0]),
                amount_value,
                reference,
                txn_description,
                now,
            ),
        )

    return {
        "reference": reference,
        "amount": amount_value,
        "payment_method": method,
        "card_id": int(card_id) if card_id is not None else None,
        "timestamp": now,
        "processed_by": principal_id,
        "new_balance": new_balance,
    }


def get_fake_bill_payments_history(client_ip: str, principal_id: str) -> list[dict[str, object]]:
    with sqlite3.connect(DB_PATH) as conn:
        _ensure_billing_tables(conn)
        rows = conn.execute(
            """
            SELECT
                bp.id,
                bp.amount,
                bp.payment_method,
                bp.reference_number,
                bp.status,
                bp.created_at,
                bp.processed_at,
                bp.description,
                b.name,
                c.name,
                vc.card_number
            FROM fake_bill_payments bp
            JOIN fake_billers b ON bp.biller_id = b.id
            JOIN fake_bill_categories c ON b.category_id = c.id
            LEFT JOIN fake_cards vc ON vc.id = bp.card_id
            WHERE bp.principal_id = ?
            ORDER BY bp.created_at DESC
            """,
            (principal_id,),
        ).fetchall()

    return [
        {
            "id": int(row[0]),
            "amount": float(row[1] or 0.0),
            "payment_method": row[2],
            "card_number": row[10],
            "reference": row[3],
            "status": row[4] or "completed",
            "created_at": row[5],
            "processed_at": row[6],
            "description": row[7],
            "biller_name": row[8],
            "category_name": row[9],
        }
        for row in rows
    ]
