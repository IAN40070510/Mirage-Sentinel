import sqlite3
import json
import os
import logging
from datetime import datetime

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


from typing import Any


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
) -> bool:
    """記錄攻擊者的假卡片信息"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO fake_cards (client_ip, principal_id, card_number, card_holder, expiry, cvv, card_type, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (client_ip, principal_id, card_number, card_holder, expiry, cvv, card_type, now)
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
            SELECT card_number, card_holder, expiry, cvv, card_type, created_at
            FROM fake_cards
            WHERE client_ip = ? AND principal_id = ?
            ORDER BY created_at DESC
            """,
            (client_ip, principal_id)
        )
        results = cursor.fetchall()
        return [
            {
                "card_number": row[0],
                "card_holder": row[1],
                "expiry": row[2],
                "cvv": row[3],
                "card_type": row[4],
                "created_at": row[5]
            }
            for row in results
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
