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


def _migrate_query_id_to_principal_id(conn: sqlite3.Connection):
    """將舊版 query_id 欄位遷移為 principal_id，相容伺服器上的既有資料庫。"""
    cursor = conn.execute("PRAGMA table_info(deception_memory)")
    columns = {row[1] for row in cursor.fetchall()}
    if "principal_id" not in columns and "query_id" in columns:
        # 先刪除依賴舊欄位名稱的唯一索引（若存在），再重命名欄位
        conn.execute("DROP INDEX IF EXISTS idx_deception_memory_client_query")
        conn.execute(
            "ALTER TABLE deception_memory RENAME COLUMN query_id TO principal_id"
        )
        logger.info("[deception_db] Migrated column query_id -> principal_id.")


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
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_deception_memory_client_query ON deception_memory(client_ip, principal_id)"
    )


def setup_deception_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deception_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                principal_id TEXT,
                fake_data_payload TEXT,
                -- SQL 註解必須使用雙橫線 --
                last_vector TEXT,
                max_risk_seen INTEGER,
                interaction_count INTEGER DEFAULT 1,
                hits INTEGER DEFAULT 1,
                last_seen TEXT
            )
        """
        )
        _migrate_attacker_ip_to_client_ip(conn)
        _migrate_query_id_to_principal_id(conn)
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
