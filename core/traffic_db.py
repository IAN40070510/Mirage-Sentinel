import sqlite3
import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def setup_traffic_db():
    """初始化日誌庫，含 3NF 正規化表結構（clients, fingerprints, traffic_logs, attack_details）"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        polluted_status INTEGER DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_agent TEXT,
        tls_fingerprint TEXT,
        UNIQUE(user_agent, tls_fingerprint)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_at TEXT NOT NULL,
        response_at TEXT,
        process_ms INTEGER,
        client_id INTEGER NOT NULL,
        fingerprint_id INTEGER,
        query_id TEXT,
        is_attack INTEGER DEFAULT 0,
        location TEXT,
        is_proxy INTEGER DEFAULT 0,
        FOREIGN KEY(client_id) REFERENCES clients(id),
        FOREIGN KEY(fingerprint_id) REFERENCES fingerprints(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_details (
        traffic_log_id INTEGER PRIMARY KEY,
        raw_payload TEXT,
        response_payload TEXT,
        attack_vector TEXT,
        risk_level INTEGER,
        hits INTEGER,
        interaction_depth INTEGER,
        dwell_time REAL,
        mitigation_status TEXT,
        FOREIGN KEY(traffic_log_id) REFERENCES traffic_logs(id)
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_logs_is_attack ON traffic_logs(is_attack)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_logs_request_at ON traffic_logs(request_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip)")

    conn.commit()
    conn.close()
    logger.info(f"Traffic Log Engine Ready: {DB_PATH}")


def log_traffic_event(data: dict):
    """寫入全流量紀錄（包含正常 / 攻擊），攻擊進一步寫入 attack_details"""
    conn = get_connection()
    cursor = conn.cursor()

    client_ip = data.get("client_ip")
    if not client_ip:
        raise ValueError("log_traffic_event requires 'client_ip' in data")

    if not data.get("request_at"):
        data["request_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    user_agent = data.get("user_agent")
    tls_fingerprint = data.get("tls_fingerprint")
    is_proxy = 1 if data.get("is_proxy") else 0
    is_attack = 1 if data.get("is_attack") else 0

    cursor.execute("INSERT OR IGNORE INTO clients (ip, polluted_status) VALUES (?, ?)", (client_ip, is_proxy))
    cursor.execute("SELECT id FROM clients WHERE ip = ?", (client_ip,))
    client_id = cursor.fetchone()["id"]

    cursor.execute("INSERT OR IGNORE INTO fingerprints (user_agent, tls_fingerprint) VALUES (?, ?)", (user_agent, tls_fingerprint))
    cursor.execute("SELECT id FROM fingerprints WHERE user_agent = ? AND tls_fingerprint = ?", (user_agent, tls_fingerprint))
    fingerprint_id = cursor.fetchone()["id"]

    cursor.execute(
        """
        INSERT INTO traffic_logs (
            request_at, response_at, process_ms, client_id, fingerprint_id,
            query_id, is_attack, location, is_proxy
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("request_at"),
            data.get("response_at"),
            data.get("process_ms"),
            client_id,
            fingerprint_id,
            data.get("query_id"),
            is_attack,
            data.get("location"),
            is_proxy,
        ),
    )

    traffic_log_id = cursor.lastrowid

    if is_attack:
        cursor.execute(
            """
            INSERT OR REPLACE INTO attack_details (
                traffic_log_id, raw_payload, response_payload, attack_vector,
                risk_level, hits, interaction_depth, dwell_time, mitigation_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                traffic_log_id,
                data.get("raw_payload"),
                json.dumps(data.get("response_payload"), ensure_ascii=False) if data.get("response_payload") is not None else None,
                data.get("attack_vector"),
                data.get("risk_level"),
                data.get("hits"),
                data.get("interaction_depth"),
                data.get("dwell_time"),
                data.get("mitigation_status"),
            ),
        )

    conn.commit()
    conn.close()


def get_recent_traffic(limit: int = 100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, c.ip AS client_ip, f.user_agent, f.tls_fingerprint, d.attack_vector,
               d.risk_level, d.hits, d.interaction_depth, d.dwell_time, d.mitigation_status
        FROM traffic_logs t
        JOIN clients c ON t.client_id = c.id
        LEFT JOIN fingerprints f ON t.fingerprint_id = f.id
        LEFT JOIN attack_details d ON d.traffic_log_id = t.id
        ORDER BY t.request_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]