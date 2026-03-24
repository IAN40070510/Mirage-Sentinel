import sqlite3
import os

# Nexus 只負責查詢/分析，寫入由 traffic_db 處理。
CURRENT_FILE_PATH = os.path.abspath(__file__)
CORE_DIR = os.path.dirname(CURRENT_FILE_PATH)
PROJECT_ROOT = os.path.dirname(CORE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")


def get_connection():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Traffic DB not initialized: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_attack_summary(limit: int = 100):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT t.id, t.request_at, t.response_at, c.ip AS client_ip,
               f.user_agent, f.tls_fingerprint, d.attack_vector, d.risk_level,
               d.hits, d.interaction_depth, d.dwell_time, d.mitigation_status
        FROM traffic_logs t
        JOIN clients c ON t.client_id = c.id
        LEFT JOIN fingerprints f ON t.fingerprint_id = f.id
        LEFT JOIN attack_details d ON d.traffic_log_id = t.id
        WHERE t.is_attack = 1
        ORDER BY t.request_at DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_traffic_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(1) AS total FROM traffic_logs")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(1) AS attacks FROM traffic_logs WHERE is_attack = 1")
    attacks = cursor.fetchone()["attacks"]

    cursor.execute("SELECT COUNT(1) AS normals FROM traffic_logs WHERE is_attack = 0")
    normals = cursor.fetchone()["normals"]

    conn.close()
    return {
        "total": total,
        "attacks": attacks,
        "normals": normals,
        "attack_rate": round(attacks / (total or 1), 4)
    }


def get_client_profile(client_ip: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, ip, polluted_status FROM clients WHERE ip = ?", (client_ip,))
    client = cursor.fetchone()
    if not client:
        conn.close()
        return {}

    cursor.execute("""
        SELECT t.id, t.request_at, t.response_at, t.query_id, t.is_attack,
               d.attack_vector, d.risk_level, d.hits, d.interaction_depth, d.dwell_time
        FROM traffic_logs t
        LEFT JOIN attack_details d ON d.traffic_log_id = t.id
        WHERE t.client_id = ?
        ORDER BY t.request_at DESC
        LIMIT 50
    """, (client["id"],))

    events = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {
        "client": dict(client),
        "events": events
    }
