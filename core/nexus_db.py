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
<<<<<<< Updated upstream
        SELECT t.id, t.request_at, t.response_at, c.ip AS attacker_ip,
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
=======
    CREATE TABLE IF NOT EXISTS nexus_activity(
        id INTEGER PRIMARY KEY AUTOINCREMENT, --- 預設自動增加id
        attacker_ip TEXT NOT NULL, --- 攻擊者IP地址
        user_agent TEXT, --- 攻擊者的User-Agent字符串
        tls_fingerprint TEXT, --- 攻擊者的TLS指紋
        is_proxy BOOLEAN DEFAULT 0, --- 是否使用代理
        timestamp DATETIME, --- 記錄攻擊時間
        raw_payload TEXT, --- 原始惡意代碼
        attack_vector TEXT, --- 攻擊向量類型
        risk_level INTEGER DEFAULT 0, --- 風險評級
        response_payload TEXT, --- 反饋給攻擊者的響應內容
        query_id TEXT, --- 攻擊的對象
        hits INTEGER DEFAULT 1, --- 攻擊次數
        interaction_depth INTEGER DEFAULT 0, --- 互動深度
        dwell_time FLOAT DEFAULT 0.0, --- 滯留時間
        mitigation_status TEXT DEFAULT 'monitored' --- 緩解狀態
    )
    """)
    conn.commit()
>>>>>>> Stashed changes
    conn.close()
    return [dict(row) for row in rows]


def get_traffic_stats():
    conn = get_connection()
    cursor = conn.cursor()

<<<<<<< Updated upstream
    cursor.execute("SELECT COUNT(1) AS total FROM traffic_logs")
    total = cursor.fetchone()["total"]
=======
    try:
        cursor.execute("SELECT 1 FROM nexus_activity WHERE attacker_ip = ? AND query_id = ?", (attacker_ip, query_id))
        if cursor.fetchone():
            cursor.execute("""
                UPDATE nexus_activity 
                SET hits = hits + 1
                WHERE attacker_ip = ? AND query_id = ?
            """, (attacker_ip, query_id))
        else:
            cursor.execute("""
                INSERT INTO nexus_activity (
                    attacker_ip, user_agent, tls_fingerprint, is_proxy, 
                    raw_payload, attack_vector, risk_level, response_payload, 
                    query_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (attacker_ip, user_agent, tls_fingerprint, is_proxy, 
                  json.dumps(raw_payload), attack_vector, risk_level, 
                  json.dumps(response_payload), query_id))
        conn.commit()
    except Exception as e:
        print(f"Error saving cache: {e}")
    finally:
        conn.close()
>>>>>>> Stashed changes

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


def get_client_profile(ip: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, ip, polluted_status FROM clients WHERE ip = ?", (ip,))
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

<<<<<<< Updated upstream
    events = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {
        "client": dict(client),
        "events": events
    }
=======
# if __name__ == "__main__":
#     init_security_db()
#     save_cache("192.168.1.1", "Mozilla/5.0", "tls_1", False, {"cmd": "whoami"}, "SQLi", 5, {"res": "ok"}, "q_101")
#     print(get_cache("192.168.1.1", "q_101"))
>>>>>>> Stashed changes
