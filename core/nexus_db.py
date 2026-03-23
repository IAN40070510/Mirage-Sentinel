import sqlite3
import json
import os

# 前端專用的資料庫，包含好的與壞的資訊，用於前端展示和分析。這個資料庫不包含敏感資訊，僅用於統計和展示攻擊活動的趨勢和模式。

CURRENT_FILE_PATH = os.path.abspath(__file__)
CORE_DIR = os.path.dirname(CURRENT_FILE_PATH)
PROJECT_ROOT = os.path.dirname(CORE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_nexus.db")

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_security_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nexus_activity(
        id INTEGER PRIMARY KEY AUTOINCREMENT, --- 預設自動增加id
        attacker_ip TEXT NOT NULL, --- 攻擊者IP地址
        user_agent TEXT, --- 攻擊者的User-Agent字符串
        tls_fingerprint TEXT, --- 攻擊者的TLS指紋
        is_proxy BOOLEAN DEFAULT 0, --- 是否使用代理
        timestamp DATETIME DEFAULT (datetime('now','localtime')), --- 記錄攻擊時間
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
    conn.close()

def save_cache(attacker_ip: str, user_agent: str, tls_fingerprint: str, is_proxy: bool, 
               raw_payload: dict, attack_vector: str, risk_level: int, 
               response_payload: dict, query_id: str):
    
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT 1 FROM nexus_activity WHERE attacker_ip = ? AND query_id = ?", (attacker_ip, query_id))
        if cursor.fetchone():
            cursor.execute("""
                UPDATE nexus_activity 
                SET hits = hits + 1,
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

def get_cache(ip: str, query_id: str) -> dict:
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM nexus_activity WHERE attacker_ip = ? AND query_id = ?", (ip, query_id))
        result = cursor.fetchone()
        if result:
            return {
                "attacker_ip": result["attacker_ip"],
                "user_agent": result["user_agent"],
                "tls_fingerprint": result["tls_fingerprint"],
                "is_proxy": bool(result["is_proxy"]),
                "raw_payload": json.loads(result["raw_payload"]),
                "attack_vector": result["attack_vector"],
                "risk_level": result["risk_level"],
                "response_payload": json.loads(result["response_payload"]),
                "query_id": result["query_id"],
            }
        return {}
    except Exception as e:
        print(f"Error getting cache: {e}")
        return {}
    finally:
        conn.close()


if __name__ == "__main__":
    init_security_db()
    save_cache("192.168.1.1", "Mozilla/5.0", "tls_1", False, {"cmd": "whoami"}, "SQLi", 5, {"res": "ok"}, "q_101")
    print(get_cache("192.168.1.1", "q_101"))