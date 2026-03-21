import sqlite3
import json

def init_security_db():
    # 連接指定資料庫 traffic_nexus.db
    conn = sqlite3.connect("traffic_nexus.db")

    cursor = conn.cursor()

    # Query_id 是被攻擊的員工編號，fake_data_payload 是我們提供的假資料，hits 是被攻擊的次數
    cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS deception_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attacker_ip TEXT,
        query_id TEXT,
        fake_data_payload TEXT,
        hits INTEGER,
        risk_level INTEGER,
        created_at TIMESTAMP,
        last_seen TIMESTAMP
    )               
    """)

    conn.commit()
    conn.close()

def save_cache(ip: str, query_id: str, payload: dict, risk_level: int , created_at: str, last_seen: str):
    
    conn = sqlite3.connect("traffic_nexus.db")

    cursor = conn.cursor()

    try:
        cursor.execute("select 1 from deception_logs where attacker_ip = ? and query_id = ?", (ip, query_id))
        if cursor.fetchone():
            cursor.execute("update deception_logs set hits = hits + 1, last_seen = ? where attacker_ip = ? and query_id = ?", (last_seen, ip, query_id))
        else:
            cursor.execute("insert into deception_logs (attacker_ip, query_id, fake_data_payload, hits, risk_level, created_at, last_seen) values (?, ?, ?, 1, ?, ?, ?)", (ip, query_id, json.dumps(payload), risk_level, created_at, last_seen))
        conn.commit()
    except Exception as e:
        print(f"Error saving cache: {e}")
    
    conn.close()

def get_cache(ip: str, query_id: str) -> dict:
    
    conn = sqlite3.connect("traffic_nexus.db")

    cursor = conn.cursor()

    try:
        cursor.execute("select * from deception_logs where attacker_ip = ? and query_id = ?", (ip, query_id))
        result = cursor.fetchone()
        if result:
            conn.close()
            return {"attacker_ip": result[1],"query_id": result[2],"fake_data_payload": json.loads(result[3]), "hits": result[4], "risk_level": result[5], "created_at": result[6], "last_seen": result[7]}
        else:
            conn.close()
            return {}
    except Exception as e:
        print(f"Error getting cache: {e}")
        conn.close()
        return {}
    
# init_security_db()
# save_cache("192.168.1.1", "query_1", {"data": "fake_data"}, 5, "2023-01-01 00:00:00", "2023-01-01 00:00:00")
# print(get_cache("192.168.1.1", "query_1"))