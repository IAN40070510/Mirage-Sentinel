import sqlite3
import json
from datetime import datetime

# 幻影記憶庫的 SQLite 資料庫路徑
DB_PATH = "sqlite_memory.db"

def setup_mirage_database():
    """初始化幻影記憶庫"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS deception_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker_ip TEXT,          -- 攻擊者 IP
            query_id TEXT,             -- 查詢標靶 (如 1001, admin)
            fake_data_payload TEXT,    -- JSON 假資料
            hits INTEGER DEFAULT 1,    -- 攻擊次數
            risk_level INTEGER,        -- 風險等級 (對齊簡報 SQL)
            raw_payload TEXT,          --  新增：駭客輸入的原始字串 (How)
            attack_vector TEXT,        --  新增：系統判定的攻擊類別 (How)
            user_agent TEXT,           --  新增：駭客使用的瀏覽器或工具指紋 (Who)
            created_at TIMESTAMP,      -- 首次建檔時間
            last_seen TIMESTAMP        -- 最後攻擊時間
        )
    ''')
    conn.commit()
    conn.close()

def get_memory(ip: str, query_id: str):
    """讀取記憶：若駭客重複攻擊，回傳一樣的假資料並增加 hits"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT fake_data_payload FROM deception_logs 
        WHERE attacker_ip = ? AND query_id = ?
    ''', (ip, query_id))
    result = cursor.fetchone()
    
    if result:
        # 更新最後看見時間與攻擊次數
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            UPDATE deception_logs 
            SET hits = hits + 1, last_seen = ? 
            WHERE attacker_ip = ? AND query_id = ?
        ''', (now_str, ip, query_id))
        conn.commit()
        conn.close()
        return json.loads(result[0])
        
    conn.close()
    return None

def save_memory(ip: str, query_id: str, payload: dict, risk_level: int, raw_payload: str, attack_vector: str, user_agent: str):
    """寫入記憶：首次遭受到該 IP 攻擊時，寫入假資料與風險分數、情報特徵"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute('''
        INSERT INTO deception_logs (
            attacker_ip, query_id, fake_data_payload, risk_level, 
            raw_payload, attack_vector, user_agent, created_at, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip, query_id, json.dumps(payload), risk_level, raw_payload, attack_vector, user_agent, now_str, now_str))
    conn.commit()
    conn.close()