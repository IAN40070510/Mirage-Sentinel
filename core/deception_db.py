import sqlite3
import json
import os
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "mirage_memory.db")

def setup_deception_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS deception_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attacker_ip TEXT,
                query_id TEXT,
                fake_data_payload TEXT,
                -- SQL 註解必須使用雙橫線 --
                last_vector TEXT,
                max_risk_seen INTEGER,
                interaction_count INTEGER DEFAULT 1,
                hits INTEGER DEFAULT 1,
                last_seen TEXT
            )
        ''')
    print(f"[*] Deception Memory Engine Ready: {DB_PATH}")

def get_memory(ip: str, query_id: str):
    """
    讀取記憶：回傳字典以供 main.py 計算滯留時間與深度
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute('''
            SELECT fake_data_payload, last_seen, interaction_count, hits 
            FROM deception_memory 
            WHERE attacker_ip = ? AND query_id = ?
        ''', (ip, query_id))
        result = cursor.fetchone()
        
        if result:
            return {
                "payload": json.loads(result[0]),
                "last_seen": result[1],
                "depth": result[2],
                "hits": result[3]
            }
    return None

def save_deception_state(ip: str, query_id: str, vector: str, risk: int, payload: dict = None):
    """
    儲存或更新記憶：確保資料一致性 (Upsert 邏輯)
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    with sqlite3.connect(DB_PATH) as conn:
        # 檢查是否已存在紀錄
        cursor = conn.execute('SELECT id FROM deception_memory WHERE attacker_ip = ? AND query_id = ?', (ip, query_id))
        exists = cursor.fetchone()

        if exists:
            # 更新已有的紀錄
            conn.execute('''
                UPDATE deception_memory SET 
                hits = hits + 1, 
                interaction_count = interaction_count + 1, 
                last_vector = ?, 
                max_risk_seen = CASE WHEN ? > max_risk_seen THEN ? ELSE max_risk_seen END,
                last_seen = ? 
                WHERE attacker_ip = ? AND query_id = ?
            ''', (vector, risk, risk, now, ip, query_id))
        else:
            # 第一次攻擊，插入新紀錄
            if payload:
                conn.execute('''
                    INSERT INTO deception_memory (
                        attacker_ip, query_id, fake_data_payload, last_vector, max_risk_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (ip, query_id, json.dumps(payload, ensure_ascii=False), vector, risk, now))

def get_attacker_intelligence(ip: str):
    """提取駭客畫像，供 AI 引擎參考"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute('''
            SELECT last_vector, max_risk_seen, interaction_count 
            FROM deception_memory WHERE attacker_ip = ? 
            ORDER BY last_seen DESC LIMIT 1
        ''', (ip,))
        result = cursor.fetchone()
        if result:
            return {
                "vector": result[0],
                "risk": result[1],
                "count": result[2]
            }
    return None