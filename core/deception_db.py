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
                
                # --- 新增：Agent 餵給 AI 的情報欄位 ---
                last_vector TEXT,        -- 紀錄駭客上次用的招式 (如 SQLi)
                max_risk_seen INTEGER,   -- 紀錄看過的最高風險分數
                interaction_count INTEGER DEFAULT 1, -- 互動次數，次數越高 AI 越客製化
                
                hits INTEGER DEFAULT 1,
                last_seen TIMESTAMP
            )
        ''')

def get_memory(ip: str, query_id: str):
    """讀取記憶：若駭客重複攻擊，回傳一樣的假資料並增加 hits"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute('SELECT fake_data_payload FROM deception_memory WHERE attacker_ip = ? AND query_id = ?', (ip, query_id))
        result = cursor.fetchone()
        if result:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute('''
                UPDATE deception_memory 
                SET hits = hits + 1, interaction_count = interaction_count + 1, last_seen = ? 
                WHERE attacker_ip = ? AND query_id = ?
            ''', (now, ip, query_id))
            return json.loads(result[0])
    return None

def get_attacker_intelligence(ip: str):
    """關鍵函數：提取駭客畫像，準備餵給 Mirage Engine"""
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

def save_deception_state(ip: str, query_id: str, payload: dict, vector: str, risk: int):
    """寫入記憶：同步存入本次攻擊的特徵"""
    with sqlite3.connect(DB_PATH) as conn:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute('''
            INSERT INTO deception_memory (
                attacker_ip, query_id, fake_data_payload, last_vector, max_risk_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (ip, query_id, json.dumps(payload), vector, risk, now))