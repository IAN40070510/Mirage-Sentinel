import sqlite3
import os
import json
from datetime import datetime

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")

def setup_traffic_db():
    """初始化戰情室日誌庫 (對齊試算表規格)"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                -- 時間維度 (When)
                request_at TEXT,
                response_at TEXT,
                process_ms INTEGER,
                -- 駭客畫像 (Who)
                attacker_ip TEXT,
                location TEXT,
                is_proxy INTEGER,        -- 0: False, 1: True
                user_agent TEXT,
                tls_fingerprint TEXT,
                -- 攻防內容 (Content)
                raw_payload TEXT,
                response_payload TEXT,
                query_id TEXT,
                -- 威脅分析 (How)
                attack_vector TEXT,
                risk_level INTEGER,
                -- 行為偵測 (Why)
                hits INTEGER,
                interaction_depth INTEGER,
                dwell_time FLOAT,
                -- 防禦狀態 (Status)
                mitigation_status TEXT
            )
        ''')
    print(f"[*] Traffic Log Engine Ready: {DB_PATH}")

def log_attack_event(data: dict):
    """將合併後的試算表數據存入日誌"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            INSERT INTO attack_events (
                request_at, response_at, process_ms, attacker_ip, location, 
                is_proxy, user_agent, tls_fingerprint, raw_payload, 
                response_payload, query_id, attack_vector, risk_level, 
                hits, interaction_depth, dwell_time, mitigation_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get("request_at"), data.get("response_at"), data.get("process_ms"),
            data.get("attacker_ip"), data.get("location"), data.get("is_proxy"),
            data.get("user_agent"), data.get("tls_fingerprint"), data.get("raw_payload"),
            json.dumps(data.get("response_payload"), ensure_ascii=False),
            data.get("query_id"), data.get("attack_vector"), data.get("risk_level"),
            data.get("hits"), data.get("interaction_depth"), data.get("dwell_time"),
            data.get("mitigation_status")
        ))