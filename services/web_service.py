import sqlite3
import os
import json
from datetime import datetime
from core.traffic_db import get_recent_traffic

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_hacker_dwell_time(attacker_ip: str) -> dict:
    """透過資料庫比對，若上一次攻擊距離這次攻擊不到10分鐘視為滯留"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            WHERE c.ip = ?
            ORDER BY t.request_at DESC LIMIT 2
        ''', (attacker_ip,))
        rows = cursor.fetchall()

        cursor.execute('''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            WHERE c.ip = ?
            ORDER BY t.request_at ASC
        ''', (attacker_ip,))
        all_rows = cursor.fetchall()

    if not all_rows:
        return {"ip": attacker_ip, "dwell_seconds": 0, "is_active": False}

    now = datetime.now()
    latest_time = datetime.strptime(all_rows[-1][0], "%Y-%m-%d %H:%M:%S")
    first_time = datetime.strptime(all_rows[0][0], "%Y-%m-%d %H:%M:%S")

    is_active = False
    if len(rows) >= 2:
        last_req = datetime.strptime(rows[0][0], "%Y-%m-%d %H:%M:%S")
        prev_req = datetime.strptime(rows[1][0], "%Y-%m-%d %H:%M:%S")
        if (last_req - prev_req).total_seconds() <= 600:
            is_active = True
    elif len(rows) == 1:
        if (now - latest_time).total_seconds() <= 600:
            is_active = True

    dwell_seconds = int((latest_time - first_time).total_seconds())

    return {
        "ip": attacker_ip,
        "dwell_seconds": dwell_seconds,
        "is_active": is_active
    }

def analyze_interaction_depth(attacker_ip: str, query_id: str) -> dict:
    """透過 IP 與 query_id 對應互動深度"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            WHERE c.ip = ? AND t.query_id = ?
            ORDER BY t.request_at DESC
        ''', (attacker_ip, query_id))
        rows = cursor.fetchall()

    depth_level = len(rows)

    return {
        "ip": attacker_ip,
        "depth_level": depth_level,
        "total_actions": depth_level
    }


def get_attack_timeline(attacker_ip: str) -> dict:
    """視覺化呈現該駭客的行為路徑"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT t.request_at, d.attack_vector
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            LEFT JOIN attack_details d ON t.id = d.traffic_log_id
            WHERE c.ip = ?
            ORDER BY t.request_at ASC
        ''', (attacker_ip,))
        rows = cursor.fetchall()

    timeline = []
    for row in rows:
        dt = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        time_str = dt.strftime("%H:%M")
        action = row[1] or "normal"
        timeline.append({"time": time_str, "action": action})

    return {
        "ip": attacker_ip,
        "timeline": timeline
    }

def log_misjudgment(attacker_ip: str, reason: str) -> None:
    """可將IP存入誤判資料夾，以供後續AI調整"""
    os.makedirs(ERROR_LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(ERROR_LOG_DIR, f"misjudgment_{attacker_ip.replace('.', '_')}_{timestamp}.json")
    
    data = {
        "attacker_ip": attacker_ip,
        "reason": reason,
        "logged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def get_command_heatmap() -> dict:
    """判斷最常輸入指令前十"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT raw_payload, COUNT(*) as count 
            FROM nexus_activity 
            GROUP BY raw_payload 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        rows = cursor.fetchall()
        
    top_commands = [{"cmd": row[0], "count": row[1]} for row in rows]
    
    return {
        "top_commands": top_commands
    }

def auto_updates() -> dict:
    """每5秒自動讀取資料庫更新儀表板"""
    # 僅回傳當前時間與已更新字串
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "update_log": f"{current_time}已更新"
    }

def get_ip_details(ip: str) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT t.id, t.request_at, t.response_at, t.process_ms, c.ip AS attacker_ip,
               t.query_id, t.is_attack, d.raw_payload, d.attack_vector, d.risk_level,
               d.hits, d.interaction_depth, d.dwell_time, d.mitigation_status
        FROM traffic_logs t
        JOIN clients c ON t.client_id = c.id
        LEFT JOIN attack_details d ON t.id = d.traffic_log_id
        WHERE c.ip = ?
        ORDER BY t.request_at DESC
        LIMIT 1
    ''', (ip,))

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


def fetch_recent_traffic(limit: int = 100) -> dict:
    items = get_recent_traffic(limit)
    return {"recent_traffic": items}


def compare_traffic():
    conn = get_db_connection()
    cursor = conn.cursor()

    return

def set_log_category():
    return

# def execute_terminal_cmd():
#     return



if __name__ == "__main__":
    pass

