import sqlite3
import os
import json
from datetime import datetime
from core import nexus_db
from core import traffic_db
from core.deception_metrics import compute_interaction_metrics

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def get_hacker_dwell_time(client_ip: str) -> dict:
    """透過資料庫比對，若上一次攻擊距離這次攻擊不到10分鐘視為滯留"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            WHERE c.ip = ?
            ORDER BY t.request_at DESC LIMIT 2
        ''', (client_ip,))
        rows = cursor.fetchall()

        cursor.execute('''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            WHERE c.ip = ?
            ORDER BY t.request_at ASC
        ''', (client_ip,))
        all_rows = cursor.fetchall()

    if not all_rows:
        return {"client_ip": client_ip, "dwell_seconds": 0, "is_active": False}

    now = datetime.now()
    latest_time = _parse_ts(all_rows[-1][0])
    first_time = _parse_ts(all_rows[0][0])

    is_active = False
    if len(rows) >= 2:
        last_req = _parse_ts(rows[0][0])
        prev_req = _parse_ts(rows[1][0])
        if (last_req - prev_req).total_seconds() <= 600:
            is_active = True
    elif len(rows) == 1:
        if (now - latest_time).total_seconds() <= 600:
            is_active = True

    dwell_seconds = int((latest_time - first_time).total_seconds())

    return {
        "client_ip": client_ip,
        "dwell_seconds": dwell_seconds,
        "is_active": is_active
    }

def analyze_interaction_depth(client_ip: str, query_id: str) -> dict:
    """使用 deception_metrics 共用邏輯估算互動深度。"""
    profile = nexus_db.get_client_profile(client_ip)
    events = profile.get("events", [])
    has_memory_hit = any(
        str(e.get("query_id")) == str(query_id) and int(e.get("is_attack") or 0) == 1
        for e in events
    )

    metrics = compute_interaction_metrics(
        client_ip=client_ip,
        query_id=query_id,
        current_payload=None,
        has_memory_hit=has_memory_hit,
    )

    return {
        "client_ip": client_ip,
        "query_id": query_id,
        "depth_score": metrics["depth_score"],
        "funnel_level": metrics["funnel_level"],
        "dwell_seconds": metrics["dwell_seconds"],
        "endpoint_coverage": metrics["endpoint_coverage"],
        "payload_evolution_score": metrics["payload_evolution_score"],
        "dimension_scores": {
            "funnel": metrics["funnel_score"],
            "dwell_time": metrics["dwell_score"],
            "endpoint_coverage": metrics["coverage_score"],
            "payload_evolution": metrics["payload_evolution_score"],
        },
    }


def get_attack_timeline(client_ip: str) -> dict:
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
        ''', (client_ip,))
        rows = cursor.fetchall()

    timeline = []
    for row in rows:
        dt = _parse_ts(row[0])
        time_str = dt.strftime("%H:%M:%S.%f")[:-3]
        action = row[1] or "normal"
        timeline.append({"time": time_str, "action": action})

    return {
        "client_ip": client_ip,
        "timeline": timeline
    }

def log_misjudgment(client_ip: str, reason: str) -> None:
    """可將IP存入誤判資料夾，以供後續AI調整"""
    os.makedirs(ERROR_LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(ERROR_LOG_DIR, f"misjudgment_{client_ip.replace('.', '_')}_{timestamp}.json")
    
    data = {
        "client_ip": client_ip,
        "reason": reason,
        "logged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def get_command_heatmap() -> dict:
    """判斷最常輸入指令前十（traffic_logs.db）"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.raw_payload, COUNT(*) as count
            FROM traffic_logs t
            JOIN attack_details d ON t.id = d.traffic_log_id
            WHERE t.is_attack = 1 AND d.raw_payload IS NOT NULL
            GROUP BY raw_payload 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        rows = cursor.fetchall()
        
    top_commands = [{"cmd": row[0], "count": row[1]} for row in rows]
    
    return {
        "top_commands": top_commands
    }

def get_ip_details(client_ip: str) -> dict:
    profile = nexus_db.get_client_profile(client_ip)
    if not profile:
        return {}

    latest = (profile.get("events") or [{}])[0]
    return {
        "client_ip": client_ip,
        "polluted_status": profile.get("client", {}).get("polluted_status", 0),
        **latest,
    }


def fetch_recent_traffic(limit: int = 100, mode: str = "all") -> dict:
    """mode: all(全流量) 或 attacks(僅攻擊流量)。"""
    if mode == "attacks":
        items = nexus_db.get_attack_summary(limit)
    else:
        items = traffic_db.get_recent_traffic(limit)
    return {"recent_traffic": items}


def auto_updates() -> dict:
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return {"update_log": f"{current_time}已更新"}


if __name__ == "__main__":
    pass

