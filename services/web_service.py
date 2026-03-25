import sqlite3
import os
import json
from datetime import datetime

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_nexus.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

def get_hacker_dwell_time(attacker_ip: str) -> dict:
    """透過資料庫比對，若上一次攻擊距離這次攻擊不到10分鐘視為滯留"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 取出該 IP 最新兩筆時間
        cursor.execute('''
            SELECT timestamp FROM nexus_activity 
            WHERE attacker_ip = ? 
            ORDER BY timestamp DESC LIMIT 2
        ''', (attacker_ip,))
        rows = cursor.fetchall()
        
        # 取得第一筆與最後一筆算總長度
        cursor.execute('''
            SELECT timestamp FROM nexus_activity 
            WHERE attacker_ip = ? 
            ORDER BY timestamp ASC
        ''', (attacker_ip,))
        all_rows = cursor.fetchall()

    if not all_rows:
        return {"ip": attacker_ip, "dwell_seconds": 0, "is_active": False}
        
    now = datetime.now()
    latest_time = datetime.strptime(all_rows[-1][0], "%Y-%m-%d %H:%M:%S")
    first_time = datetime.strptime(all_rows[0][0], "%Y-%m-%d %H:%M:%S")
    
    is_active = False
    if len(rows) >= 2:
        last_req = datetime.strptime(rows[0][0], "%Y-%m-%d %H:%M:%S.%f")
        prev_req = datetime.strptime(rows[1][0], "%Y-%m-%d %H:%M:%S.%f")
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
    """透過att_id與query_id比對，若上一次攻擊距離這次攻擊不到10分鐘視為仍在互動"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp FROM nexus_activity 
            WHERE attacker_ip = ? AND query_id = ?
            ORDER BY timestamp DESC
        ''', (attacker_ip, query_id))
        rows = cursor.fetchall()
        
    depth_level = 0
    total_actions = len(rows)
    
    if total_actions > 0:
        latest_time = datetime.strptime(rows[0][0], "%Y-%m-%d %H:%M:%S.%f")
        if (datetime.now() - latest_time).total_seconds() <= 600:
            depth_level = total_actions
        else:
            depth_level = total_actions

    return {
        "ip": attacker_ip,
        "depth_level": depth_level,
        "total_actions": total_actions
    }

def get_attack_timeline(attacker_ip: str) -> dict:
    """視覺化呈現該駭客的行為路徑"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, attack_vector FROM nexus_activity 
            WHERE attacker_ip = ?
            ORDER BY timestamp ASC
        ''', (attacker_ip,))
        rows = cursor.fetchall()
        
    timeline = []
    for row in rows:
        dt = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
        time_str = dt.strftime("%H:%M")
        action = row[1]
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

def get_ip_details(ip : str) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT *
        FROM nexus_activity 
        WHERE attacker_ip = ? 
    ''', (ip,))

    row = cursor.fetchone()

    conn.close()
    return dict(row)

if __name__ == "__main__":
    pass


def validate_api_key(api_key: str) -> bool:
    """簡單 API key 驗證，供上層 router / middleware 使用。"""
    return api_key == "replace-with-a-strong-random-key"


def fetch_all_client_ips(limit: int = 500) -> dict:
    """回傳資料庫中所有 client IP，並附帶簡易流量與風險資訊。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT
                c.ip,
                c.polluted_status,
                COUNT(t.id) AS total_requests,
                SUM(CASE WHEN t.is_attack = 1 THEN 1 ELSE 0 END) AS attack_requests,
                MAX(t.request_at) AS latest_request_at,
                MAX(t.location) AS location
            FROM clients c
            LEFT JOIN traffic_logs t ON c.id = t.client_id
            GROUP BY c.id, c.ip, c.polluted_status
            ORDER BY total_requests DESC, c.ip ASC
            LIMIT ?
            ''',
            (limit,)
        )
        rows = cursor.fetchall()

    items = []
    for row in rows:
        total_requests = int(row["total_requests"] or 0)
        attack_requests = int(row["attack_requests"] or 0)
        if attack_requests >= 10 or int(row["polluted_status"] or 0) == 1:
            risk = "HIGH"
        elif attack_requests > 0:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        items.append({
            "ip": row["ip"],
            "traffic": total_requests,
            "attack_requests": attack_requests,
            "normal_requests": max(total_requests - attack_requests, 0),
            "country": row["location"] or "-",
            "risk": risk,
            "polluted_status": int(row["polluted_status"] or 0),
            "latest_request_at": row["latest_request_at"],
        })

    return {"items": items}


def compare_traffic(limit: int = 1000) -> dict:
    """對比正常與攻擊流量，供圓餅圖或總覽使用。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT
                COUNT(*) AS total_requests,
                SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) AS attack_requests,
                SUM(CASE WHEN is_attack = 0 THEN 1 ELSE 0 END) AS normal_requests
            FROM (
                SELECT id, is_attack
                FROM traffic_logs
                ORDER BY request_at DESC
                LIMIT ?
            )
            ''',
            (limit,)
        )
        row = cursor.fetchone()

    total_requests = int((row["total_requests"] or 0) if row else 0)
    attack_requests = int((row["attack_requests"] or 0) if row else 0)
    normal_requests = int((row["normal_requests"] or 0) if row else 0)

    attack_ratio = round((attack_requests / total_requests) * 100, 2) if total_requests else 0
    normal_ratio = round((normal_requests / total_requests) * 100, 2) if total_requests else 0

    return {
        "total_requests": total_requests,
        "attack_requests": attack_requests,
        "normal_requests": normal_requests,
        "attack_ratio": attack_ratio,
        "normal_ratio": normal_ratio,
    }


def set_log_category(category_name: str, items: list | None = None) -> dict:
    """保留給前端類別系統使用，先回傳標準格式。"""
    return {
        "category_name": category_name,
        "items": items or [],
        "status": "ready"
    }


def execute_terminal_cmd(command_text: str, selected_ip: str | None = None) -> dict:
    """保留給指令框使用，避免在 service 層直接執行系統指令。"""
    normalized = (command_text or "").strip()
    return {
        "status": "accepted" if normalized else "empty",
        "command": normalized,
        "selected_ip": selected_ip,
        "message": "請在 router / controller 層自行決定如何處理此命令。"
    }


def generate_hacker_pdf(client_ip: str) -> dict:
    """先回傳報告資料結構，PDF 生成可之後在 router 或專用 service 實作。"""
    dwell = get_hacker_dwell_time(client_ip)
    timeline = get_attack_timeline(client_ip)
    details = get_ip_details(client_ip)
    traffic_summary = compare_traffic()

    return {
        "report_type": "hacker_pdf_payload",
        "client_ip": client_ip,
        "dwell": dwell,
        "details": details,
        "timeline": timeline,
        "traffic_summary": traffic_summary,
    }


def get_dashboard_ip_bundle(client_ip: str) -> dict:
    """整合主視窗常用資訊。"""
    dwell = get_hacker_dwell_time(client_ip)
    timeline_data = get_attack_timeline(client_ip)
    details = get_ip_details(client_ip)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT
                MAX(t.location) AS location,
                COUNT(t.id) AS traffic,
                MAX(d.attack_vector) AS attack_vector,
                MAX(d.raw_payload) AS raw_payload
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE c.ip = ?
            ''',
            (client_ip,)
        )
        row = cursor.fetchone()

    traffic = int((row["traffic"] or 0) if row else 0)
    attack_vector = (row["attack_vector"] if row else None) or details.get("attack_vector") or "-"
    raw_payload = (row["raw_payload"] if row else None) or details.get("raw_payload") or "-"

    if details.get("polluted_status") == 1 or dwell.get("is_active"):
        risk = "HIGH"
    elif traffic > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "client_ip": client_ip,
        "country": (row["location"] if row else None) or "-",
        "traffic": traffic,
        "risk": risk,
        "protocol": details.get("protocol", "-"),
        "port": details.get("port", "-"),
        "behavior": attack_vector,
        "payload": raw_payload,
        "timeline": timeline_data.get("timeline", []),
        "dwell_seconds": dwell.get("dwell_seconds", 0),
        "is_active": dwell.get("is_active", False),
        "details": details,
    }
