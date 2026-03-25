import sqlite3
import os
import json
from datetime import datetime

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _safe_parse_datetime(value: str | None):
    """兼容有無毫秒的時間格式。"""
    if not value:
        return None

    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


def get_hacker_dwell_time(attacker_ip: str) -> dict:
    """透過資料庫比對，若上一次攻擊距離這次攻擊不到10分鐘視為滯留"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            WHERE c.ip = ? AND t.is_attack = 1
            ORDER BY t.request_at DESC
            LIMIT 2
            ''',
            (attacker_ip,)
        )
        latest_two = cursor.fetchall()

        cursor.execute(
            '''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            WHERE c.ip = ? AND t.is_attack = 1
            ORDER BY t.request_at ASC
            ''',
            (attacker_ip,)
        )
        all_rows = cursor.fetchall()

    if not all_rows:
        return {"ip": attacker_ip, "dwell_seconds": 0, "is_active": False}

    first_time = _safe_parse_datetime(all_rows[0]["request_at"])
    last_time = _safe_parse_datetime(all_rows[-1]["request_at"])

    if not first_time or not last_time:
        return {"ip": attacker_ip, "dwell_seconds": 0, "is_active": False}

    is_active = False
    now = datetime.now()

    if len(latest_two) >= 2:
        last_req = _safe_parse_datetime(latest_two[0]["request_at"])
        prev_req = _safe_parse_datetime(latest_two[1]["request_at"])
        if last_req and prev_req and (last_req - prev_req).total_seconds() <= 600:
            is_active = True
    elif len(latest_two) == 1:
        only_req = _safe_parse_datetime(latest_two[0]["request_at"])
        if only_req and (now - only_req).total_seconds() <= 600:
            is_active = True

    dwell_seconds = int((last_time - first_time).total_seconds())

    return {
        "ip": attacker_ip,
        "dwell_seconds": max(dwell_seconds, 0),
        "is_active": is_active
    }


def analyze_interaction_depth(attacker_ip: str, query_id: str) -> dict:
    """透過 attacker_ip 與 query_id 比對互動深度"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT t.request_at
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            WHERE c.ip = ? AND t.query_id = ? AND t.is_attack = 1
            ORDER BY t.request_at DESC
            ''',
            (attacker_ip, query_id)
        )
        rows = cursor.fetchall()

    total_actions = len(rows)
    depth_level = total_actions

    latest_time = _safe_parse_datetime(rows[0]["request_at"]) if rows else None
    if latest_time:
        _still_active = (datetime.now() - latest_time).total_seconds() <= 600
        # 目前 depth_level 就直接等於總互動次數，保留欄位方便未來擴充
        depth_level = total_actions

    return {
        "ip": attacker_ip,
        "query_id": query_id,
        "depth_level": depth_level,
        "total_actions": total_actions
    }


def get_attack_timeline(attacker_ip: str) -> dict:
    """視覺化呈現該駭客的行為路徑"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT
                t.request_at,
                COALESCE(a.attack_vector, 'unknown') AS attack_vector
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details a ON a.traffic_log_id = t.id
            WHERE c.ip = ? AND t.is_attack = 1
            ORDER BY t.request_at ASC
            ''',
            (attacker_ip,)
        )
        rows = cursor.fetchall()

    timeline = []
    for row in rows:
        dt = _safe_parse_datetime(row["request_at"])
        time_str = dt.strftime("%H:%M") if dt else "--:--"
        timeline.append({
            "time": time_str,
            "action": row["attack_vector"]
        })

    return {
        "ip": attacker_ip,
        "timeline": timeline
    }


def log_misjudgment(attacker_ip: str, reason: str) -> None:
    """可將IP存入誤判資料夾，以供後續AI調整"""
    os.makedirs(ERROR_LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(
        ERROR_LOG_DIR,
        f"misjudgment_{attacker_ip.replace('.', '_')}_{timestamp}.json"
    )

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
        cursor.execute(
            '''
            SELECT
                COALESCE(a.raw_payload, '(empty)') AS raw_payload,
                COUNT(*) AS count
            FROM attack_details a
            JOIN traffic_logs t ON t.id = a.traffic_log_id
            WHERE t.is_attack = 1
            GROUP BY COALESCE(a.raw_payload, '(empty)')
            ORDER BY count DESC, raw_payload ASC
            LIMIT 10
            '''
        )
        rows = cursor.fetchall()

    top_commands = [{"cmd": row["raw_payload"], "count": row["count"]} for row in rows]

    return {
        "top_commands": top_commands
    }


def get_ip_details(ip: str) -> dict:
    """取得特定 IP 最新一筆詳細資訊"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT
                c.ip AS attacker_ip,
                c.polluted_status,
                t.request_at,
                t.response_at,
                t.process_ms,
                t.query_id,
                t.is_attack,
                t.location,
                t.is_proxy,
                f.user_agent,
                f.tls_fingerprint,
                a.raw_payload,
                a.response_payload,
                a.attack_vector,
                a.risk_level,
                a.hits,
                a.interaction_depth,
                a.dwell_time,
                a.mitigation_status
            FROM clients c
            LEFT JOIN traffic_logs t ON t.client_id = c.id
            LEFT JOIN fingerprints f ON f.id = t.fingerprint_id
            LEFT JOIN attack_details a ON a.traffic_log_id = t.id
            WHERE c.ip = ?
            ORDER BY t.request_at DESC
            LIMIT 1
            ''',
            (ip,)
        )
        row = cursor.fetchone()

    if not row:
        return {
            "attacker_ip": ip,
            "polluted_status": 0,
            "request_at": None,
            "response_at": None,
            "process_ms": None,
            "query_id": None,
            "is_attack": 0,
            "location": "-",
            "is_proxy": 0,
            "user_agent": None,
            "tls_fingerprint": None,
            "raw_payload": None,
            "response_payload": None,
            "attack_vector": None,
            "risk_level": 0,
            "hits": 0,
            "interaction_depth": 0,
            "dwell_time": 0.0,
            "mitigation_status": None,
        }

    return dict(row)


if __name__ == "__main__":
    pass


def validate_api_key(api_key: str) -> bool:
    """簡單 API key 驗證，供上層 router / middleware 使用。"""
    return api_key == "dev-local-api-key-change-me"


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

        cursor.execute(
            '''
            SELECT
                c.ip AS client_ip,
                t.request_at,
                t.location,
                t.is_proxy,
                t.is_attack,
                a.attack_vector,
                a.raw_payload,
                a.risk_level,
                a.mitigation_status
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details a ON a.traffic_log_id = t.id
            ORDER BY t.request_at DESC
            LIMIT ?
            ''',
            (limit,)
        )
        detail_rows = cursor.fetchall()

    total_requests = int((row["total_requests"] or 0) if row else 0)
    attack_requests = int((row["attack_requests"] or 0) if row else 0)
    normal_requests = int((row["normal_requests"] or 0) if row else 0)

    attack_ratio = round((attack_requests / total_requests) * 100, 2) if total_requests else 0
    normal_ratio = round((normal_requests / total_requests) * 100, 2) if total_requests else 0

    all_traffic = []
    attack_traffic = []

    for row in detail_rows:
        item = {
            "client_ip": row["client_ip"],
            "request_at": row["request_at"],
            "location": row["location"] or "-",
            "is_proxy": int(row["is_proxy"] or 0),
            "is_attack": int(row["is_attack"] or 0),
            "attack_type": row["attack_vector"] or "-",
            "raw_payload": row["raw_payload"] or "-",
            "risk_level": int(row["risk_level"] or 0),
            "mitigation_status": row["mitigation_status"] or "-",
        }
        all_traffic.append(item)
        if item["is_attack"] == 1:
            attack_traffic.append(item)

    return {
        "total_requests": total_requests,
        "attack_requests": attack_requests,
        "normal_requests": normal_requests,
        "attack_ratio": attack_ratio,
        "normal_ratio": normal_ratio,
        "all_traffic": all_traffic,
        "attack_traffic": attack_traffic,
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
                MAX(a.attack_vector) AS attack_vector,
                MAX(a.raw_payload) AS raw_payload
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details a ON a.traffic_log_id = t.id
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
        "protocol": details.get("tls_fingerprint", "-"),
        "port": details.get("query_id", "-"),
        "behavior": attack_vector,
        "payload": raw_payload,
        "timeline": timeline_data.get("timeline", []),
        "dwell_seconds": dwell.get("dwell_seconds", 0),
        "is_active": dwell.get("is_active", False),
        "details": details,
    }


def fetch_recent_traffic(limit: int = 100, mode: str = "all") -> list:
    """取得近期流量紀錄，mode=all 或 attacks。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        sql = '''
            SELECT
                t.id,
                t.request_at,
                t.response_at,
                t.process_ms,
                t.query_id,
                t.is_attack,
                t.location,
                t.is_proxy,
                c.ip AS client_ip,
                c.polluted_status,
                f.user_agent,
                f.tls_fingerprint,
                a.raw_payload,
                a.response_payload,
                a.attack_vector,
                a.risk_level,
                a.hits,
                a.interaction_depth,
                a.dwell_time,
                a.mitigation_status
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN fingerprints f ON f.id = t.fingerprint_id
            LEFT JOIN attack_details a ON a.traffic_log_id = t.id
        '''

        params = []
        if mode == "attacks":
            sql += " WHERE t.is_attack = 1 "

        sql += " ORDER BY t.request_at DESC LIMIT ? "
        params.append(limit)

        cursor.execute(sql, params)
        rows = cursor.fetchall()

    return [dict(row) for row in rows]


def auto_updates() -> dict:
    """給儀表板輪詢使用的簡易更新資訊。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM traffic_logs")
        total_logs = int(cursor.fetchone()["total"] or 0)

        cursor.execute("SELECT MAX(request_at) AS latest_request_at FROM traffic_logs")
        latest_request_at = cursor.fetchone()["latest_request_at"]

    return {
        "status": "ok",
        "total_logs": total_logs,
        "latest_request_at": latest_request_at,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }