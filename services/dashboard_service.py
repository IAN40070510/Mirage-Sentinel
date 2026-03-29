import json
import logging
import os
import sqlite3
from datetime import datetime

from core.traffic_db import get_recent_traffic as core_get_recent_traffic

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")
DEFAULT_DEV_API_KEY = "dev-local-api-key-change-me"


def get_db_connection():
    """取得 SQLite 連線並套用基本最佳化。"""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")
    return conn



def _parse_ts(ts: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unsupported timestamp format: {ts}")



def validate_api_key(api_key: str | None) -> bool:
    expected_key = os.getenv("API_KEY", "").strip() or DEFAULT_DEV_API_KEY
    return bool(api_key) and api_key == expected_key



def get_hacker_dwell_time(client_ip: str) -> dict:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT t.request_at
                FROM traffic_logs t
                JOIN clients c ON c.id = t.client_id
                WHERE c.ip = ? AND t.is_attack = 1
                ORDER BY t.request_at ASC
                """,
                (client_ip,),
            )
            rows = cursor.fetchall()

        if not rows:
            return {"client_ip": client_ip, "dwell_seconds": 0, "is_active": False}

        first_time = _parse_ts(rows[0][0])
        latest_time = _parse_ts(rows[-1][0])
        dwell_seconds = int(max((latest_time - first_time).total_seconds(), 0))
        is_active = (datetime.now() - latest_time).total_seconds() <= 600

        return {
            "client_ip": client_ip,
            "dwell_seconds": dwell_seconds,
            "is_active": is_active,
        }
    except Exception as exc:
        logger.error("Failed to get dwell time for %s: %r", client_ip, exc)
        return {
            "client_ip": client_ip,
            "dwell_seconds": 0,
            "is_active": False,
            "error": str(exc),
        }



def analyze_interaction_depth(client_ip: str, query_id: str) -> dict:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM traffic_logs t
                JOIN clients c ON c.id = t.client_id
                WHERE c.ip = ? AND t.query_id = ? AND t.is_attack = 1
                """,
                (client_ip, query_id),
            )
            total_actions = int((cursor.fetchone() or [0])[0])

        return {
            "client_ip": client_ip,
            "query_id": query_id,
            "interaction_depth": total_actions,
            "depth_level": total_actions,
            "total_actions": total_actions,
        }
    except Exception as exc:
        logger.error("Failed to analyze interaction depth for %s: %r", client_ip, exc)
        return {
            "client_ip": client_ip,
            "query_id": query_id,
            "interaction_depth": 0,
            "depth_level": 0,
            "total_actions": 0,
            "error": str(exc),
        }



def get_attack_timeline(attacker_ip: str) -> dict:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT t.request_at, COALESCE(d.attack_vector, 'attack') AS attack_vector
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE c.ip = ? AND t.is_attack = 1
            ORDER BY t.request_at ASC
            """,
            (attacker_ip,),
        )
        rows = cursor.fetchall()

    timeline = []
    for row in rows:
        dt = _parse_ts(row[0])
        timeline.append({"time": dt.strftime("%H:%M"), "action": row[1]})

    return {"ip": attacker_ip, "timeline": timeline}



def log_misjudgment(attacker_ip: str, reason: str) -> None:
    os.makedirs(ERROR_LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(
        ERROR_LOG_DIR,
        f"misjudgment_{attacker_ip.replace('.', '_')}_{timestamp}.json",
    )
    data = {
        "attacker_ip": attacker_ip,
        "reason": reason,
        "logged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
    }
    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)



def get_command_heatmap() -> dict:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COALESCE(d.raw_payload, t.query_id, '-') AS cmd, COUNT(*) AS count
            FROM traffic_logs t
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE t.is_attack = 1
            GROUP BY cmd
            ORDER BY count DESC
            LIMIT 10
            """
        )
        rows = cursor.fetchall()

    return {"top_commands": [{"cmd": row[0], "count": row[1]} for row in rows]}



def get_ip_details(ip: str) -> dict:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                c.ip AS client_ip,
                MAX(t.location) AS location,
                COUNT(t.id) AS hits,
                MAX(t.query_id) AS query_id,
                MAX(t.tls_fingerprint) AS tls_fingerprint,
                MAX(d.attack_vector) AS attack_vector,
                MAX(d.raw_payload) AS raw_payload,
                MAX(d.mitigation_status) AS mitigation_status,
                MAX(d.risk_level) AS risk_level,
                MAX(c.polluted_status) AS polluted_status
            FROM clients c
            LEFT JOIN traffic_logs t ON t.client_id = c.id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE c.ip = ?
            GROUP BY c.ip
            """,
            (ip,),
        )
        row = cursor.fetchone()

    if not row:
        return {}

    result = dict(row)
    result["risk_level"] = int(result.get("risk_level") or 0)
    result["polluted_status"] = int(result.get("polluted_status") or 0)
    return result



def fetch_recent_traffic(limit: int = 100, mode: str = "all") -> dict:
    rows = core_get_recent_traffic(limit)
    if mode == "attacks":
        rows = [row for row in rows if int(row.get("is_attack") or 0) == 1]
    return {"recent_traffic": rows}



def fetch_all_client_ips(limit: int = 500) -> dict:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
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
            """,
            (limit,),
        )
        rows = cursor.fetchall()

    items = []
    for row in rows:
        total_requests = int(row["total_requests"] or 0)
        attack_requests = int(row["attack_requests"] or 0)
        polluted_status = int(row["polluted_status"] or 0)
        if attack_requests >= 10 or polluted_status == 1:
            risk = "HIGH"
        elif attack_requests > 0:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        items.append(
            {
                "ip": row["ip"],
                "traffic": total_requests,
                "attack_requests": attack_requests,
                "normal_requests": max(total_requests - attack_requests, 0),
                "country": row["location"] or "-",
                "risk": risk,
                "polluted_status": polluted_status,
                "latest_request_at": row["latest_request_at"],
            }
        )

    return {"items": items}



def compare_traffic(limit: int = 1000) -> dict:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
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
            """,
            (limit,),
        )
        row = cursor.fetchone()

        cursor.execute(
            """
            SELECT
                c.ip AS client_ip,
                MAX(d.attack_vector) AS attack_type,
                MAX(t.query_id) AS target,
                COUNT(*) AS event_count
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE t.is_attack = 1
            GROUP BY c.ip
            ORDER BY event_count DESC
            LIMIT 10
            """
        )
        attack_rows = cursor.fetchall()

    total_requests = int((row["total_requests"] or 0) if row else 0)
    attack_requests = int((row["attack_requests"] or 0) if row else 0)
    normal_requests = int((row["normal_requests"] or 0) if row else 0)

    attack_ratio = round((attack_requests / total_requests) * 100, 2) if total_requests else 0
    normal_ratio = round((normal_requests / total_requests) * 100, 2) if total_requests else 0

    attack_traffic = [
        {
            "client_ip": row["client_ip"],
            "attack_type": row["attack_type"] or "attack",
            "target": row["target"] or "unknown-target",
            "count": int(row["event_count"] or 0),
        }
        for row in attack_rows
    ]

    return {
        "total_requests": total_requests,
        "attack_requests": attack_requests,
        "normal_requests": normal_requests,
        "attack_ratio": attack_ratio,
        "normal_ratio": normal_ratio,
        "attack_traffic": attack_traffic,
    }



def auto_updates() -> dict:
    """提供前端輪詢用的輕量更新資訊。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_logs,
                MAX(request_at) AS latest_request_at,
                SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) AS attack_logs
            FROM traffic_logs
            """
        )
        row = cursor.fetchone()

    total_logs = int((row["total_logs"] or 0) if row else 0)
    attack_logs = int((row["attack_logs"] or 0) if row else 0)
    latest_request_at = row["latest_request_at"] if row else None

    return {
        "status": "ok",
        "auto_refresh": True,
        "refresh_interval_ms": 5000,
        "latest_request_at": latest_request_at,
        "total_logs": total_logs,
        "attack_logs": attack_logs,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }



def set_log_category(category_name: str, items: list | None = None) -> dict:
    return {"category_name": category_name, "items": items or [], "status": "ready"}



def execute_terminal_cmd(command_text: str, selected_ip: str | None = None) -> dict:
    normalized = (command_text or "").strip()
    return {
        "status": "accepted" if normalized else "empty",
        "command": normalized,
        "selected_ip": selected_ip,
        "message": "已接收指令內容；目前 service 層不直接執行系統命令。",
    }



def generate_hacker_pdf(client_ip: str) -> dict:
    return {
        "report_type": "hacker_pdf_payload",
        "client_ip": client_ip,
        "dwell": get_hacker_dwell_time(client_ip),
        "details": get_ip_details(client_ip),
        "timeline": get_attack_timeline(client_ip),
        "traffic_summary": compare_traffic(),
    }



def get_dashboard_ip_bundle(client_ip: str) -> dict:
    dwell = get_hacker_dwell_time(client_ip)
    timeline_data = get_attack_timeline(client_ip)
    details = get_ip_details(client_ip)

    if not details:
        return {}

    traffic = int(details.get("hits") or 0)
    attack_vector = details.get("attack_vector") or "-"
    raw_payload = details.get("raw_payload") or "-"
    protocol = details.get("tls_fingerprint") or "-"
    port = details.get("query_id") or "-"
    risk_level = int(details.get("risk_level") or 0)
    polluted_status = int(details.get("polluted_status") or 0)

    if polluted_status == 1 or risk_level >= 70 or dwell.get("is_active"):
        risk = "HIGH"
    elif risk_level > 0 or traffic > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "client_ip": client_ip,
        "country": details.get("location") or "-",
        "traffic": traffic,
        "risk": risk,
        "protocol": protocol,
        "port": port,
        "behavior": attack_vector,
        "payload": raw_payload,
        "timeline": timeline_data.get("timeline", []),
        "dwell_seconds": dwell.get("dwell_seconds", 0),
        "is_active": dwell.get("is_active", False),
        "details": details,
    }


if __name__ == "__main__":
    pass
