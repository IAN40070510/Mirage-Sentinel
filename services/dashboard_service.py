import sqlite3
import os
import json
import logging
from datetime import datetime
from core.traffic_db import get_recent_traffic as core_get_recent_traffic

logger = logging.getLogger(__name__)

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")

# SQLite 連接優化（雖然 SQLite 不支援真正的連接池，但可以優化連接設置）
def get_db_connection():
    """取得資料庫連接，並進行最佳化設置"""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # 啟用 WAL 模式以改進並發性能
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")  # 提高寫入速度
    conn.execute("PRAGMA cache_size=-64000")   # 使用 64MB 快取
    return conn

def _parse_ts(ts: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unsupported timestamp format: {ts}")


def get_hacker_dwell_time(client_ip: str) -> dict:
    """以攻擊流量紀錄估算同一 client_ip 的滯留時間與活躍狀態。
    
    Args:
        client_ip: 客戶端 IP 地址
        
    Returns:
        包含滯留時間資訊的字典
        
    Raises:
        ValueError: 如果時間戳格式無效
        Exception: 如果資料庫查詢失敗
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT t.request_at
                FROM traffic_logs t
                JOIN clients c ON c.id = t.client_id
                WHERE c.ip = ? AND t.is_attack = 1
                ORDER BY t.request_at ASC
                ''',
                (client_ip,)
            )
            rows = cursor.fetchall()

        if not rows:
            return {"client_ip": client_ip, "dwell_seconds": 0, "is_active": False}

        first_time = _parse_ts(rows[0][0])
        latest_time = _parse_ts(rows[-1][0])
        dwell_seconds = int(max((latest_time - first_time).total_seconds(), 0))
        is_active = (datetime.now() - latest_time).total_seconds() <= 600

        return {"client_ip": client_ip, "dwell_seconds": dwell_seconds, "is_active": is_active}
    except Exception as e:
        logger.error(f"Failed to get dwell time for {client_ip}: {repr(e)}")
        return {"client_ip": client_ip, "dwell_seconds": 0, "is_active": False, "error": str(e)}

def analyze_interaction_depth(client_ip: str, query_id: str) -> dict:
    """依 client_ip + query_id 回傳互動深度（以攻擊事件次數表示）。
    
    Args:
        client_ip: 客戶端 IP 地址
        query_id: 查詢 ID
        
    Returns:
        包含互動深度的字典
        
    Raises:
        Exception: 如果資料庫查詢失敗
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT COUNT(*)
                FROM traffic_logs t
                JOIN clients c ON c.id = t.client_id
                WHERE c.ip = ? AND t.query_id = ? AND t.is_attack = 1
                ''',
                (client_ip, query_id)
            )
            total_actions = int((cursor.fetchone() or [0])[0])

        return {
            "client_ip": client_ip,
            "query_id": query_id,
            "interaction_depth": total_actions,
            # Backward compatibility for existing frontend/testing code.
            "depth_level": total_actions,
            "total_actions": total_actions,
        }
    except Exception as e:
        logger.error(f"Failed to analyze interaction depth for {client_ip}: {repr(e)}")
        return {
            "client_ip": client_ip,
            "query_id": query_id,
            "interaction_depth": 0,
            "depth_level": 0,
            "total_actions": 0,
            "error": str(e)
        }

def get_attack_timeline(attacker_ip: str) -> dict:
    """視覺化呈現該 IP 的攻擊行為路徑。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT t.request_at, COALESCE(d.attack_vector, 'attack') AS attack_vector
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE c.ip = ? AND t.is_attack = 1
            ORDER BY t.request_at ASC
            ''',
            (attacker_ip,)
        )
        rows = cursor.fetchall()

    timeline = []
    for row in rows:
        dt = _parse_ts(row[0])
        timeline.append({"time": dt.strftime("%H:%M"), "action": row[1]})

    return {"ip": attacker_ip, "timeline": timeline}

def log_misjudgment(attacker_ip: str, reason: str) -> None:
    """可將IP存入誤判資料夾，以供後續AI調整"""
    os.makedirs(ERROR_LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(ERROR_LOG_DIR, f"misjudgment_{attacker_ip.replace('.', '_')}_{timestamp}.json")
    
    data = {
        "attacker_ip": attacker_ip,
        "reason": reason,
        "logged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def get_command_heatmap() -> dict:
    """判斷最常輸入指令前十。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT COALESCE(d.raw_payload, t.query_id, '-') AS cmd, COUNT(*) AS count
            FROM traffic_logs t
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE t.is_attack = 1
            GROUP BY cmd
            ORDER BY count DESC
            LIMIT 10
            '''
        )
        rows = cursor.fetchall()

    top_commands = [{"cmd": row[0], "count": row[1]} for row in rows]
    return {"top_commands": top_commands}

def get_ip_details(ip : str) -> dict:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT
                c.ip AS client_ip,
                MAX(t.location) AS location,
                COUNT(t.id) AS hits,
                MAX(d.attack_vector) AS attack_vector,
                MAX(d.raw_payload) AS raw_payload,
                MAX(d.mitigation_status) AS mitigation_status,
                MAX(d.risk_level) AS risk_level
            FROM clients c
            LEFT JOIN traffic_logs t ON t.client_id = c.id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE c.ip = ?
            GROUP BY c.ip
            ''',
            (ip,)
        )
        row = cursor.fetchone()

    return dict(row) if row else {}


def fetch_recent_traffic(limit: int = 100, mode: str = "all") -> dict:
    rows = core_get_recent_traffic(limit)
    if mode == "attacks":
        rows = [r for r in rows if int(r.get("is_attack") or 0) == 1]
    return {"recent_traffic": rows}


def auto_updates() -> dict:
    """提供前端輪詢用的輕量更新檢查資訊。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT
                COUNT(*) AS total_requests,
                MAX(request_at) AS latest_request_at,
                SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) AS attack_requests
            FROM traffic_logs
            '''
        )
        row = cursor.fetchone()

    total_requests = int((row["total_requests"] or 0) if row else 0)
    attack_requests = int((row["attack_requests"] or 0) if row else 0)
    latest_request_at = (row["latest_request_at"] if row else None) or None

    return {
        "status": "ok",
        "total_requests": total_requests,
        "attack_requests": attack_requests,
        "latest_request_at": latest_request_at,
    }

if __name__ == "__main__":
    pass


def validate_api_key(api_key: str) -> bool:
    """簡單 API key 驗證，供上層 router / middleware 使用。"""
    expected_key = os.getenv("API_KEY", "").strip() or "dev-local-api-key-change-me"
    return api_key == expected_key


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
                MAX(d.attack_vector) AS attack_type,
                MAX(t.query_id) AS target,
                COUNT(*) AS event_count
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE t.is_attack = 1
            GROUP BY c.ip
            ORDER BY event_count DESC
            LIMIT ?
            ''',
            (limit,)
        )
        attack_rows = cursor.fetchall()

    total_requests = int((row["total_requests"] or 0) if row else 0)
    attack_requests = int((row["attack_requests"] or 0) if row else 0)
    normal_requests = int((row["normal_requests"] or 0) if row else 0)

    attack_ratio = round((attack_requests / total_requests) * 100, 2) if total_requests else 0
    normal_ratio = round((normal_requests / total_requests) * 100, 2) if total_requests else 0

    attack_traffic = [
        {
            "client_ip": r["client_ip"],
            "attack_type": r["attack_type"] or "attack",
            "target": r["target"] or "unknown-target",
            "count": int(r["event_count"] or 0),
        }
        for r in attack_rows
    ]

    return {
        "total_requests": total_requests,
        "attack_requests": attack_requests,
        "normal_requests": normal_requests,
        "attack_ratio": attack_ratio,
        "normal_ratio": normal_ratio,
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
