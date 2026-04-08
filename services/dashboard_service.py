import json
import logging
import os
import sqlite3
import time
import ipaddress
from urllib import request, parse
from datetime import datetime

from core.traffic_db import get_recent_traffic as core_get_recent_traffic

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")
IP_GEO_CACHE_TTL = int(os.getenv("IP_GEO_CACHE_TTL", "3600"))
_ip_geo_cache: dict[str, tuple[str, float]] = {}


def _is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    )


def _resolve_ip_region(ip: str, fallback_location: str | None = None) -> str:
    """將 IP 轉成地區字串，失敗時回退既有 location 或 Unknown。"""
    normalized_fallback = (fallback_location or "").strip()
    # 某些舊資料把 endpoint path 寫入 location，例如 /api/v1/user，需忽略後重算。
    fallback_looks_like_endpoint = normalized_fallback.startswith("/")
    if (
        normalized_fallback
        and normalized_fallback != "-"
        and not fallback_looks_like_endpoint
    ):
        return normalized_fallback

    if not _is_public_ip(ip):
        return "Private/Local"

    now = time.time()
    cached = _ip_geo_cache.get(ip)
    if cached and now - cached[1] <= IP_GEO_CACHE_TTL:
        return cached[0]

    geo_url = (
        "http://ip-api.com/json/"
        f"{parse.quote(ip)}"
        "?fields=status,country,regionName,city,message"
    )
    try:
        with request.urlopen(geo_url, timeout=1.8) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        if payload.get("status") == "success":
            parts = [
                payload.get("country"),
                payload.get("regionName"),
                payload.get("city"),
            ]
            region = "/".join([part for part in parts if part]) or "Unknown"
        else:
            region = "Unknown"
    except Exception as exc:
        logger.debug("IP 地理解析失敗 ip=%s error=%r", ip, exc)
        region = normalized_fallback or "Unknown"

    _ip_geo_cache[ip] = (region, now)
    return region


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
    expected_key = os.getenv("API_KEY", "").strip()
    if not expected_key:
        return False
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
                MAX(t.mouse_entropy) AS mouse_entropy,
                MAX(t.mouse_source) AS mouse_source,
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
    result.setdefault("tls_fingerprint", None)
    result["risk_level"] = int(result.get("risk_level") or 0)
    result["polluted_status"] = int(result.get("polluted_status") or 0)
    result["mouse_entropy"] = float(result.get("mouse_entropy") or 0.0)
    result["mouse_source"] = result.get("mouse_source") or "missing"
    result["location"] = _resolve_ip_region(ip, result.get("location"))
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
                "country": _resolve_ip_region(row["ip"], row["location"]),
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

    attack_ratio = (
        round((attack_requests / total_requests) * 100, 2) if total_requests else 0
    )
    normal_ratio = (
        round((normal_requests / total_requests) * 100, 2) if total_requests else 0
    )

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


# ========== 鑑識事件標準化查詢層 (Forensic Event Standardized Query Layer) ==========


def get_events_by_route(route: str, limit: int = 100, offset: int = 0) -> dict:
    """按路由分類查詢事件 (real 或 deception)."""
    if route not in ("real", "deception"):
        return {"error": "Invalid route. Must be 'real' or 'deception'", "events": []}

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # 查詢欺敵路由（is_attack=1）或真實路由（is_attack=0）
            is_attack = 1 if route == "deception" else 0

            cursor.execute(
                """
                SELECT
                    t.id,
                    t.request_at,
                    c.ip AS client_ip,
                    t.query_id,
                    t.location,
                    d.response_payload,
                    d.risk_level,
                    d.attack_vector
                FROM traffic_logs t
                JOIN clients c ON t.client_id = c.id
                LEFT JOIN attack_details d ON d.traffic_log_id = t.id
                WHERE t.is_attack = ?
                ORDER BY t.request_at DESC
                LIMIT ? OFFSET ?
                """,
                (is_attack, limit, offset),
            )
            rows = cursor.fetchall()

        events = []
        for row in rows:
            event = {
                "id": row["id"],
                "request_at": row["request_at"],
                "client_ip": row["client_ip"],
                "query_id": row["query_id"],
                "location": row["location"],
                "route": route,
                "risk_level": int(row["risk_level"] or 0),
                "attack_vector": row["attack_vector"],
                "risk_score": None,
                "deception_reason": None,
            }

            # 解析 response_payload 以提取 route/risk_score/deception_reason
            if row["response_payload"]:
                try:
                    payload = (
                        json.loads(row["response_payload"])
                        if isinstance(row["response_payload"], str)
                        else row["response_payload"]
                    )
                    event["risk_score"] = payload.get("risk_score")
                    event["deception_reason"] = payload.get("deception_reason")
                except (json.JSONDecodeError, TypeError):
                    pass

            events.append(event)

        return {"route": route, "total": len(events), "events": events}
    except Exception as exc:
        logger.error("Failed to get events by route %s: %r", route, exc)
        return {"error": str(exc), "events": []}


def get_events_by_risk_score(
    min_score: int = 0, max_score: int = 100, limit: int = 100
) -> dict:
    """按風險分數範圍查詢事件."""
    if not (0 <= min_score <= 100 and 0 <= max_score <= 100 and min_score <= max_score):
        return {
            "error": "Invalid score range. Must be 0-100 and min <= max",
            "events": [],
        }

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    t.id,
                    t.request_at,
                    c.ip AS client_ip,
                    t.query_id,
                    t.location,
                    d.response_payload,
                    d.risk_level,
                    d.attack_vector
                FROM traffic_logs t
                JOIN clients c ON t.client_id = c.id
                LEFT JOIN attack_details d ON d.traffic_log_id = t.id
                WHERE d.risk_level >= ? AND d.risk_level <= ?
                ORDER BY d.risk_level DESC, t.request_at DESC
                LIMIT ?
                """,
                (min_score, max_score, limit),
            )
            rows = cursor.fetchall()

        events = []
        for row in rows:
            event = {
                "id": row["id"],
                "request_at": row["request_at"],
                "client_ip": row["client_ip"],
                "query_id": row["query_id"],
                "location": row["location"],
                "risk_level": int(row["risk_level"] or 0),
                "attack_vector": row["attack_vector"],
                "risk_score": None,
                "deception_reason": None,
                "route": None,
            }

            # 解析 response_payload
            if row["response_payload"]:
                try:
                    payload = (
                        json.loads(row["response_payload"])
                        if isinstance(row["response_payload"], str)
                        else row["response_payload"]
                    )
                    event["risk_score"] = payload.get("risk_score")
                    event["deception_reason"] = payload.get("deception_reason")
                    event["route"] = payload.get("route")
                except (json.JSONDecodeError, TypeError):
                    pass

            events.append(event)

        return {
            "min_score": min_score,
            "max_score": max_score,
            "total": len(events),
            "events": events,
        }
    except Exception as exc:
        logger.error("Failed to get events by risk score: %r", exc)
        return {"error": str(exc), "events": []}


def get_deception_chain(query_id: str) -> dict:
    """回放攻擊鏈：按 query_id 聚合相關事件，重現完整攻擊路徑"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    t.id,
                    t.request_at,
                    c.ip AS client_ip,
                    t.query_id,
                    t.location,
                    t.is_attack,
                    d.response_payload,
                    d.raw_payload,
                    d.risk_level,
                    d.attack_vector,
                    d.interaction_depth,
                    d.dwell_time
                FROM traffic_logs t
                JOIN clients c ON t.client_id = c.id
                LEFT JOIN attack_details d ON d.traffic_log_id = t.id
                WHERE t.query_id = ?
                ORDER BY t.request_at ASC
                """,
                (query_id,),
            )
            rows = cursor.fetchall()

        if not rows:
            return {
                "query_id": query_id,
                "chain_length": 0,
                "events": [],
                "message": "No events found",
            }

        events = []
        total_dwell_time = 0.0
        max_risk_score = 0
        deception_events = 0

        for row in rows:
            event = {
                "timestamp": row["request_at"],
                "client_ip": row["client_ip"],
                "location": row["location"],
                "is_attack": bool(row["is_attack"]),
                "attack_vector": row["attack_vector"],
                "raw_payload": row["raw_payload"],
                "risk_level": int(row["risk_level"] or 0),
                "risk_score": None,
                "deception_reason": None,
                "route": None,
                "endpoint": None,
            }

            # 解析 response_payload
            if row["response_payload"]:
                try:
                    payload = (
                        json.loads(row["response_payload"])
                        if isinstance(row["response_payload"], str)
                        else row["response_payload"]
                    )
                    event["risk_score"] = payload.get("risk_score")
                    event["deception_reason"] = payload.get("deception_reason")
                    event["route"] = payload.get("route")
                    event["endpoint"] = payload.get("endpoint")

                    # 追蹤最高風險分數與欺敵事件數
                    if event["risk_score"]:
                        max_risk_score = max(max_risk_score, event["risk_score"])
                    if payload.get("route") == "deception":
                        deception_events += 1
                except (json.JSONDecodeError, TypeError):
                    pass

            if row["dwell_time"]:
                total_dwell_time = max(total_dwell_time, float(row["dwell_time"]))

            events.append(event)

        return {
            "query_id": query_id,
            "client_ip": rows[0]["client_ip"] if rows else None,
            "chain_length": len(events),
            "deception_events": deception_events,
            "max_risk_score": max_risk_score,
            "total_dwell_time": total_dwell_time,
            "first_event": rows[0]["request_at"] if rows else None,
            "last_event": rows[-1]["request_at"] if rows else None,
            "events": events,
        }
    except Exception as exc:
        logger.error("Failed to get deception chain for query_id %s: %r", query_id, exc)
        return {"query_id": query_id, "error": str(exc), "events": []}


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
        "mouse_entropy": details.get("mouse_entropy", 0.0),
        "mouse_source": details.get("mouse_source", "missing"),
        "details": details,
    }


def get_country_statistics(limit: int = 20) -> dict:
    """按國家/地區統計攻擊數與連線數（用於趨勢呈現）"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                COALESCE(t.location, 'Unknown') AS country,
                COUNT(t.id) AS total_requests,
                SUM(CASE WHEN t.is_attack = 1 THEN 1 ELSE 0 END) AS attack_count,
                COUNT(DISTINCT c.ip) AS unique_ips
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            GROUP BY t.location
            ORDER BY attack_count DESC, total_requests DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()

    stats = []
    for row in rows:
        country = (
            _resolve_ip_region("0.0.0.1", row["country"])
            if row["country"] != "Unknown"
            else "Unknown"
        )
        stats.append(
            {
                "country": country,
                "total_requests": int(row["total_requests"] or 0),
                "attack_count": int(row["attack_count"] or 0),
                "unique_ips": int(row["unique_ips"] or 0),
            }
        )

    return {"statistics": stats, "total_countries": len(stats)}


def get_attack_vector_distribution() -> dict:
    """按攻擊類型統計分布（SQLi、LFI、XSS、RCE 等）"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                COALESCE(d.attack_vector, 'Unknown') AS attack_type,
                COUNT(*) AS count,
                AVG(d.risk_level) AS avg_risk,
                MAX(d.risk_level) AS max_risk
            FROM attack_details d
            GROUP BY d.attack_vector
            ORDER BY count DESC
            """
        )
        rows = cursor.fetchall()

    distribution = []
    for row in rows:
        distribution.append(
            {
                "attack_type": row["attack_type"],
                "count": int(row["count"] or 0),
                "avg_risk": round(float(row["avg_risk"] or 0), 2),
                "max_risk": int(row["max_risk"] or 0),
            }
        )

    return {"distribution": distribution}


def get_top_source_ips(limit: int = 20) -> dict:
    """源 IP 熱點分布（連線數、攻擊數、風險等級）"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                c.ip,
                COUNT(t.id) AS total_connections,
                SUM(CASE WHEN t.is_attack = 1 THEN 1 ELSE 0 END) AS attack_count,
                MAX(t.location) AS location,
                MAX(d.risk_level) AS max_risk,
                MAX(d.attack_vector) AS latest_attack_type
            FROM clients c
            LEFT JOIN traffic_logs t ON c.id = t.client_id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            GROUP BY c.ip
            ORDER BY attack_count DESC, total_connections DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()

    ips = []
    for row in rows:
        ips.append(
            {
                "ip": row["ip"],
                "country": _resolve_ip_region(row["ip"], row["location"]),
                "total_connections": int(row["total_connections"] or 0),
                "attack_count": int(row["attack_count"] or 0),
                "max_risk": int(row["max_risk"] or 0),
                "latest_attack_type": row["latest_attack_type"] or "-",
            }
        )

    return {"top_ips": ips, "total_unique_ips": len(ips)}


def get_time_series_stats(hours: int = 24) -> dict:
    """按時間段統計（小時粒度，用於趨勢圖）"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                strftime('%H:00', t.request_at) AS hour,
                COUNT(t.id) AS total_count,
                SUM(CASE WHEN t.is_attack = 1 THEN 1 ELSE 0 END) AS attack_count,
                SUM(CASE WHEN t.is_attack = 0 THEN 1 ELSE 0 END) AS normal_count,
                AVG(d.risk_level) AS avg_risk
            FROM traffic_logs t
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE datetime(t.request_at) >= datetime('now', '-' || ? || ' hours')
            GROUP BY strftime('%H:00', t.request_at)
            ORDER BY hour ASC
            """,
            (hours,),
        )
        rows = cursor.fetchall()

    time_series = []
    for row in rows:
        time_series.append(
            {
                "hour": row["hour"],
                "total_count": int(row["total_count"] or 0),
                "attack_count": int(row["attack_count"] or 0),
                "normal_count": int(row["normal_count"] or 0),
                "avg_risk": round(float(row["avg_risk"] or 0), 2),
            }
        )

    return {"time_series": time_series, "period_hours": hours}


if __name__ == "__main__":
    pass
