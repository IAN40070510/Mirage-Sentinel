from typing import Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

_logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """確保 backend_soc 啟動時自行初始化 DB schema，不依賴 backend_public。"""
    from core.traffic_db import setup_traffic_db

    setup_traffic_db()
    _logger.info("[dashboard_service] DB schema initialized.")
    yield


app = FastAPI(lifespan=lifespan)


# 兼容舊 SOC 前端路由 alias（必須放在 app 實例建立之後）
@app.get("/api/v1/dashboard/command_heatmap")
async def dashboard_command_heatmap(request: Request):
    require_api_key(request)
    return get_command_heatmap()


@app.get("/api/v1/dashboard/traffic_compare")
async def dashboard_traffic_compare(request: Request):
    require_api_key(request)
    return compare_traffic()


# 與新版 API 相容的 alias 路由，供 SOC 前端存取
from fastapi import APIRouter

alias_router = APIRouter(prefix="")


@alias_router.get("/recent_traffic")
async def alias_recent_traffic(request: Request, limit: int = 100, mode: str = "all"):
    return await dashboard_recent_traffic(request, limit, mode)


@alias_router.get("/live_ips")
async def alias_live_ips(request: Request, limit: int = 500):
    return await dashboard_ips(request)


@alias_router.get("/ip_bundle/{client_ip}")
async def alias_ip_bundle(client_ip: str, request: Request):
    return await dashboard_ip_detail(client_ip, request)


app.include_router(alias_router, prefix="/api/v1/dashboard")

# 允許前端跨域請求
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API_KEY 驗證
def require_api_key(request: Request):
    api_key = request.headers.get("X-API-KEY")
    if not validate_api_key(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key"
        )


# 健康檢查
@app.get("/healthz")
def health_check():
    return {"status": "ok"}


@app.get("/api/v1/dashboard/recent_traffic")
async def dashboard_recent_traffic(
    request: Request, limit: int = 100, mode: str = "all"
):
    require_api_key(request)
    return fetch_recent_traffic(limit, mode)


@app.get("/api/v1/dashboard")
@app.get("/api/v1/dashboard/")
async def dashboard_root(request: Request):
    require_api_key(request)
    # 提供可用路由摘要，避免 /soc/ 直接回 404 影響排障。
    return {
        "service": "Mirage SOC Dashboard API",
        "status": "ok",
        "available_routes": [
            "/api/v1/dashboard/recent_traffic",
            "/api/v1/dashboard/events/by_route/{route}",
            "/api/v1/dashboard/events/by_risk_score",
            "/api/v1/dashboard/replay/{principal_id}",
            "/api/v1/dashboard/replay/session/{session_chain_id}",
            "/api/v1/dashboard/statistics/deception_effectiveness",
        ],
    }


# SOC Dashboard API 路由
@app.get("/api/v1/dashboard/ips")
async def dashboard_ips(request: Request):
    require_api_key(request)
    return fetch_all_client_ips()


@app.get("/api/v1/dashboard/ip/{client_ip}")
async def dashboard_ip_detail(client_ip: str, request: Request):
    require_api_key(request)
    return get_dashboard_ip_bundle(client_ip)


@app.get("/api/v1/dashboard/compare")
async def dashboard_compare(request: Request):
    require_api_key(request)
    return compare_traffic()


@app.get("/api/v1/dashboard/heatmap")
async def dashboard_heatmap(request: Request):
    require_api_key(request)
    return get_command_heatmap()


@app.get("/api/v1/dashboard/auto_updates")
async def dashboard_auto_updates(request: Request):
    require_api_key(request)
    return auto_updates()


@app.get("/api/v1/dashboard/country_stats")
async def dashboard_country_stats(request: Request):
    require_api_key(request)
    return get_country_statistics()


@app.get("/api/v1/dashboard/attack_vector")
async def dashboard_attack_vector(request: Request):
    require_api_key(request)
    return get_attack_vector_distribution()


@app.get("/api/v1/dashboard/top_ips")
async def dashboard_top_ips(request: Request):
    require_api_key(request)
    return get_top_source_ips()


@app.get("/api/v1/dashboard/time_series")
async def dashboard_time_series(request: Request):
    require_api_key(request)
    return get_time_series_stats()


@app.get("/api/v1/dashboard/events/by_route/{route}")
async def dashboard_events_by_route(
    route: str,
    request: Request,
    limit: int = 100,
    offset: int = 0,
):
    require_api_key(request)
    return get_events_by_route(route, limit=limit, offset=offset)


@app.get("/api/v1/dashboard/events/by_risk_score")
async def dashboard_events_by_risk_score(
    request: Request,
    min_score: int = 0,
    max_score: int = 100,
    limit: int = 100,
):
    require_api_key(request)
    return get_events_by_risk_score(
        min_score=min_score, max_score=max_score, limit=limit
    )


@app.get("/api/v1/dashboard/replay/{principal_id}")
async def dashboard_replay_by_query(principal_id: str, request: Request):
    require_api_key(request)
    return get_deception_chain(principal_id)


@app.get("/api/v1/dashboard/replay/session/{session_chain_id}")
async def dashboard_replay_by_session(session_chain_id: str, request: Request):
    require_api_key(request)
    return get_deception_chain_by_session(session_chain_id)


@app.get("/api/v1/dashboard/statistics/deception_effectiveness")
async def dashboard_deception_effectiveness(request: Request, hours: int = 24):
    require_api_key(request)
    return get_deception_effectiveness_summary(hours=hours)


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
FEATURE_DB_PATH = os.path.join(PROJECT_ROOT, "data", "feature_store.db")
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
    """將 IP 轉成國家字串，失敗時回退既有 location 或 Unknown。"""

    def _country_only(value: str) -> str:
        text = (value or "").strip()
        if not text:
            return ""
        # 舊資料可能為 "Country/Region/City"，目前戰情室僅保留國家層級。
        return text.split("/", 1)[0].strip()

    normalized_fallback = (fallback_location or "").strip()
    # 某些舊資料把路由占位值或 endpoint path 寫入 location，需忽略後重算。
    fallback_looks_like_endpoint = normalized_fallback.startswith("/")
    fallback_is_placeholder = (
        normalized_fallback.lower()
        in {
            "-",
            "unknown",
            "banking:proxy",
            "private/local",
        }
        or ":" in normalized_fallback
    )

    if (
        normalized_fallback
        and not fallback_looks_like_endpoint
        and not fallback_is_placeholder
    ):
        return _country_only(normalized_fallback) or "Unknown"

    if not _is_public_ip(ip):
        return "Private/Local"

    now = time.time()
    cached = _ip_geo_cache.get(ip)
    if cached and now - cached[1] <= IP_GEO_CACHE_TTL:
        return cached[0]

    geo_url = (
        "http://ip-api.com/json/" f"{parse.quote(ip)}" "?fields=status,country,message"
    )
    try:
        with request.urlopen(geo_url, timeout=1.8) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        if payload.get("status") == "success":
            region = _country_only(str(payload.get("country") or "")) or "Unknown"
        else:
            region = "Unknown"
    except Exception as exc:
        logger.debug("IP 地理解析失敗 ip=%s error=%r", ip, exc)
        region = _country_only(normalized_fallback) or "Unknown"

    _ip_geo_cache[ip] = (region, now)
    return region


def get_db_connection():
    """取得 SQLite 連線並套用基本最佳化。"""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if os.path.exists(FEATURE_DB_PATH):
        conn.execute(f"ATTACH DATABASE '{FEATURE_DB_PATH}' AS fs")
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


def get_hacker_dwell_time(client_ip: str) -> dict[str, Any]:
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


from core.deception_engine import compute_interaction_metrics


def analyze_interaction_depth(client_ip: str, principal_id: str) -> dict[str, Any]:
    """
    進階互動深度分析：回傳多維度誘餌擬真度與攻擊者信任度指標，供 SOC 前端判斷。
    """
    try:
        # 這裡 current_payload 與 has_memory_hit 可依需求調整，先設為 None/False
        metrics = compute_interaction_metrics(
            client_ip=client_ip,
            principal_id=principal_id,
            current_payload=None,
            has_memory_hit=False,
        )
        # 正規化為可擴充的字典，避免型別推斷把 value 限制為 int。
        output: dict[str, Any] = dict(metrics)
        output["client_ip"] = client_ip
        output["principal_id"] = principal_id
        return output
    except Exception as exc:
        logger.error("Failed to analyze interaction depth for %s: %r", client_ip, exc)
        return {
            "client_ip": client_ip,
            "principal_id": principal_id,
            "error": str(exc),
        }


def get_attack_timeline(attacker_ip: str) -> dict[str, Any]:
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


def get_ip_all_traffic_logs(client_ip: str) -> list[dict[str, Any]]:
    """回傳指定 IP 的全流量事件（含正常/攻擊），供 SELECTED IP DETAIL 完整顯示。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                t.request_at,
                t.method,
                t.endpoint,
                t.principal_id,
                t.is_attack,
                t.input_string,
                COALESCE(d.attack_vector, '-') AS attack_vector,
                COALESCE(d.risk_level, 0) AS risk_level,
                COALESCE(d.raw_payload, '-') AS raw_payload,
                COALESCE(fs_df.sentinel_decision, '-') AS sentinel_decision,
                COALESCE(fs_df.sentinel_score, 0) AS sentinel_score,
                COALESCE(fs_df.sentinel_attack_type, '-') AS sentinel_attack_type,
                COALESCE(d.response_origin, '-') AS response_origin,
                COALESCE(d.flow_stage, '-') AS flow_stage
            FROM traffic_logs t
            JOIN clients c ON c.id = t.client_id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            LEFT JOIN fs.derived_features fs_df ON fs_df.traffic_log_id = t.id
            WHERE c.ip = ?
            ORDER BY t.request_at DESC
            """,
            (client_ip,),
        )
        rows = cursor.fetchall()

    logs: list[dict[str, Any]] = []
    for row in rows:
        logs.append(
            {
                "timestamp": row["request_at"],
                "method": row["method"] or "-",
                "endpoint": row["endpoint"] or "-",
                "principal_id": row["principal_id"] or "-",
                "is_attack": int(row["is_attack"] or 0),
                "input_string": row["input_string"] or row["raw_payload"] or "-",
                "attack_vector": row["attack_vector"] or "-",
                "risk_level": int(row["risk_level"] or 0),
                "raw_payload": row["raw_payload"] or "-",
                "sentinel_decision": row["sentinel_decision"] or "-",
                "sentinel_score": float(row["sentinel_score"] or 0.0),
                "sentinel_attack_type": row["sentinel_attack_type"] or "-",
                "response_origin": row["response_origin"] or "-",
                "flow_stage": row["flow_stage"] or "-",
                # 保持與舊前端欄位相容
                "action": row["attack_vector"] or "-",
                "time": _parse_ts(row["request_at"]).strftime("%H:%M:%S.%f")[:-3],
            }
        )

    return logs


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


def get_command_heatmap() -> dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COALESCE(d.raw_payload, t.principal_id, '-') AS cmd, COUNT(*) AS count
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


def get_ip_details(ip: str) -> dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                c.ip AS client_ip,
                MAX(t.location) AS location,
                COUNT(t.id) AS hits,
                MAX(t.principal_id) AS principal_id,
                MAX(fs_df.mouse_entropy) AS mouse_entropy,
                MAX(fs_df.mouse_source) AS mouse_source,
                MAX(d.attack_vector) AS attack_vector,
                MAX(d.raw_payload) AS raw_payload,
                MAX(d.mitigation_status) AS mitigation_status,
                MAX(d.risk_level) AS risk_level,
                MAX(c.polluted_status) AS polluted_status
            FROM clients c
            LEFT JOIN traffic_logs t ON t.client_id = c.id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            LEFT JOIN fs.derived_features fs_df ON fs_df.traffic_log_id = t.id
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


def fetch_recent_traffic(limit: int = 100, mode: str = "all") -> dict[str, Any]:
    rows = core_get_recent_traffic(limit)
    if mode == "attacks":
        rows = [row for row in rows if int(row.get("is_attack") or 0) == 1]

    for row in rows:
        client_ip = str(row.get("client_ip") or "").strip()
        resolved = _resolve_ip_region(client_ip, row.get("location"))
        row["location"] = resolved
        row["country"] = resolved
        row["xgboost_score"] = row.get("sentinel_score")
        row["xgboost_attack_type"] = row.get("sentinel_attack_type")
        row["xgboost_decision"] = row.get("sentinel_decision")
        row["xgboost_model_ready"] = row.get("sentinel_model_ready")

    return {"recent_traffic": rows}


def fetch_all_client_ips(limit: int = 500) -> dict[str, Any]:
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


def compare_traffic(limit: int = 1000) -> dict[str, Any]:
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
                MAX(t.principal_id) AS target,
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


def get_events_by_route(
    route: str, limit: int = 100, offset: int = 0
) -> dict[str, Any]:
    """按路由分類查詢事件 (real 或 deception)."""
    if route not in ("real", "deception"):
        return {"error": "Invalid route. Must be 'real' or 'deception'", "events": []}

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # 以分流證據欄位判斷 real/deception，而非僅依賴 is_attack。
            if route == "deception":
                cursor.execute(
                    """
                    SELECT
                        t.id,
                        t.request_at,
                        c.ip AS client_ip,
                        t.principal_id AS principal_id,
                        t.session_chain_id,
                        t.principal_id,
                        t.location,
                        d.response_payload,
                        d.risk_level,
                        d.attack_vector,
                        d.route_before,
                        d.route_after,
                        d.response_origin,
                        d.real_backend_touched,
                        fs_df.deception_score,
                        fs_df.trust_level,
                        fs_df.memory_hit,
                        d.flow_stage
                    FROM traffic_logs t
                    JOIN clients c ON t.client_id = c.id
                    LEFT JOIN attack_details d ON d.traffic_log_id = t.id
                    LEFT JOIN fs.derived_features fs_df ON fs_df.traffic_log_id = t.id
                    WHERE (
                        COALESCE(d.route_after, '') = 'mirage'
                        OR COALESCE(d.deception_engaged, 0) = 1
                        OR COALESCE(d.response_origin, '') IN ('mirage', 'sandbox_ai')
                    )
                    ORDER BY t.request_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            else:
                cursor.execute(
                    """
                    SELECT
                        t.id,
                        t.request_at,
                        c.ip AS client_ip,
                        t.principal_id AS principal_id,
                        t.session_chain_id,
                        t.principal_id,
                        t.location,
                        d.response_payload,
                        d.risk_level,
                        d.attack_vector,
                        d.route_before,
                        d.route_after,
                        d.response_origin,
                        d.real_backend_touched,
                        fs_df.deception_score,
                        fs_df.trust_level,
                        fs_df.memory_hit,
                        d.flow_stage
                    FROM traffic_logs t
                    JOIN clients c ON t.client_id = c.id
                    LEFT JOIN attack_details d ON d.traffic_log_id = t.id
                    LEFT JOIN fs.derived_features fs_df ON fs_df.traffic_log_id = t.id
                    WHERE (
                        COALESCE(d.real_backend_touched, 0) = 1
                        OR COALESCE(d.response_origin, '') = 'vuln_bank_main'
                        OR (t.is_attack = 0 AND COALESCE(d.route_after, '') != 'mirage')
                    )
                    ORDER BY t.request_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = cursor.fetchall()

        events = []
        for row in rows:
            event = {
                "id": row["id"],
                "request_at": row["request_at"],
                "client_ip": row["client_ip"],
                "principal_id": row["principal_id"],
                "session_chain_id": row["session_chain_id"],
                "location": row["location"],
                "route": route,
                "risk_level": int(row["risk_level"] or 0),
                "attack_vector": row["attack_vector"],
                "route_before": row["route_before"],
                "route_after": row["route_after"],
                "response_origin": row["response_origin"],
                "real_backend_touched": int(row["real_backend_touched"] or 0),
                "flow_stage": row["flow_stage"],
                "deception_score": int(row["deception_score"] or 0),
                "trust_level": row["trust_level"] or "low",
                "memory_hit": bool(row["memory_hit"] or 0),
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
) -> dict[str, Any]:
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
                    t.principal_id AS principal_id,
                    t.principal_id,
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
                "principal_id": row["principal_id"],
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


def get_deception_chain(principal_id: str) -> dict[str, Any]:
    """回放攻擊鏈：按 principal_id 聚合相關事件，重現完整攻擊路徑"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT
                    t.id,
                    t.request_at,
                    c.ip AS client_ip,
                    t.session_chain_id,
                    t.principal_id AS principal_id,
                    t.principal_id,
                    t.location,
                    t.is_attack,
                    d.response_payload,
                    d.raw_payload,
                    d.risk_level,
                    d.attack_vector,
                    fs_df.interaction_depth,
                    fs_df.dwell_time,
                    d.route_before,
                    d.route_after,
                    d.response_origin,
                    d.real_backend_touched,
                    d.flow_stage,
                    fs_df.deception_score,
                    fs_df.trust_level,
                    fs_df.memory_hit
                FROM traffic_logs t
                JOIN clients c ON t.client_id = c.id
                LEFT JOIN attack_details d ON d.traffic_log_id = t.id
                LEFT JOIN fs.derived_features fs_df ON fs_df.traffic_log_id = t.id
                WHERE t.principal_id = ?
                ORDER BY t.request_at ASC
                """,
                (principal_id,),
            )
            rows = cursor.fetchall()

        if not rows:
            return {
                "principal_id": principal_id,
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
                "principal_id": row["principal_id"],
                "session_chain_id": row["session_chain_id"],
                "location": row["location"],
                "is_attack": bool(row["is_attack"]),
                "attack_vector": row["attack_vector"],
                "raw_payload": row["raw_payload"],
                "risk_level": int(row["risk_level"] or 0),
                "route_before": row["route_before"],
                "route_after": row["route_after"],
                "response_origin": row["response_origin"],
                "real_backend_touched": int(row["real_backend_touched"] or 0),
                "flow_stage": row["flow_stage"],
                "deception_score": int(row["deception_score"] or 0),
                "trust_level": row["trust_level"] or "low",
                "memory_hit": bool(row["memory_hit"] or 0),
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
                except (json.JSONDecodeError, TypeError):
                    pass

            if event["deception_score"]:
                max_risk_score = max(max_risk_score, int(event["deception_score"]))
            if event["flow_stage"] == "deception":
                deception_events += 1

            if row["dwell_time"]:
                total_dwell_time = max(total_dwell_time, float(row["dwell_time"]))

            events.append(event)

        return {
            "principal_id": principal_id,
            "client_ip": rows[0]["client_ip"] if rows else None,
            "session_chain_id": rows[0]["session_chain_id"] if rows else None,
            "chain_length": len(events),
            "deception_events": deception_events,
            "max_risk_score": max_risk_score,
            "total_dwell_time": total_dwell_time,
            "first_event": rows[0]["request_at"] if rows else None,
            "last_event": rows[-1]["request_at"] if rows else None,
            "events": events,
        }
    except Exception as exc:
        logger.error(
            "Failed to get deception chain for principal_id %s: %r", principal_id, exc
        )
        return {"principal_id": principal_id, "error": str(exc), "events": []}


def get_deception_chain_by_session(session_chain_id: str) -> dict[str, Any]:
    """按 session_chain_id 回放事件鏈，供 SOC 做攻擊鏈分段與驗證。"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    t.request_at,
                    c.ip AS client_ip,
                    t.principal_id AS principal_id,
                    t.session_chain_id,
                    t.principal_id,
                    t.method,
                    t.endpoint,
                    t.is_attack,
                    d.attack_vector,
                    d.route_before,
                    d.route_after,
                    d.response_origin,
                    d.real_backend_touched,
                    d.flow_stage,
                    fs_df.deception_score,
                    fs_df.trust_level,
                    fs_df.memory_hit
                FROM traffic_logs t
                JOIN clients c ON t.client_id = c.id
                LEFT JOIN attack_details d ON d.traffic_log_id = t.id
                LEFT JOIN fs.derived_features fs_df ON fs_df.traffic_log_id = t.id
                WHERE t.session_chain_id = ?
                ORDER BY t.request_at ASC
                """,
                (session_chain_id,),
            )
            rows = cursor.fetchall()

        if not rows:
            return {
                "session_chain_id": session_chain_id,
                "chain_length": 0,
                "events": [],
                "message": "No events found",
            }

        events = [
            {
                "timestamp": row["request_at"],
                "client_ip": row["client_ip"],
                "principal_id": row["principal_id"],
                "method": row["method"],
                "endpoint": row["endpoint"],
                "is_attack": bool(row["is_attack"]),
                "attack_vector": row["attack_vector"],
                "route_before": row["route_before"],
                "route_after": row["route_after"],
                "response_origin": row["response_origin"],
                "real_backend_touched": int(row["real_backend_touched"] or 0),
                "flow_stage": row["flow_stage"],
                "deception_score": int(row["deception_score"] or 0),
                "trust_level": row["trust_level"] or "low",
                "memory_hit": bool(row["memory_hit"] or 0),
            }
            for row in rows
        ]

        return {
            "session_chain_id": session_chain_id,
            "principal_id": rows[0]["principal_id"],
            "client_ip": rows[0]["client_ip"],
            "chain_length": len(events),
            "first_event": rows[0]["request_at"],
            "last_event": rows[-1]["request_at"],
            "events": events,
        }
    except Exception as exc:
        logger.error(
            "Failed to get deception chain for session_chain_id %s: %r",
            session_chain_id,
            exc,
        )
        return {"session_chain_id": session_chain_id, "error": str(exc), "events": []}


def get_deception_effectiveness_summary(hours: int = 24) -> dict[str, Any]:
    """彙總 Mirage 成效指標，供 SOC 快速判讀欺敵品質。"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN COALESCE(d.flow_stage, '') = 'deception'
                          OR COALESCE(d.route_after, '') = 'mirage'
                          OR COALESCE(d.deception_engaged, 0) = 1
                         THEN 1 ELSE 0 END) AS deception_events,
                SUM(CASE WHEN t.is_attack = 0
                          OR COALESCE(d.flow_stage, '') IN ('upstream', 'upstream_error')
                          OR COALESCE(d.route_after, '') = 'vuln_bank_main'
                          OR COALESCE(d.real_backend_touched, 0) = 1
                         THEN 1 ELSE 0 END) AS real_path_events,
                AVG(COALESCE(fs_df.deception_score, 0)) AS avg_deception_score,
                SUM(CASE WHEN COALESCE(fs_df.trust_level, '') = 'high' THEN 1 ELSE 0 END) AS high_trust_events,
                SUM(CASE WHEN COALESCE(fs_df.memory_hit, 0) = 1 THEN 1 ELSE 0 END) AS memory_hit_events
            FROM traffic_logs t
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            LEFT JOIN fs.derived_features fs_df ON fs_df.traffic_log_id = t.id
            WHERE t.request_at >= datetime('now', ?)
            """,
            (f"-{hours} hours",),
        )
        row = cursor.fetchone()

    total_events = int(row["total_events"] or 0) if row else 0
    deception_events = int(row["deception_events"] or 0) if row else 0
    real_path_events = int(row["real_path_events"] or 0) if row else 0
    high_trust_events = int(row["high_trust_events"] or 0) if row else 0
    memory_hit_events = int(row["memory_hit_events"] or 0) if row else 0
    avg_deception_score = (
        round(float(row["avg_deception_score"] or 0.0), 2) if row else 0.0
    )

    deception_ratio = (
        round((deception_events / total_events) * 100, 2) if total_events else 0.0
    )
    high_trust_ratio = (
        round((high_trust_events / deception_events) * 100, 2)
        if deception_events
        else 0.0
    )
    memory_hit_ratio = (
        round((memory_hit_events / deception_events) * 100, 2)
        if deception_events
        else 0.0
    )

    return {
        "window_hours": hours,
        "total_events": total_events,
        "deception_events": deception_events,
        "real_path_events": real_path_events,
        "deception_ratio": deception_ratio,
        "avg_deception_score": avg_deception_score,
        "high_trust_events": high_trust_events,
        "high_trust_ratio": high_trust_ratio,
        "memory_hit_events": memory_hit_events,
        "memory_hit_ratio": memory_hit_ratio,
    }


def auto_updates() -> dict[str, Any]:
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


from typing import Any


def set_log_category(
    category_name: str, items: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {"category_name": category_name, "items": items or [], "status": "ready"}


def execute_terminal_cmd(
    command_text: str, selected_ip: str | None = None
) -> dict[str, Any]:
    normalized = (command_text or "").strip()
    return {
        "status": "accepted" if normalized else "empty",
        "command": normalized,
        "selected_ip": selected_ip,
        "message": "已接收指令內容；目前 service 層不直接執行系統命令。",
    }


def generate_hacker_pdf(client_ip: str) -> dict[str, Any]:
    return {
        "report_type": "hacker_pdf_payload",
        "client_ip": client_ip,
        "dwell": get_hacker_dwell_time(client_ip),
        "details": get_ip_details(client_ip),
        "timeline": get_attack_timeline(client_ip),
        "traffic_summary": compare_traffic(),
    }


def get_dashboard_ip_bundle(client_ip: str) -> dict[str, Any]:
    dwell = get_hacker_dwell_time(client_ip)
    timeline_data = get_attack_timeline(client_ip)
    traffic_logs = get_ip_all_traffic_logs(client_ip)
    details = get_ip_details(client_ip)

    if not details:
        return {}

    traffic = int(details.get("hits") or 0)
    attack_vector = details.get("attack_vector") or "-"
    raw_payload = details.get("raw_payload") or "-"
    protocol = details.get("tls_fingerprint") or "-"
    port = details.get("principal_id") or "-"
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
        "input_string": details.get("input_string") or raw_payload,
        "timeline": timeline_data.get("timeline", []),
        "traffic_logs": traffic_logs,
        "traffic_log_count": len(traffic_logs),
        "dwell_seconds": dwell.get("dwell_seconds", 0),
        "is_active": dwell.get("is_active", False),
        "mouse_entropy": details.get("mouse_entropy", 0.0),
        "mouse_source": details.get("mouse_source", "missing"),
        "details": details,
    }


def get_country_statistics(limit: int = 20) -> dict[str, Any]:
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


def get_attack_vector_distribution() -> dict[str, Any]:
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


def get_top_source_ips(limit: int = 20) -> dict[str, Any]:
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


def get_time_series_stats(hours: int = 24) -> dict[str, Any]:
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
