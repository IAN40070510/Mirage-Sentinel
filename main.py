# deception_db：欺敵記憶讀寫（同 IP + query_id 的持續欺敵）
from core.deception_db import setup_deception_db

"""
Mirage-Sentinel 主入口（API Gateway）

本檔案負責：
1. 啟動 FastAPI 與 Nginx、middleware。
2. 提供主要對外 API（已移除 /api/v1/user/{user_id} 與 /api/v1/simulate_attack，改由 80 port 的 vuln-bank-main API 服務）。
3. 初始化雙資料庫（traffic + deception memory）。
4. 協調哨兵偵測、欺敵策略、沙盒回應與日誌落地。
"""

from fastapi import (
    FastAPI,
    Request,
    BackgroundTasks,
    HTTPException,
    Depends,
    Header,
)
from fastapi.openapi.utils import get_openapi
from fastapi.responses import Response
import uvicorn
import time
import os
import logging
import importlib
import ipaddress
import math
import statistics
import json
import re
import hashlib
from typing import Any, cast
from urllib.parse import parse_qsl
import pandas as pd
import httpx
from datetime import datetime
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# 配置日誌（實際輸出格式與 handler 由啟動環境決定）
logger = logging.getLogger(__name__)

# ===== 核心模組匯入 =====
# sentinel：攻擊意圖偵測（目前改為本機 AI 模型主判斷）
# deception_db：欺敵記憶讀寫
# deception_engine：互動深度/漏斗層級評分
# traffic_db：全量流量事件落地
# sandbox：惡意流量導向沙盒/降級假資料
from core.traffic_db import (
    setup_traffic_db,
    log_traffic_event,
    get_recent_transactions_by_user,
    get_transaction_amounts_by_user,
)
from core.feature_store import get_feature_store
from core.sentinel import (
    analyze_intent as signature_analyze_intent,
    detect_replication_risk,
    detect_rate_limiting_risk,
    detect_anomalous_amount_risk,
)
from api import dashboard
from api.db.session import init_db, create_tables, seed_banking_demo_data

def _resolve_model_loader():
    """模型路徑相容：優先新路徑，失敗時回退舊路徑。"""
    module_candidates = (
        "model.Sentinel.XGBoost.ai_sentinel",
        "model.ai_sentinel",
    )
    for module_name in module_candidates:
        try:
            module = importlib.import_module(module_name)
            loader = getattr(module, "load_sentinel_model", None)
            if callable(loader):
                return loader
        except Exception:
            continue

    logger.warning("AI 模型載入器不可用，將回退簽名規則模式。")
    return lambda: None


load_sentinel_model = _resolve_model_loader()

from fastapi.middleware.cors import CORSMiddleware

distilbert_model = None
# 載入 .env（讓 API_KEY / SANDBOX_API_URL 等配置可由環境管理）
load_dotenv()
feature_store = get_feature_store()

# ===== API Key 設定 =====
# API_KEY 主要用於 Dashboard 驗證；當 Dashboard 關閉時，允許以警告模式啟動。
API_KEY = os.getenv("API_KEY", "").strip()
ai_sentinel: Any = load_sentinel_model()


def _is_placeholder_secret(secret: str) -> bool:
    marker = (secret or "").strip().lower()
    return (
        (not marker)
        or marker.startswith("change_me")
        or marker.startswith("replace-with")
    )


def _env_flag(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


ENABLE_DASHBOARD = _env_flag("ENABLE_DASHBOARD", "false")
DASHBOARD_INTERNAL_ONLY = _env_flag("DASHBOARD_INTERNAL_ONLY", "true")
DASHBOARD_ADMIN_KEY = os.getenv("DASHBOARD_ADMIN_KEY", "").strip()
VULN_BANK_BASE_URL = os.getenv("VULN_BANK_BASE_URL", "http://vuln-bank-main:80").rstrip(
    "/"
)


def _is_private_or_loopback_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        return ip_obj.is_private or ip_obj.is_loopback
    except Exception:
        return False


def _is_valid_ip(ip_text: str) -> bool:
    try:
        ipaddress.ip_address((ip_text or "").strip())
        return True
    except Exception:
        return False


def _extract_client_ip(request: Request) -> str:
    """擷取可信來源 IP：僅在上游是私網代理時才信任轉發標頭。"""
    peer_ip = request.client.host if request.client else ""
    if _is_private_or_loopback_ip(peer_ip):
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            forwarded_ip = xff.split(",")[0].strip()
            if _is_valid_ip(forwarded_ip):
                return forwarded_ip

        x_real_ip = request.headers.get("x-real-ip", "").strip()
        if _is_valid_ip(x_real_ip):
            return x_real_ip

    return peer_ip


async def verify_dashboard_access(
    request: Request,
    x_dashboard_key: str | None = Header(default=None, alias="X-Dashboard-Key"),
):
    """
    根據 ENABLE_DASHBOARD 決定是否允許訪問。
    若 Dashboard 禁用，返回 403。
    若啟用，則檢查內網 IP 或管理金鑰。
    """
    # 如果 Dashboard 功能被禁用，直接拒絕訪問
    if not ENABLE_DASHBOARD:
        raise HTTPException(
            status_code=403, detail="Dashboard is disabled on this instance"
        )

    # Dashboard 啟用時，檢查內網限制
    if not DASHBOARD_INTERNAL_ONLY:
        return

    client_ip = request.client.host if request.client else ""
    if _is_private_or_loopback_ip(client_ip):
        return

    if DASHBOARD_ADMIN_KEY and x_dashboard_key == DASHBOARD_ADMIN_KEY:
        return

    raise HTTPException(
        status_code=403, detail="Dashboard is restricted to internal network"
    )


def analyze_intent(text: str):
    """
    使用本機 AI Sentinel 作為主判斷引擎，回傳格式與舊介面相容。
    回傳: (is_attack, confidence, attack_vector, sentinel_decision, sentinel_model_ready)
    """
    if not text or not str(text).strip():
        return False, 0.0, "None", "PASS", bool(ai_sentinel)

    if not ai_sentinel:
        # 模型未載入時回退到簽名規則引擎，避免入口完全失明。
        is_attack, confidence, attack_vector = signature_analyze_intent(text)
        return (
            is_attack,
            confidence,
            attack_vector,
            "BLOCK" if is_attack else "PASS",
            False,
        )

    try:
        df_input = pd.DataFrame({"payload": [str(text).lower().strip()]})
        judgment = ai_sentinel.predict(df_input).iloc[0]

        confidence = float(judgment["attack_score"])
        attack_vector = str(judgment["top_attack_type"])
        sentinel_decision = str(judgment.get("decision", "PASS") or "PASS")
        is_attack = confidence > 0.3

        return is_attack, confidence, attack_vector, sentinel_decision, True
    except Exception as exc:
        logger.error(f"AI Sentinel 判斷失敗: {exc}")
        return False, 0.0, "None", "PASS", bool(ai_sentinel)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    應用生命週期：
    1) 驗證 API_KEY（僅在 Dashboard 啟用時要求有效值）。
    2) 初始化 deception / traffic 雙資料庫。
    3) 啟動完成後交由 FastAPI 正常提供服務。
    """
    if _is_placeholder_secret(API_KEY):
        if ENABLE_DASHBOARD:
            raise RuntimeError(
                "API_KEY is required and must not be empty or placeholder text."
            )
        logger.warning("API_KEY 未提供有效值，Dashboard 已關閉，將以降級模式啟動。")

    if not ENABLE_DASHBOARD:
        logger.info("Dashboard 已停用，略過 API_KEY 強制檢查。")

    setup_deception_db()
    setup_traffic_db()

    # Initialize PostgreSQL database if DATABASE_URL is set
    if init_db():
        create_tables()
        seed_banking_demo_data()
        logger.info("[DB] PostgreSQL database initialized successfully.")
    else:
        logger.warning("[DB] PostgreSQL not connected - using mock data mode.")

    logger.info("Mirage-Sentinel 全時哨兵監控模式已啟動。")
    yield


# ===== FastAPI App 建立 =====
# 始終保留 OpenAPI 文檔供查看，但 Dashboard 路由會檢查 ENABLE_DASHBOARD
app = FastAPI(
    title="Mirage-Sentinel API Gateway",
    version="1.6-FullSentinel",
    lifespan=lifespan,
    docs_url="/docs",  # 始終允許查看 API 文規
    redoc_url="/redoc",  # 始終允許 ReDoc
    openapi_url="/openapi.json",  # 始終允許 OpenAPI schema
)


# 始終包含 Dashboard 路由，但 verify_dashboard_access 會根據 ENABLE_DASHBOARD 拒絕訪問
app.include_router(
    dashboard.router,
    prefix="/api/v1",
    tags=["Dashboard"],
    dependencies=[Depends(verify_dashboard_access)],
)

# CORS：目前開發期全面放行，正式環境可改為白名單。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 自定義 OpenAPI schema 生成：根據 ENABLE_DASHBOARD 過濾文檔
def custom_openapi() -> dict[str, object]:
    """
    生成 OpenAPI schema，當 ENABLE_DASHBOARD=false 時，隱藏 Dashboard 路由。
    符合 AGENTS.md 安全規範：公開蜜罐不應暴露敏感監控功能。
    """
    # 每次都重新生成，不使用緩存，確保 ENABLE_DASHBOARD 值被正確應用
    try:
        output = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
    except Exception as generate_error:
        logger.error(f"Failed to generate OpenAPI schema: {generate_error}")
        return {
            "openapi": "3.0.2",
            "info": {"title": app.title, "version": app.version},
            "paths": {},
        }

    # 當 Dashboard 禁用時，移除所有 Dashboard 路由的文檔
    if not ENABLE_DASHBOARD and output.get("paths"):
        paths_to_remove = [
            path
            for path in output["paths"].keys()
            if path == "/api/v1/dashboard" or path.startswith("/api/v1/dashboard/")
        ]
        for path in paths_to_remove:
            del output["paths"][path]

        # 移除 Dashboard tag
        if output.get("tags"):
            output["tags"] = [
                tag for tag in output["tags"] if tag.get("name") != "Dashboard"
            ]

        logger.info(
            f"Filtered OpenAPI schema: removed {len(paths_to_remove)} Dashboard paths"
        )

    app.openapi_schema = output
    return app.openapi_schema


app.openapi = custom_openapi


def _compute_header_entropy(request: Request) -> float:
    """以請求 Header 名稱字元分布近似熵值，用於維度 2 的結構特徵。"""
    header_names = "".join(sorted(k.lower() for k in request.headers.keys()))
    if not header_names:
        return 0.0

    counts: dict[str, int] = {}
    total = len(header_names)
    for ch in header_names:
        counts[ch] = counts.get(ch, 0) + 1

    entropy = 0.0
    for value in counts.values():
        p = value / total
        entropy -= p * math.log2(p)

    return round(entropy, 6)


def _parse_request_at(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        return None


def _compute_timing_features(user_id: str) -> tuple[float, float]:
    """從近期請求推估間隔與節奏變異。"""
    recent = get_recent_transactions_by_user(user_id, limit_seconds=900, max_results=25)
    timestamps: list[datetime] = []
    for record in recent:
        parsed = _parse_request_at(record.get("request_at"))
        if parsed:
            timestamps.append(parsed)

    if len(timestamps) < 2:
        return 0.0, 0.0

    timestamps.sort()
    intervals_ms: list[float] = []
    for i in range(1, len(timestamps)):
        delta_ms = (timestamps[i] - timestamps[i - 1]).total_seconds() * 1000.0
        intervals_ms.append(delta_ms)

    last_interval = round(intervals_ms[-1], 3)
    if len(intervals_ms) > 1:
        req_time_var = round(statistics.pvariance(intervals_ms), 6)
    else:
        req_time_var = 0.0

    return last_interval, req_time_var


def _extract_amount_value(
    payload: str | None, explicit_amount: float | None
) -> float | None:
    if explicit_amount is not None:
        return float(explicit_amount)
    if not payload:
        return None

    # 取 payload 第一個數值作為近似金額訊號（非交易場景可能為 None）。
    matched = re.search(r"-?\d+(?:\.\d+)?", str(payload))
    if not matched:
        return None
    try:
        return float(matched.group(0))
    except Exception:
        return None


def _compute_amount_deviation(user_id: str, amount_value: float | None) -> float:
    if amount_value is None:
        return 0.0
    history = get_transaction_amounts_by_user(user_id, limit_hours=24, max_results=100)
    if not history:
        return 0.0
    avg_amount = statistics.mean(history)
    if avg_amount <= 0:
        return 0.0
    return round(amount_value / avg_amount, 6)


def _derive_device_id(client_ip: str, user_agent: str, tls_fingerprint: str) -> str:
    """以穩定字串組合近似設備識別，不存放原始敏感資料。"""
    raw = f"{client_ip}|{user_agent}|{tls_fingerprint}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _derive_session_chain_id(
    client_ip: str,
    principal_id: str,
    device_id: str,
    request_epoch_ms: int,
    bucket_minutes: int = 10,
) -> str:
    """用時間桶將連續互動歸入同一條 session chain，供 SOC 回放。"""
    bucket_ms = max(bucket_minutes, 1) * 60 * 1000
    bucket_index = request_epoch_ms // bucket_ms
    raw = f"{client_ip}|{principal_id}|{device_id}|{bucket_index}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _compute_deception_effectiveness(
    should_intercept: bool,
    risk_level: int,
    confidence: float,
    risk_reasons_count: int,
) -> tuple[str, int, str, bool]:
    """將分流結果標準化成 SOC 可直接顯示的成效欄位。"""
    if not should_intercept:
        return "upstream", 0, "low", False

    base_score = int(min(100, max(risk_level, int(confidence * 100))))
    adjusted_score = min(100, base_score + min(risk_reasons_count * 5, 15))

    if adjusted_score >= 80:
        trust_level = "high"
    elif adjusted_score >= 50:
        trust_level = "medium"
    else:
        trust_level = "low"

    return "deception", adjusted_score, trust_level, False


def _parse_mouse_entropy(request: Request) -> tuple[float, str]:
    """讀取前端回傳的滑鼠熵：優先 Header，其次 Cookie。"""
    raw_value = request.headers.get("X-Mouse-Entropy")
    source = "header"
    if raw_value is None:
        raw_value = request.cookies.get("ms_mouse_entropy")
        source = "cookie"

    if raw_value is None:
        return 0.0, "missing"

    try:
        entropy = float(raw_value)
        if entropy < 0:
            entropy = 0.0
        if entropy > 32.0:
            entropy = 32.0
        return round(entropy, 6), source
    except Exception:
        return 0.0, "invalid"


def _mouse_tracker_script() -> str:
    """注入到 HTML 的追蹤腳本：計算滑鼠方向熵並寫入 cookie。"""
    return (
        "<script>(function(){if(window.__msMouseTracker){return;}"
        "window.__msMouseTracker=true;var pts=[];var maxPts=180;"
        "function n(v){return Number.isFinite(v)?v:0;}"
        "function s(){if(pts.length<6){return 0;}"
        "var bins=[0,0,0,0,0,0,0,0];"
        "for(var i=1;i<pts.length;i++){var dx=pts[i].x-pts[i-1].x;var dy=pts[i].y-pts[i-1].y;"
        "if(dx===0&&dy===0){continue;}"
        "var a=Math.atan2(dy,dx);if(a<0){a+=Math.PI*2;}"
        "var idx=Math.floor((a/(Math.PI*2))*8);if(idx<0){idx=0;}if(idx>7){idx=7;}bins[idx]++;}"
        "var total=0;for(var j=0;j<bins.length;j++){total+=bins[j];}if(total===0){return 0;}"
        "var e=0;for(var k=0;k<bins.length;k++){if(bins[k]===0){continue;}var p=bins[k]/total;e-=p*Math.log2(p);}"
        "return e;}"
        "function w(v){document.cookie='ms_mouse_entropy='+encodeURIComponent(v.toFixed(6))+'; Path=/; Max-Age=600; SameSite=Lax';}"
        "window.addEventListener('mousemove',function(ev){pts.push({x:n(ev.clientX),y:n(ev.clientY),t:Date.now()});"
        "if(pts.length>maxPts){pts.shift();}}, {passive:true});"
        "setInterval(function(){try{w(s());}catch(_e){}},1500);"
        "window.addEventListener('beforeunload',function(){try{w(s());}catch(_e){} });"
        "})();</script>"
    )


def _inject_mouse_tracker_html(content: bytes, content_type: str | None) -> bytes:
    if not content:
        return content
    ctype = (content_type or "").lower()
    if "text/html" not in ctype:
        return content

    try:
        text = content.decode("utf-8")
    except Exception:
        return content

    marker = "window.__msMouseTracker"
    if marker in text:
        return content

    script = _mouse_tracker_script()
    lower = text.lower()
    idx = lower.rfind("</body>")
    if idx >= 0:
        text = text[:idx] + script + text[idx:]
    else:
        text = text + script
    return text.encode("utf-8")


@app.get("/")
async def root() -> dict[str, object]:
    """服務根節點：提供健康入口與文件連結。"""
    return {
        "service": "Mirage-Sentinel API Gateway",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "main_entry": "/api/v1/user/{user_id}",
        "simulate_entry": "/api/v1/simulate_attack",
        "dashboard_enabled": ENABLE_DASHBOARD,
        "dashboard_internal_only": DASHBOARD_INTERNAL_ONLY,
    }


@app.get("/healthz")
async def healthz():
    """容器/平台健康檢查端點。"""
    return {"status": "ok"}


# 攻擊模擬端點：功能與 /user 類似，但來源資訊固定為測試情境


def detect_proxy(request: Request) -> int:
    """
    代理檢測（簡化版）：
    1) 先看常見代理標頭。
    2) 再看 IP 是否命中已知代理池（目前為占位邏輯）。
    3) 最後看 User-Agent 是否帶 proxy/crawler 關鍵字。
    """
    proxy_headers = [
        "X-Forwarded-For",
        "Via",
        "Forwarded",
        "Client-IP",
        "True-Client-IP",
    ]
    for header in proxy_headers:
        if header in request.headers:
            return 1

    client_ip = request.client.host if request.client else ""
    if is_known_proxy_ip(client_ip):
        return 1

    user_agent = request.headers.get("user-agent", "").lower()
    if "proxy" in user_agent or "crawler" in user_agent:
        return 1

    return 0


def is_known_proxy_ip(ip: str) -> bool:
    """已知代理 IP 檢測占位函式（後續可接外部黑名單/資料源）。"""
    return False


def _is_internal_sentinel_path(path: str) -> bool:
    internal_prefixes = (
        "/api/v1/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/healthz",
    )
    return path.startswith(internal_prefixes)


def _is_render_critical_path(path: str) -> bool:
    """前端關鍵資源路徑：避免純規則風險誤攔截造成頁面失真。"""
    normalized = "/" + (path or "").lstrip("/")
    if normalized == "/":
        return True

    if normalized.startswith("/static/"):
        return True

    if normalized in {"/login", "/register", "/forgot-password", "/reset-password"}:
        return True

    ext = os.path.splitext(normalized)[1].lower()
    return ext in {
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
    }


def _build_upstream_headers(request: Request) -> dict[str, str]:
    drop_headers = {
        "host",
        "content-length",
        "connection",
        "accept-encoding",
        "transfer-encoding",
    }
    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in drop_headers
    }
    headers["x-forwarded-proto"] = request.headers.get("x-forwarded-proto", "http")
    headers["x-real-ip"] = _extract_client_ip(request)
    return headers


def _normalize_attack_vector(attack_vector: str | None) -> str:
    normalized = (attack_vector or "").strip()
    if not normalized:
        return ""
    if normalized.lower() in {"none", "null", "unknown"}:
        return ""
    return normalized


def _decision_source(is_attack: bool, risk_reasons: list[str]) -> str:
    if is_attack and risk_reasons:
        return "hybrid"
    if is_attack:
        return "ml"
    if risk_reasons:
        return "rule"
    return "none"


def _extract_login_credentials_text(
    upstream_path: str,
    query_text: str,
    body_text: str,
    content_type: str,
) -> str:
    """Extract username/password-like fields for login routes to ensure SOC/XGBoost visibility."""
    normalized_path = "/" + upstream_path.lstrip("/")
    if normalized_path not in {"/login", "/banking/login"}:
        return ""

    login_keys = {
        "username",
        "password",
        "user",
        "email",
        "account",
    }
    collected: list[str] = []

    for key, value in parse_qsl(query_text, keep_blank_values=True):
        if key.lower() in login_keys:
            collected.append(f"{key}={value}")

    body_content_type = (content_type or "").lower()

    if body_text:
        if "application/json" in body_content_type:
            try:
                payload = json.loads(body_text)
                if isinstance(payload, dict):
                    for key, value in payload.items():
                        if str(key).lower() in login_keys:
                            collected.append(f"{key}={value}")
            except Exception:
                pass

        if (
            "application/x-www-form-urlencoded" in body_content_type
            or ("=" in body_text and "&" in body_text)
        ):
            for key, value in parse_qsl(body_text, keep_blank_values=True):
                if key.lower() in login_keys:
                    collected.append(f"{key}={value}")

    return "&".join(collected)


def _local_deception_payload(
    principal_id: str,
    attack_vector: str,
    client_ip: str,
    upstream_path: str,
) -> dict[str, object]:
    now_iso = datetime.now().isoformat(timespec="milliseconds")
    return {
        "status": "ok",
        "route": "mirage",
        "response_origin": "mirage",
        "user_id": principal_id,
        "attack_vector": attack_vector or "suspicious",
        "message": "Request accepted for extended verification.",
        "ticket": f"MRG-{hashlib.sha256(f'{client_ip}|{principal_id}|{upstream_path}|{now_iso}'.encode('utf-8')).hexdigest()[:12]}",
        "queued_at": now_iso,
        "next_step": "manual_review",
    }


async def _execute_deception_response(
    client_ip: str,
    principal_id: str,
    detection_target: str,
    attack_vector: str,
    risk_level: int,
) -> tuple[bytes, int, dict[str, str], dict[str, object]]:
    try:
        from core.ai_agent_orchestrator import execute_sandbox_ai_agent

        logger.info(
            "[AI AGENT] 前置分流到沙盒AI Agent: %s - %s", client_ip, attack_vector
        )

        ai_response = await execute_sandbox_ai_agent(
            client_ip=client_ip,
            query_id=principal_id,
            raw_payload=detection_target,
            attack_vector=attack_vector,
            risk_level=max(1, risk_level // 10),
        )

        fake_data = ai_response.get("fake_data")
        if isinstance(fake_data, dict) and fake_data:
            return (
                json.dumps(fake_data).encode("utf-8"),
                200,
                {"content-type": "application/json"},
                {
                    "mitigation_status": "ai_deception",
                    "response_payload": fake_data,
                    "response_origin": "sandbox_ai",
                    "deception_mode": "sandbox_ai",
                    "ai_action": ai_response.get("ai_decision", {}).get("action"),
                    "ai_confidence": ai_response.get("ai_decision", {}).get(
                        "confidence", 0
                    ),
                },
            )
    except Exception as ai_exc:
        logger.error("[AI AGENT] 前置分流失敗，改用本機 Mirage 備援: %s", ai_exc)

    # 使用新版 Mirage 假資料生成，傳入端點與攻擊向量
    from core.mirage import generate_fake_data

    endpoint = detection_target.split(" ", 1)[0] if detection_target else ""
    fallback_payload = generate_fake_data(
        principal_id, endpoint=endpoint, attack_vector=attack_vector
    )
    return (
        json.dumps(fallback_payload).encode("utf-8"),
        200,
        {"content-type": "application/json"},
        {
            "mitigation_status": "local_deception_fallback",
            "response_payload": fallback_payload,
            "response_origin": "mirage",
            "deception_mode": "local_fallback",
        },
    )


async def _proxy_banking_request(
    upstream_path: str,
    request: Request,
    background_tasks: BackgroundTasks | None,
):
    start_perf = time.perf_counter()
    request_epoch_ms = int(time.time() * 1000)
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    client_ip = _extract_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    referer = request.headers.get("referer")
    tls_fingerprint = request.headers.get("X-JA3-Fingerprint", "N/A")
    header_entropy = _compute_header_entropy(request)
    device_id = _derive_device_id(client_ip, user_agent, tls_fingerprint)

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    query_text = request.url.query or ""
    # 補強：完整擷取所有 header
    headers_dict = {k.lower(): v for k, v in request.headers.items()}
    header_count = len(headers_dict)
    content_type = headers_dict.get("content-type", "")
    content_length = headers_dict.get("content-length", "")
    authorization = headers_dict.get("authorization", "")
    # principal_id 表示「互動主體識別」，目前優先對應到 vuln-bank-main 的
    # X-User-Id / CIF / customer id。若缺失則回退成 proxy:<client_ip>。
    # query_id 為歷史命名，暫時保留作為相容欄位。
    principal_id = request.headers.get("X-User-Id", "").strip() or f"proxy:{client_ip}"
    query_id = principal_id
    session_chain_id = _derive_session_chain_id(
        client_ip=client_ip,
        principal_id=principal_id,
        device_id=device_id,
        request_epoch_ms=request_epoch_ms,
    )
    normalized_upstream_path = "/" + upstream_path.lstrip("/")
    render_critical_path = _is_render_critical_path(normalized_upstream_path)
    login_credentials_text = _extract_login_credentials_text(
        upstream_path=upstream_path,
        query_text=query_text,
        body_text=body_text,
        content_type=content_type,
    )
    raw_payload_text = body_text
    if login_credentials_text:
        raw_payload_text = (
            f"{body_text}\n{login_credentials_text}" if body_text else login_credentials_text
        )
    detection_target = (
        f"{upstream_path} {query_text} {body_text} {login_credentials_text}".strip()
    )

    req_interval_ms, req_time_var = _compute_timing_features(principal_id)
    amount_value = _extract_amount_value(body_text, None)
    amount_deviation = _compute_amount_deviation(principal_id, amount_value)

    feature_store.record_observation(user_id=principal_id, device_id=device_id)
    graph_metrics = feature_store.get_metrics(user_id=principal_id, device_id=device_id)
    mouse_entropy, mouse_source = _parse_mouse_entropy(request)

    intent_result = analyze_intent(detection_target)
    if isinstance(intent_result, tuple):
        intent_values = cast(tuple[Any, ...], intent_result)
    else:
        intent_values = ()

    if len(intent_values) >= 5:
        (
            is_attack,
            confidence,
            attack_vector,
            sentinel_decision,
            sentinel_model_ready,
        ) = intent_values[:5]
    elif len(intent_values) >= 3:
        is_attack, confidence, attack_vector = intent_values[:3]
        sentinel_decision = "BLOCK" if is_attack else "PASS"
        sentinel_model_ready = bool(ai_sentinel)
    else:
        is_attack, confidence, attack_vector = False, 0.0, "None"
        sentinel_decision = "PASS"
        sentinel_model_ready = bool(ai_sentinel)
    attack_vector = _normalize_attack_vector(attack_vector)
    model_attack_type = attack_vector
    risk_reasons: list[str] = []

    replication_risk, replication_reason = detect_replication_risk(
        principal_id, detection_target
    )
    if replication_risk:
        risk_reasons.append(replication_reason)

    rate_risk, rate_reason = detect_rate_limiting_risk(client_ip)
    if rate_risk:
        risk_reasons.append(rate_reason)

    amount_risk, amount_reason = detect_anomalous_amount_risk(
        principal_id, int(amount_value) if amount_value is not None else None
    )
    if amount_risk:
        risk_reasons.append(amount_reason)

    if risk_reasons:
        attack_vector = ", ".join(filter(None, [attack_vector, *risk_reasons]))

    ml_intercept = is_attack and (sentinel_decision == "BLOCK" or confidence > 0.75)
    should_intercept = (ml_intercept or bool(risk_reasons)) and not render_critical_path
    effective_risk_reasons = risk_reasons if not render_critical_path else []
    decision_source = _decision_source(is_attack, effective_risk_reasons)
    risk_level = max(int(confidence * 100), 80 if effective_risk_reasons else 0)
    flow_stage, deception_score, trust_level, memory_hit = (
        _compute_deception_effectiveness(
            should_intercept=should_intercept,
            risk_level=risk_level,
            confidence=confidence,
            risk_reasons_count=len(effective_risk_reasons),
        )
    )

    event_payload = {
        "request_at": request_at,
        "response_at": None,
        "process_ms": 0,
        "client_ip": client_ip,  # 真實來源 IP（支援 X-Forwarded-For）
        "location": request.headers.get("CF-IPCountry")
        or request.headers.get("X-Country")
        or request.headers.get("X-Country-Code"),
        "is_proxy": detect_proxy(request),
        "user_agent": user_agent,
        "tls_fingerprint": tls_fingerprint,
        "raw_payload": raw_payload_text,  # 完整未解析的原始負載
        "principal_id": principal_id,
        "session_chain_id": session_chain_id,
        "query_id": query_id,
        "method": request.method,  # 請求方法
        "endpoint": f"/{upstream_path.lstrip('/')}",  # 完整目標路徑
        "query_string": query_text,  # 查詢參數原文
        "authorization": authorization,  # 身分驗證憑證原文
        "content_type": content_type,  # 內容類型宣告
        "content_length": content_length,  # 內容長度宣告
        "header_count": header_count,  # 標頭總數量
        "all_headers": headers_dict,  # 所有 header（for 鑑識/除錯，可選）
        "referer": referer,
        "header_entropy": header_entropy,
        "req_interval_ms": req_interval_ms,
        "req_time_var": req_time_var,
        "device_id": device_id,
        "user_device_ratio": graph_metrics.user_device_ratio,
        "device_user_ratio": graph_metrics.device_user_ratio,
        "req_rate_5m": graph_metrics.req_rate_5m,
        "graph_feature_source": graph_metrics.source,
        "mouse_entropy": mouse_entropy,
        "mouse_source": mouse_source,
        "amount_value": amount_value,
        "amount_deviation": amount_deviation,
        "sentinel_score": round(confidence, 6),
        "sentinel_attack_type": model_attack_type,
        "sentinel_decision": sentinel_decision,
        "sentinel_model_ready": 1 if sentinel_model_ready else 0,
        "attack_vector": attack_vector if should_intercept else None,
        "risk_level": risk_level if should_intercept else 0,
        "is_attack": 1 if should_intercept else 0,
        "response_payload": None,
        "hits": 0,
        "interaction_depth": 0,
        "dwell_time": 0.0,
        "mitigation_status": "normal" if not should_intercept else "observed",
        "decision_source": decision_source,
        "route_before": "banking_proxy",
        "route_after": "mirage" if should_intercept else "vuln_bank_main",
        "deception_reason": (
            ", ".join(effective_risk_reasons)
            if effective_risk_reasons
            else attack_vector
        ),
        "policy_hit": attack_vector if should_intercept else None,
        "upstream_attempted": 0,
        "upstream_status_code": None,
        "deception_engaged": 1 if should_intercept else 0,
        "deception_mode": None,
        "real_backend_touched": 0,
        "response_origin": "pending",
        "flow_stage": flow_stage,
        "deception_score": deception_score,
        "trust_level": trust_level,
        "memory_hit": memory_hit,
    }

    status_code = 502
    response_content = b""
    response_headers: dict[str, str] = {}

    if should_intercept:
        (
            response_content,
            status_code,
            response_headers,
            deception_meta,
        ) = await _execute_deception_response(
            client_ip=client_ip,
            principal_id=principal_id,
            detection_target=detection_target,
            attack_vector=attack_vector,
            risk_level=risk_level,
        )
        event_payload.update(deception_meta)
        event_payload["flow_stage"] = "deception"
        event_payload["deception_score"] = max(
            event_payload.get("deception_score", 0), 70
        )
        event_payload["trust_level"] = (
            "high" if event_payload.get("deception_score", 0) >= 80 else "medium"
        )
    else:
        upstream_url = f"{VULN_BANK_BASE_URL}/{upstream_path.lstrip('/')}"
        if query_text:
            upstream_url = f"{upstream_url}?{query_text}"

        event_payload["upstream_attempted"] = 1
        try:
            async with httpx.AsyncClient(
                timeout=20.0, follow_redirects=False
            ) as client:
                upstream_response = await client.request(
                    method=request.method,
                    url=upstream_url,
                    content=body_bytes if body_bytes else None,
                    headers=_build_upstream_headers(request),
                )
            status_code = upstream_response.status_code
            response_content = _inject_mouse_tracker_html(
                upstream_response.content,
                upstream_response.headers.get("content-type"),
            )
            response_headers = {
                k: v
                for k, v in upstream_response.headers.items()
                if k.lower()
                not in {
                    "content-length",
                    "transfer-encoding",
                    "connection",
                }
            }
            event_payload["upstream_status_code"] = status_code
            event_payload["real_backend_touched"] = 1
            event_payload["response_origin"] = "vuln_bank_main"
            event_payload["flow_stage"] = "upstream"
        except Exception as exc:
            logger.error("banking proxy upstream failed: %s", exc)
            response_content = b'{"detail":"upstream unavailable"}'
            response_headers = {"content-type": "application/json"}
            event_payload["mitigation_status"] = "upstream_error"
            event_payload["response_origin"] = "upstream_error"
            event_payload["flow_stage"] = "upstream_error"

    process_ms = int((time.perf_counter() - start_perf) * 1000)
    response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    event_payload["process_ms"] = process_ms
    event_payload["response_at"] = response_at

    if background_tasks:
        background_tasks.add_task(log_traffic_event, event_payload)
    else:
        log_traffic_event(event_payload)

    return Response(
        content=response_content,
        status_code=status_code,
        headers=response_headers,
    )


@app.api_route(
    "/banking/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def proxy_banking_prefixed(
    path: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    return await _proxy_banking_request(
        upstream_path=path,
        request=request,
        background_tasks=background_tasks,
    )


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def proxy_banking_root(
    path: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    req_path = "/" + path.lstrip("/") if path else "/"
    if _is_internal_sentinel_path(req_path):
        raise HTTPException(status_code=404, detail="Not found")

    return await _proxy_banking_request(
        upstream_path=path,
        request=request,
        background_tasks=background_tasks,
    )


if __name__ == "__main__":
    # 生產環境通常交給 process manager / container 指令啟動。
    # 這裡保留本機開發入口，方便直接 python main.py。
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port)
