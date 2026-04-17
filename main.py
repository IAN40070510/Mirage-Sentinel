# deception_db：欺敵記憶讀寫（同 IP + principal_id 的持續欺敵）
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
import html
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
        except ImportError:
            # Module not found or failed to import, try next candidate
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


def _get_vuln_bank_base_url_candidates() -> list[str]:
    primary = VULN_BANK_BASE_URL
    candidates: list[str] = [primary]
    for url in (
        "http://localhost:80",
        "http://127.0.0.1:80",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
    ):
        normalized = url.rstrip("/")
        if normalized not in candidates:
            candidates.append(normalized)
    return candidates


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


def _extract_json_or_form_fields(body_text: str, content_type: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    body = (body_text or "").strip()
    lowered_content_type = (content_type or "").lower()

    if not body:
        return fields

    if "application/json" in lowered_content_type or body.startswith("{") or body.startswith("["):
        try:
            payload = json.loads(body)
            if isinstance(payload, dict):
                for key, value in payload.items():
                    fields[str(key).lower()] = str(value).strip()
        except Exception:
            pass

    if "application/x-www-form-urlencoded" in lowered_content_type or ("=" in body and "&" in body):
        for key, value in parse_qsl(body, keep_blank_values=True):
            fields[str(key).lower()] = str(value).strip()

    return fields


def _derive_principal_id(
    upstream_path: str,
    body_text: str,
    content_type: str,
    request: Request,
    client_ip: str,
) -> str:
    header_principal = request.headers.get("X-User-Id", "").strip()
    if header_principal:
        return header_principal

    normalized_path = "/" + (upstream_path or "").lstrip("/").lower()
    if normalized_path in {"/login", "/register"}:
        body_fields = _extract_json_or_form_fields(body_text, content_type)
        username = body_fields.get("username", "").strip()
        if username:
            return username

    return f"proxy:{client_ip}"


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
        logger.warning("AI Sentinel model unavailable; returning neutral PASS.")
        return False, 0.0, "None", "PASS", False

    try:
        df_input = pd.DataFrame({"payload": [str(text).lower().strip()]})
        judgment = ai_sentinel.predict(df_input).iloc[0]

        confidence = float(judgment["attack_score"])
        attack_vector = str(judgment["top_attack_type"])
        # 產品規則：僅保留二元決策，attack_score >= 0.7 視為 BLOCK，否則 PASS。
        is_attack = confidence >= 0.7
        sentinel_decision = "BLOCK" if is_attack else "PASS"

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


def _build_mirage_cookie_header(fake_session_token: str) -> str:
    """Build Mirage session cookie header for deception-flow stickiness."""
    return f"mirage_session={fake_session_token}; Path=/; HttpOnly; SameSite=Lax"


def _coerce_amount(value: object, fallback: float = 1000.0) -> float:
    try:
        if isinstance(value, (int, float, str)):
            return float(value)
    except Exception:
        pass
    return fallback


def _build_mirage_dashboard_html(fake_response: dict[str, object]) -> str:
        """Render a shadow dashboard using the same template shape as real banking UI."""
        username = str(fake_response.get("username") or fake_response.get("user_id") or "guest")
        account_number = str(
                fake_response.get("account_number")
                or fake_response.get("account_id")
                or "ACC-UNKNOWN"
        )
        balance = fake_response.get("balance", 50000.0)

        try:
            if isinstance(balance, (int, float, str)):
                balance_text = f"{float(balance):,.2f}"
            else:
                balance_text = "50,000.00"
        except Exception:
            balance_text = "50,000.00"

        safe_username = html.escape(username)
        safe_account = html.escape(account_number)
        safe_balance = html.escape(balance_text)

        template_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "vuln-bank-main",
            "templates",
            "dashboard.html",
        )
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
        except Exception:
            return (
                "<!DOCTYPE html><html><body>"
                f"<h1>Welcome back, {safe_username}</h1>"
                f"<p>Account: {safe_account}</p>"
                f"<p>Balance: ${safe_balance}</p>"
                "</body></html>"
            )

        # Core substitutions used by the real dashboard layout.
        template = template.replace("{{ username | safe }}", safe_username)
        template = template.replace("{{ username }}", safe_username)
        template = template.replace("{{ account_number }}", safe_account)
        template = template.replace("{{ balance }}", safe_balance)
        template = template.replace("{{ user_bio|safe }}", "")
        template = template.replace(
            "{{ url_for('static', filename='uploads/' + user.profile_picture) if user.profile_picture else url_for('static', filename='user.png') }}",
            "/static/user.png",
        )
        template = re.sub(
            r"\{\{\s*url_for\('static',\s*filename='([^']+)'\)\s*\}\}",
            lambda m: f"/static/{m.group(1)}",
            template,
        )

        # Remove unresolved Jinja control blocks/vars so browser receives plain HTML.
        template = re.sub(r"\{%[^%]*%\}", "", template)
        template = re.sub(r"\{\{[^}]*\}\}", "", template)

        # Keep frontend logic intact by seeding the shadow token expected by dashboard.js.
        bootstrap = (
            "<script>"
            f"localStorage.setItem('jwt_token', '{html.escape(str(fake_response.get('token') or fake_response.get('session_token') or ''))}');"
            "</script>"
        )
        marker = "</head>"
        if marker in template:
            template = template.replace(marker, bootstrap + marker, 1)
        else:
            template = bootstrap + template

        return template


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

        if "application/x-www-form-urlencoded" in body_content_type or (
            "=" in body_text and "&" in body_text
        ):
            for key, value in parse_qsl(body_text, keep_blank_values=True):
                if key.lower() in login_keys:
                    collected.append(f"{key}={value}")

    return "&".join(collected)


def _classify_banking_surface(upstream_path: str) -> tuple[str, str]:
    """將銀行請求歸類為可觀測的業務面向，避免只剩地理 location 可用。"""
    normalized_path = "/" + (upstream_path or "").lstrip("/")
    lowered_path = normalized_path.lower()

    if "/transfer" in lowered_path:
        return "banking:transfers", "transfer"
    if "/login" in lowered_path:
        return "banking:auth", "login"
    if "/balance" in lowered_path or "check_balance" in lowered_path:
        return "banking:balance", "balance"
    if "/loan" in lowered_path or "borrow" in lowered_path:
        return "banking:loans", "loan"
    if "/graphql" in lowered_path:
        return "banking:graphql", "graphql"
    if "/payment" in lowered_path or "/bill" in lowered_path:
        return "banking:payments", "payment"
    if "/card" in lowered_path:
        return "banking:cards", "card"
    if "/admin" in lowered_path:
        return "banking:admin", "admin"
    return "banking:generic", "general"


def _extract_transfer_details_text(
    upstream_path: str,
    query_text: str,
    body_text: str,
    content_type: str,
) -> str:
    """Extract transfer-like fields so SOC/XGBoost can see business context beyond raw payload."""
    normalized_path = "/" + (upstream_path or "").lstrip("/")
    lowered_path = normalized_path.lower()
    if "transfer" not in lowered_path and "payment" not in lowered_path:
        return ""

    transfer_keys = {
        "from_account",
        "fromaccount",
        "source_account",
        "sourceaccount",
        "to_account",
        "toaccount",
        "recipient",
        "recipient_account",
        "destination_account",
        "amount",
        "currency",
        "memo",
        "note",
        "description",
        "reference",
        "transfer_id",
        "beneficiary",
    }
    collected: list[str] = []

    for key, value in parse_qsl(query_text, keep_blank_values=True):
        if key.lower() in transfer_keys:
            collected.append(f"{key}={value}")

    body_content_type = (content_type or "").lower()

    if body_text:
        if "application/json" in body_content_type:
            try:
                payload = json.loads(body_text)
                if isinstance(payload, dict):
                    for key, value in payload.items():
                        if str(key).lower() in transfer_keys:
                            collected.append(f"{key}={value}")
            except Exception:
                pass

        if "application/x-www-form-urlencoded" in body_content_type or (
            "=" in body_text and "&" in body_text
        ):
            for key, value in parse_qsl(body_text, keep_blank_values=True):
                if key.lower() in transfer_keys:
                    collected.append(f"{key}={value}")

    return "&".join(collected)


def _extract_loan_details_text(
    upstream_path: str,
    query_text: str,
    body_text: str,
    content_type: str,
) -> str:
    """Extract loan/borrow input fields for request_loan and related flows."""
    normalized_path = "/" + (upstream_path or "").lstrip("/")
    lowered_path = normalized_path.lower()
    if "loan" not in lowered_path and "borrow" not in lowered_path:
        return ""

    loan_keys = {
        "amount",
        "loan_amount",
        "principal",
        "term",
        "tenor",
        "purpose",
        "reason",
        "collateral",
        "interest",
        "repayment",
        "installment",
        "payment_date",
        "income",
    }
    collected: list[str] = []

    for key, value in parse_qsl(query_text, keep_blank_values=True):
        if key.lower() in loan_keys:
            collected.append(f"{key}={value}")

    body_content_type = (content_type or "").lower()

    if body_text:
        if "application/json" in body_content_type:
            try:
                payload = json.loads(body_text)
                if isinstance(payload, dict):
                    for key, value in payload.items():
                        if str(key).lower() in loan_keys:
                            collected.append(f"{key}={value}")
            except Exception:
                pass

        if "application/x-www-form-urlencoded" in body_content_type or (
            "=" in body_text and "&" in body_text
        ):
            for key, value in parse_qsl(body_text, keep_blank_values=True):
                if key.lower() in loan_keys:
                    collected.append(f"{key}={value}")

    return "&".join(collected)


def _collect_scalar_values(data: Any, out: list[str]) -> None:
    if data is None:
        return
    if isinstance(data, dict):
        for value in data.values():
            _collect_scalar_values(value, out)
        return
    if isinstance(data, (list, tuple, set)):
        for item in data:
            _collect_scalar_values(item, out)
        return
    text = str(data).strip()
    if text:
        out.append(text)


def _build_values_only_detection_target(
    query_text: str,
    body_text: str,
    content_type: str,
) -> str:
    """Build XGBoost input using user-provided values only (exclude field names)."""
    values: list[str] = []

    if query_text:
        for _, value in parse_qsl(query_text, keep_blank_values=True):
            v = (value or "").strip()
            if v:
                values.append(v)

    lowered_content_type = (content_type or "").lower()
    body = (body_text or "").strip()

    if body:
        parsed = False

        if "application/json" in lowered_content_type or body.startswith("{") or body.startswith("["):
            try:
                payload = json.loads(body)
                _collect_scalar_values(payload, values)
                parsed = True
            except Exception:
                pass

        if (
            not parsed
            and (
                "application/x-www-form-urlencoded" in lowered_content_type
                or ("=" in body and "&" in body)
            )
        ):
            for _, value in parse_qsl(body, keep_blank_values=True):
                v = (value or "").strip()
                if v:
                    values.append(v)
            parsed = True

        if not parsed:
            values.append(body)

    return "".join(values).strip()


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
    upstream_path: str = "",
    request_method: str = "GET",
    body_text: str = "",
) -> tuple[bytes, int, dict[str, str], dict[str, object]]:
    """
    執行欺敵回應：
    1. 根據端點類型調用 Mirage 生成假回應
    2. 根據攻擊類型在欺敵資料庫中記錄信息（登入/轉帳/卡片等）
    3. 返回符合該端點的假回應
    """
    from core.mirage import generate_fake_data
    from core.deception_db import (
        get_memory,
        save_deception_state,
        create_fake_session_token,
        get_fake_account_for_attacker,
        record_fake_login,
        record_fake_transaction,
        record_fake_card,
        get_fake_cards_for_attacker,
        fund_fake_card,
        toggle_fake_card_freeze,
        update_fake_card_limit,
        get_fake_card_transactions,
        apply_fake_transfer,
        get_fake_bill_categories,
        get_fake_billers_by_category,
        record_fake_bill_payment,
        get_fake_bill_payments_history,
    )
    
    endpoint = "/" + (upstream_path or "").lstrip("/").lower()

    cached_memory = get_memory(client_ip, principal_id)
    fake_response: dict[str, object] | None = None
    if cached_memory and isinstance(cached_memory.get("payload"), dict):
        fake_response = cast(dict[str, object], cached_memory["payload"])
        fake_response["response_origin"] = "deception_db"
        fake_response["deception_mode"] = "db_reuse"
    else:
        fake_response = generate_fake_data(
            principal_id, endpoint=endpoint, attack_vector=attack_vector
        )

    # 嚴格模式：Mirage 只能模型回應，模型不可用時返回適當的錯誤結構。
    if not fake_response:
        now_iso = datetime.now().isoformat(timespec="milliseconds")
        fake_session_token = create_fake_session_token(client_ip, principal_id)
        
        # 即使模型不可用，也返回結構化的錯誤回應（200 而非 503，使前端能正確解析）
        error_payload = {
            "status": "error",
            "route": "mirage",
            "response_origin": "mirage_unavailable",
            "message": "Service temporarily unavailable. Please try again.",
            "endpoint": endpoint,
            "user_id": principal_id,
            "session_token": fake_session_token,
            "created_at": now_iso,
        }
        # 將錯誤也保存到欺敵資料庫，作為記錄
        save_deception_state(
            client_ip=client_ip,
            principal_id=principal_id,
            vector=attack_vector,
            risk=risk_level,
            payload=error_payload
        )
        
        return (
            json.dumps(error_payload, ensure_ascii=False).encode("utf-8"),
            200,  # 改為 200，使前端能正確解析此回應
            {
                "content-type": "application/json; charset=utf-8",
                "set-cookie": _build_mirage_cookie_header(fake_session_token),
            },
            {
                "mitigation_status": "mirage_unavailable",
                "response_payload": error_payload,
                "response_origin": "mirage",
                "deception_mode": "model_only",
            },
        )
    
    now_iso = datetime.now().isoformat(timespec="milliseconds")
    fake_session_token = create_fake_session_token(client_ip, principal_id)
    fake_username = str(fake_response.get("user_id", f"attacker_{principal_id}"))
    request_fields = _extract_json_or_form_fields(body_text, "application/json")
    request_fields.update(_extract_json_or_form_fields(body_text, "application/x-www-form-urlencoded"))
    
    # 根據端點類型記錄到欺敵資料庫
    if "/login" in endpoint or "/register" in endpoint:
        # 登入/註冊攻擊：記錄假帳號/密碼
        req_username = str(request_fields.get("username", "")).strip()
        req_password = str(request_fields.get("password", "")).strip()
        model_username = str(
            fake_response.get("username")
            or fake_response.get("user_id")
            or fake_response.get("account_id")
            or ""
        ).strip()
        model_password = str(fake_response.get("password", "")).strip()

        fake_username = req_username or model_username or f"attacker_{principal_id}"
        fake_password = req_password or model_password or "honeypot_default_password"
        fake_account_id = str(
            req_username
            or fake_response.get("account_number")
            or fake_response.get("account_id")
            or f"ACC-{fake_session_token[:8]}"
        )

        existing_fake_account = get_fake_account_for_attacker(client_ip, principal_id)
        if existing_fake_account:
            login_balance = _coerce_amount(existing_fake_account.get("balance", 50000.0), fallback=50000.0)
        else:
            login_balance = _coerce_amount(fake_response.get("balance", 50000.0), fallback=50000.0)
        mirror_is_admin = bool(fake_response.get("is_admin", False))
        mirror_profile_picture = (
            str(fake_response.get("profile_picture"))
            if fake_response.get("profile_picture") is not None
            else None
        )
        mirror_reset_pin = (
            str(fake_response.get("reset_pin"))
            if fake_response.get("reset_pin") is not None
            else None
        )
        mirror_bio = (
            str(fake_response.get("bio"))
            if fake_response.get("bio") is not None
            else None
        )
        mirror_is_suspended = bool(fake_response.get("is_suspended", False))

        record_fake_login(
            client_ip,
            principal_id,
            fake_username,
            fake_password,
            fake_account_id,
            balance=login_balance,
            is_admin=mirror_is_admin,
            profile_picture=mirror_profile_picture,
            reset_pin=mirror_reset_pin,
            bio=mirror_bio,
            is_suspended=mirror_is_suspended,
        )
        fake_response["username"] = fake_username
        fake_response["password"] = fake_password
        fake_response["account_number"] = fake_account_id
        fake_response["balance"] = login_balance
        fake_response["session_token"] = fake_session_token
        fake_response["token"] = fake_session_token
        fake_response["status"] = "success"
        # 區分 login 和 register 回應
        if "/register" in endpoint:
            fake_response["message"] = "Registration successful"
        else:
            fake_response["message"] = "Login successful"

    elif "/bill-categories" in endpoint:
        fake_response = {
            "status": "success",
            "categories": get_fake_bill_categories(),
        }

    elif "/billers/by-category/" in endpoint:
        category_match = re.search(r"/billers/by-category/(\d+)", endpoint)
        category_id = int(category_match.group(1)) if category_match else 0
        fake_response = {
            "status": "success",
            "billers": get_fake_billers_by_category(category_id),
        }

    elif "/bill-payments/create" in endpoint:
        try:
            biller_id = int(request_fields.get("biller_id") or 0)
            amount = _coerce_amount(request_fields.get("amount", 0.0), fallback=0.0)
            payment_method = str(request_fields.get("payment_method") or "balance")
            card_raw = request_fields.get("card_id")
            card_id = int(card_raw) if card_raw not in (None, "") else None
            description = str(request_fields.get("description") or "Bill Payment")

            payment_result = record_fake_bill_payment(
                client_ip=client_ip,
                principal_id=principal_id,
                biller_id=biller_id,
                amount=amount,
                payment_method=payment_method,
                card_id=card_id,
                description=description,
            )
            fake_response = {
                "status": "success",
                "message": "Payment processed successfully",
                "payment_details": {
                    "reference": payment_result.get("reference"),
                    "amount": payment_result.get("amount"),
                    "payment_method": payment_result.get("payment_method"),
                    "card_id": payment_result.get("card_id"),
                    "timestamp": payment_result.get("timestamp"),
                    "processed_by": payment_result.get("processed_by"),
                },
                "new_balance": payment_result.get("new_balance"),
            }
        except ValueError as exc:
            fake_response = {
                "status": "error",
                "message": str(exc),
            }

    elif "/bill-payments/history" in endpoint:
        fake_response = {
            "status": "success",
            "payments": get_fake_bill_payments_history(client_ip, principal_id),
        }
        
    elif "/transfer" in endpoint or "/virtual_card" in endpoint or "/virtualcard" in endpoint:
        # 轉帳攻擊（包含虛擬卡轉帳）：記錄假轉帳，不做真轉帳
        to_account = str(
            request_fields.get("to_account")
            or request_fields.get("toaccount")
            or fake_response.get("to_account", "ACC-002-FAKE")
        )
        amount = _coerce_amount(request_fields.get("amount", fake_response.get("amount", 1000)))
        description = str(
            request_fields.get("description")
            or request_fields.get("memo")
            or request_fields.get("note")
            or fake_response.get("description")
            or "Transfer"
        )
        currency = str(request_fields.get("currency", fake_response.get("currency", "USD")))
        transaction_id = str(fake_response.get("transaction_id", f"TXN-{fake_session_token[:12]}"))
        transfer_result = apply_fake_transfer(
            client_ip=client_ip,
            principal_id=principal_id,
            to_account=to_account,
            amount=amount,
            currency=currency,
            description=description,
            transaction_id=transaction_id,
        )
        fake_response["status"] = "success"
        fake_response["message"] = "Transfer completed" if "/transfer" in endpoint else "Virtual card transfer completed"
        fake_response["confirmation_code"] = f"CONF-{fake_session_token[:12]}"
        fake_response["from_account"] = transfer_result["from_account"]
        fake_response["to_account"] = transfer_result["to_account"]
        fake_response["amount"] = transfer_result["amount"]
        fake_response["description"] = transfer_result["description"]
        fake_response["currency"] = transfer_result["currency"]
        fake_response["transaction_id"] = transfer_result["transaction_id"]
        fake_response["new_balance"] = transfer_result["new_balance"]
        fake_response["balance"] = transfer_result["new_balance"]
        
    elif "/virtual-cards/" in endpoint and "/fund" in endpoint and request_method.upper() == "POST":
        card_match = re.search(r"/virtual-cards/(\d+)/fund", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        funding_result = fund_fake_card(
            client_ip,
            principal_id,
            card_id,
            _coerce_amount(request_fields.get("amount", 0.0), fallback=0.0),
        )
        fake_response = {
            "status": "success",
            "message": "Card funded successfully",
            "funding": funding_result,
        }

    elif "/virtual-cards/" in endpoint and "/toggle-freeze" in endpoint and request_method.upper() == "POST":
        card_match = re.search(r"/virtual-cards/(\d+)/toggle-freeze", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        frozen = toggle_fake_card_freeze(principal_id, card_id)
        fake_response = {
            "status": "success",
            "message": "Card frozen successfully" if frozen else "Card unfrozen successfully",
            "is_frozen": frozen,
        }

    elif "/virtual-cards/" in endpoint and "/update-limit" in endpoint and request_method.upper() == "POST":
        card_match = re.search(r"/virtual-cards/(\d+)/update-limit", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        updated = update_fake_card_limit(
            principal_id,
            card_id,
            _coerce_amount(request_fields.get("card_limit", request_fields.get("limit", 0.0)), fallback=0.0),
        )
        fake_response = {
            "status": "success",
            "message": "Card updated successfully",
            "debug_info": {
                "updated_fields": ["card_limit"],
                "card_details": updated,
            },
        }

    elif "/virtual-cards/" in endpoint and "/transactions" in endpoint:
        card_match = re.search(r"/virtual-cards/(\d+)/transactions", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        fake_response = {
            "status": "success",
            "transactions": get_fake_card_transactions(principal_id, card_id),
        }

    elif "/api/virtual-cards/create" in endpoint and request_method.upper() == "POST":
        fake_account = get_fake_account_for_attacker(client_ip, principal_id)
        card_holder = str(
            request_fields.get("card_holder")
            or (fake_account or {}).get("username")
            or principal_id
        )
        card_number = str(
            request_fields.get("card_number")
            or f"4{hashlib.sha256(f'{principal_id}|{time.time()}'.encode('utf-8')).hexdigest()[:15]}"
        )
        expiry = str(
            request_fields.get("expiry")
            or request_fields.get("expiry_date")
            or "12/28"
        )
        cvv = str(request_fields.get("cvv") or "123")
        card_type = str(request_fields.get("card_type") or "standard")
        card_currency = str(request_fields.get("currency") or "USD").upper()
        card_limit = _coerce_amount(request_fields.get("card_limit", 1000.0), fallback=1000.0)

        record_fake_card(
            client_ip,
            principal_id,
            card_number,
            card_holder,
            expiry,
            cvv,
            card_type,
            currency=card_currency,
            card_limit=card_limit,
            current_balance=0.0,
            is_frozen=False,
        )

        cards = get_fake_cards_for_attacker(client_ip, principal_id)
        created_card = cards[0] if cards else {
            "id": None,
            "card_number": card_number,
            "cvv": cvv,
            "expiry_date": expiry,
            "limit": card_limit,
            "balance": 0.0,
            "card_type": card_type,
            "currency": card_currency,
            "currency_symbol": "$",
        }

        fake_response = {
            "status": "success",
            "message": "Virtual card created successfully",
            "card_details": {
                "id": created_card.get("id"),
                "card_number": created_card.get("card_number"),
                "cvv": created_card.get("cvv"),
                "expiry_date": created_card.get("expiry_date") or created_card.get("expiry"),
                "limit": created_card.get("limit", card_limit),
                "balance": created_card.get("balance", 0.0),
                "type": created_card.get("card_type", card_type),
                "currency": created_card.get("currency", card_currency),
                "currency_symbol": created_card.get("currency_symbol", "$"),
            },
        }

    elif endpoint.endswith("/api/virtual-cards"):
        fake_response = {
            "status": "success",
            "cards": get_fake_cards_for_attacker(client_ip, principal_id),
        }

    elif (
        "/new_card" in endpoint
        or "/newcard" in endpoint
        or "/add_card" in endpoint
        or "/upload" in endpoint
        or "/profile" in endpoint
        or "/card" in endpoint
    ):
        fake_card_number = str(request_fields.get("card_number") or fake_response.get("card_number", "4111111111111111"))
        fake_card_holder = str(request_fields.get("card_holder") or fake_response.get("card_holder", fake_username or "Honeypot User"))
        fake_expiry = str(request_fields.get("expiry") or request_fields.get("expiry_date") or fake_response.get("expiry", "12/28"))
        fake_cvv = str(request_fields.get("cvv") or fake_response.get("cvv", "123"))
        fake_card_type = str(request_fields.get("card_type") or fake_response.get("card_type", "VISA"))

        if "/card" in endpoint or "/add_card" in endpoint:
            record_fake_card(client_ip, principal_id, fake_card_number, fake_card_holder, fake_expiry, fake_cvv, fake_card_type)

        fake_response["status"] = "success"
        fake_response["message"] = "Operation completed"
        fake_response["card_number"] = fake_card_number
        fake_response["card_holder"] = fake_card_holder
        fake_response["expiry_date"] = fake_expiry
        fake_response["cvv"] = fake_cvv
        fake_response["card_type"] = fake_card_type
    
    # 共通操作：保存欺敵狀態
    save_deception_state(
        client_ip=client_ip,
        principal_id=principal_id,
        vector=attack_vector,
        risk=risk_level,
        payload=fake_response
    )
    
    fake_response["session_token"] = fake_session_token
    fake_response["created_at"] = now_iso
    
    return (
        json.dumps(fake_response, ensure_ascii=False).encode("utf-8"),
        200,
        {
            "content-type": "application/json; charset=utf-8",
            "set-cookie": _build_mirage_cookie_header(fake_session_token),
        },
        {
            "mitigation_status": "mirage_deception",
            "response_payload": fake_response,
            "response_origin": "mirage",
            "deception_mode": "fake_session",
            "fake_session_token": fake_session_token,
        },
    )


async def _check_fake_session_and_respond(
    client_ip: str,
    principal_id: str,
    upstream_path: str,
    request: Request,
    request_at: str,
) -> tuple[bytes, int, dict[str, str], dict[str, object]] | None:
    """
    檢查請求是否來自之前被BLOCK的攻擊者（有假會話）。
    如果有，從假資料庫返回虛假數據，而不是轉發到真實後端。
    
    返回: (response_content, status_code, headers, event_meta) 或 None
    """
    from core.deception_db import (
        get_fake_session,
        get_memory,
        save_deception_state,
        get_fake_account_for_attacker,
        get_fake_transactions_for_attacker,
        get_fake_cards_for_attacker,
        record_fake_card,
        fund_fake_card,
        toggle_fake_card_freeze,
        update_fake_card_limit,
        get_fake_card_transactions,
        apply_fake_transfer,
        get_fake_bill_categories,
        get_fake_billers_by_category,
        record_fake_bill_payment,
        get_fake_bill_payments_history,
    )
    
    # 嘗試從請求中提取會話令牌
    fake_session_token = request.headers.get("X-Mirage-Session", "").strip()

    if not fake_session_token:
        fake_session_token = request.cookies.get("mirage_session", "").strip()
    
    if not fake_session_token or not fake_session_token.startswith("mirage_session_"):
        return None
    
    # 檢查這個令牌是否在假會話資料庫中
    fake_session = get_fake_session(fake_session_token)
    if not fake_session:
        return None
    session_principal_id = str(fake_session.get("principal_id") or principal_id)
    
    # 找到假會話！根據端點類型返回虛假數據
    endpoint = "/" + (upstream_path or "").lstrip("/").lower()
    now_iso = datetime.now().isoformat(timespec="milliseconds")

    # 靜態資源必須回源，否則頁面會因 CSS/JS 被 JSON 取代而破版。
    if _is_render_critical_path(endpoint):
        return None

    # 允許使用者重新進入登入/註冊流程，避免瀏覽器返回時直接顯示 Mirage JSON。
    if "/login" in endpoint or "/register" in endpoint:
        return None

    cached_memory = get_memory(client_ip, session_principal_id)
    cached_payload = (
        cached_memory.get("payload")
        if cached_memory and isinstance(cached_memory.get("payload"), dict)
        else None
    )

    fake_response: dict[str, object] = cast(
        dict[str, object],
        cached_payload if isinstance(cached_payload, dict) else {
        "status": "success",
        "response_origin": "mirage_cached",
        "user_id": session_principal_id,
        "endpoint": endpoint,
        "created_at": now_iso,
        "message": "Retrieved from deception cache",
    },
    )
    fake_response["response_origin"] = "mirage_cached"
    fake_response["endpoint"] = endpoint
    fake_response["created_at"] = now_iso
    
    # 根據端點類型返回相應的虛假數據
    if (
        "/login" in endpoint
        or "/dashboard" in endpoint
        or "/check_balance" in endpoint
        or endpoint in {"/", "/banking", "/banking/"}
    ):
        # 返回之前記錄的假帳戶信息
        fake_account = get_fake_account_for_attacker(client_ip, session_principal_id)
        if fake_account:
            account_id_text = str(fake_account.get("account_id") or "UNKNOWN")
            account_balance = _coerce_amount(fake_account.get("balance", 50000.0), fallback=50000.0)
            fake_response.update({
                "username": fake_account.get("username"),
                "account_id": account_id_text,
                "account_number": account_id_text,
                "balance": account_balance,
                "account_type": "Checking",
            })

    accept_header = (request.headers.get("accept") or "").lower()
    html_entry_paths = {"/", "/dashboard", "/banking", "/banking/"}
    if endpoint in html_entry_paths and request.method.upper() == "GET" and "text/html" in accept_header:
        html_content = _build_mirage_dashboard_html(fake_response)
        event_meta = {
            "mitigation_status": "fake_session_detected",
            "response_origin": "deception_cache_html",
            "deception_mode": "fake_session_hit",
            "fake_session_token": fake_session_token,
            "engagement_level": fake_session.get("engagement_level", 0),
        }
        save_deception_state(
            client_ip=client_ip,
            principal_id=session_principal_id,
            vector="cached_session",
            risk=0,
            payload=fake_response,
        )
        return (
            html_content.encode("utf-8"),
            200,
            {
                "content-type": "text/html; charset=utf-8",
                "set-cookie": _build_mirage_cookie_header(fake_session_token),
            },
            event_meta,
        )
    
    if "/transactions" in endpoint or "/transaction" in endpoint:
        # 返回之前記錄的假轉帳歷史
        fake_txns = get_fake_transactions_for_attacker(client_ip, session_principal_id)
        if fake_txns:
            fake_response["transactions"] = fake_txns
        else:
            fake_response["transactions"] = []

    if "/bill-categories" in endpoint:
        fake_response = {
            "status": "success",
            "categories": get_fake_bill_categories(),
        }

    if "/billers/by-category/" in endpoint:
        category_match = re.search(r"/billers/by-category/(\d+)", endpoint)
        category_id = int(category_match.group(1)) if category_match else 0
        fake_response = {
            "status": "success",
            "billers": get_fake_billers_by_category(category_id),
        }

    if "/bill-payments/create" in endpoint:
        if request.method.upper() == "POST":
            body_bytes = await request.body()
            body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
            content_type = request.headers.get("content-type", "")
            request_fields = _extract_json_or_form_fields(body_text, content_type)
            try:
                biller_id = int(request_fields.get("biller_id") or 0)
                amount = _coerce_amount(request_fields.get("amount", 0.0), fallback=0.0)
                payment_method = str(request_fields.get("payment_method") or "balance")
                card_raw = request_fields.get("card_id")
                card_id = int(card_raw) if card_raw not in (None, "") else None
                description = str(request_fields.get("description") or "Bill Payment")

                payment_result = record_fake_bill_payment(
                    client_ip=client_ip,
                    principal_id=session_principal_id,
                    biller_id=biller_id,
                    amount=amount,
                    payment_method=payment_method,
                    card_id=card_id,
                    description=description,
                )
                fake_response = {
                    "status": "success",
                    "message": "Payment processed successfully",
                    "payment_details": {
                        "reference": payment_result.get("reference"),
                        "amount": payment_result.get("amount"),
                        "payment_method": payment_result.get("payment_method"),
                        "card_id": payment_result.get("card_id"),
                        "timestamp": payment_result.get("timestamp"),
                        "processed_by": payment_result.get("processed_by"),
                    },
                    "new_balance": payment_result.get("new_balance"),
                }
            except ValueError as exc:
                fake_response = {
                    "status": "error",
                    "message": str(exc),
                }
        else:
            fake_response = {
                "status": "error",
                "message": "Method not allowed",
            }

    if "/bill-payments/history" in endpoint:
        fake_response = {
            "status": "success",
            "payments": get_fake_bill_payments_history(client_ip, session_principal_id),
        }
    
    if "/transfer" in endpoint:
        if request.method.upper() == "POST":
            body_bytes = await request.body()
            body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
            content_type = request.headers.get("content-type", "")
            request_fields = _extract_json_or_form_fields(body_text, content_type)
            to_account = str(
                request_fields.get("to_account")
                or request_fields.get("toaccount")
                or "ACC-002-FAKE"
            )
            amount = _coerce_amount(request_fields.get("amount", 0.0), fallback=0.0)
            description = str(
                request_fields.get("description")
                or request_fields.get("memo")
                or request_fields.get("note")
                or "Transfer"
            )
            currency = str(request_fields.get("currency", "USD"))
            txid = f"TXN-{fake_session_token[-8:]}-{int(time.time() * 1000) % 100000}"

            transfer_result = apply_fake_transfer(
                client_ip=client_ip,
                principal_id=session_principal_id,
                to_account=to_account,
                amount=amount,
                currency=currency,
                description=description,
                transaction_id=txid,
            )
            fake_response.update({
                "status": "success",
                "message": "Transfer completed",
                "from_account": transfer_result.get("from_account"),
                "to_account": transfer_result.get("to_account"),
                "amount": transfer_result.get("amount"),
                "description": transfer_result.get("description"),
                "currency": transfer_result.get("currency"),
                "transaction_id": transfer_result.get("transaction_id"),
                "new_balance": transfer_result.get("new_balance"),
                "balance": transfer_result.get("new_balance"),
            })
        else:
            # 返回最近的假轉帳信息
            fake_txns = get_fake_transactions_for_attacker(client_ip, session_principal_id)
            if fake_txns:
                latest_txn = fake_txns[0]
                fake_response.update({
                    "status": "completed",
                    "from_account": latest_txn.get("from_account"),
                    "to_account": latest_txn.get("to_account"),
                    "amount": latest_txn.get("amount"),
                    "currency": latest_txn.get("currency"),
                    "description": latest_txn.get("description"),
                    "transaction_id": latest_txn.get("transaction_id"),
                })
    
    if "/virtual-cards/" in endpoint and "/fund" in endpoint and request.method.upper() == "POST":
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
        content_type = request.headers.get("content-type", "")
        request_fields = _extract_json_or_form_fields(body_text, content_type)
        card_match = re.search(r"/virtual-cards/(\d+)/fund", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        fake_response = {
            "status": "success",
            "message": "Card funded successfully",
            "funding": fund_fake_card(
                client_ip,
                session_principal_id,
                card_id,
                _coerce_amount(request_fields.get("amount", 0.0), fallback=0.0),
            ),
        }

    elif "/virtual-cards/" in endpoint and "/toggle-freeze" in endpoint and request.method.upper() == "POST":
        card_match = re.search(r"/virtual-cards/(\d+)/toggle-freeze", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        frozen = toggle_fake_card_freeze(session_principal_id, card_id)
        fake_response = {
            "status": "success",
            "message": "Card frozen successfully" if frozen else "Card unfrozen successfully",
            "is_frozen": frozen,
        }

    elif "/virtual-cards/" in endpoint and "/update-limit" in endpoint and request.method.upper() == "POST":
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
        content_type = request.headers.get("content-type", "")
        request_fields = _extract_json_or_form_fields(body_text, content_type)
        card_match = re.search(r"/virtual-cards/(\d+)/update-limit", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        updated = update_fake_card_limit(
            session_principal_id,
            card_id,
            _coerce_amount(request_fields.get("card_limit", request_fields.get("limit", 0.0)), fallback=0.0),
        )
        fake_response = {
            "status": "success",
            "message": "Card updated successfully",
            "debug_info": {
                "updated_fields": ["card_limit"],
                "card_details": updated,
            },
        }

    elif "/virtual-cards/" in endpoint and "/transactions" in endpoint:
        card_match = re.search(r"/virtual-cards/(\d+)/transactions", endpoint)
        card_id = int(card_match.group(1)) if card_match else 0
        fake_response = {
            "status": "success",
            "transactions": get_fake_card_transactions(session_principal_id, card_id),
        }

    elif "/api/virtual-cards/create" in endpoint and request.method.upper() == "POST":
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
        content_type = request.headers.get("content-type", "")
        request_fields = _extract_json_or_form_fields(body_text, content_type)

        fake_account = get_fake_account_for_attacker(client_ip, session_principal_id)
        card_holder = str(
            request_fields.get("card_holder")
            or (fake_account or {}).get("username")
            or session_principal_id
        )
        card_number = str(
            request_fields.get("card_number")
            or f"4{hashlib.sha256(f'{session_principal_id}|{time.time()}'.encode('utf-8')).hexdigest()[:15]}"
        )
        expiry = str(
            request_fields.get("expiry")
            or request_fields.get("expiry_date")
            or "12/28"
        )
        cvv = str(request_fields.get("cvv") or "123")
        card_type = str(request_fields.get("card_type") or "standard")
        card_currency = str(request_fields.get("currency") or "USD").upper()
        card_limit = _coerce_amount(request_fields.get("card_limit", 1000.0), fallback=1000.0)

        record_fake_card(
            client_ip,
            session_principal_id,
            card_number,
            card_holder,
            expiry,
            cvv,
            card_type,
            currency=card_currency,
            card_limit=card_limit,
            current_balance=0.0,
            is_frozen=False,
        )

        cards = get_fake_cards_for_attacker(client_ip, session_principal_id)
        created_card = cards[0] if cards else {
            "id": None,
            "card_number": card_number,
            "cvv": cvv,
            "expiry_date": expiry,
            "limit": card_limit,
            "balance": 0.0,
            "card_type": card_type,
            "currency": card_currency,
            "currency_symbol": "$",
        }

        fake_response = {
            "status": "success",
            "message": "Virtual card created successfully",
            "card_details": {
                "id": created_card.get("id"),
                "card_number": created_card.get("card_number"),
                "cvv": created_card.get("cvv"),
                "expiry_date": created_card.get("expiry_date") or created_card.get("expiry"),
                "limit": created_card.get("limit", card_limit),
                "balance": created_card.get("balance", 0.0),
                "type": created_card.get("card_type", card_type),
                "currency": created_card.get("currency", card_currency),
                "currency_symbol": created_card.get("currency_symbol", "$"),
            },
        }

    elif endpoint.endswith("/api/virtual-cards"):
        fake_response = {
            "status": "success",
            "cards": get_fake_cards_for_attacker(client_ip, session_principal_id),
        }

    elif "/card" in endpoint or "/cards" in endpoint or "virtual_cards" in endpoint:
        if request.method.upper() == "POST":
            body_bytes = await request.body()
            body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
            content_type = request.headers.get("content-type", "")
            request_fields = _extract_json_or_form_fields(body_text, content_type)

            fake_account = get_fake_account_for_attacker(client_ip, session_principal_id)
            card_holder = str(
                request_fields.get("card_holder")
                or (fake_account or {}).get("username")
                or session_principal_id
            )
            card_number = str(
                request_fields.get("card_number")
                or f"4{hashlib.sha256(f'{session_principal_id}|{time.time()}'.encode('utf-8')).hexdigest()[:15]}"
            )
            expiry = str(
                request_fields.get("expiry")
                or request_fields.get("expiry_date")
                or "12/28"
            )
            cvv = str(request_fields.get("cvv") or "123")
            card_type = str(request_fields.get("card_type") or "standard")

            record_fake_card(
                client_ip,
                session_principal_id,
                card_number,
                card_holder,
                expiry,
                cvv,
                card_type,
            )

            fake_response.update({
                "status": "success",
                "message": "Virtual card created successfully",
                "card_details": {
                    "card_number": card_number,
                    "cvv": cvv,
                    "expiry_date": expiry,
                    "card_type": card_type,
                },
            })

        # 返回虛假卡片列表
        fake_cards = get_fake_cards_for_attacker(client_ip, session_principal_id)
        if fake_cards:
            fake_response["cards"] = fake_cards
        else:
            fake_response["cards"] = []
    
    logger.info(
        "[FAKE SESSION HIT] %s:%s - endpoint=%s - returning cached deception data",
        client_ip,
        principal_id,
        endpoint
    )
    
    # 記錄這個假會話請求
    event_meta = {
        "mitigation_status": "fake_session_detected",
        "response_origin": "deception_cache",
        "deception_mode": "fake_session_hit",
        "fake_session_token": fake_session_token,
        "engagement_level": fake_session.get("engagement_level", 0),
    }

    # 命中假會話也要回寫欺敵狀態，累積互動深度與命中次數。
    save_deception_state(
        client_ip=client_ip,
        principal_id=session_principal_id,
        vector="cached_session",
        risk=0,
        payload=fake_response,
    )
    
    return (
        json.dumps(fake_response, ensure_ascii=False).encode("utf-8"),
        200,
        {
            "content-type": "application/json; charset=utf-8",
            "set-cookie": _build_mirage_cookie_header(fake_session_token),
        },
        event_meta,
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
    principal_id = _derive_principal_id(
        upstream_path=upstream_path,
        body_text=body_text,
        content_type=content_type,
        request=request,
        client_ip=client_ip,
    )
    session_chain_id = _derive_session_chain_id(
        client_ip=client_ip,
        principal_id=principal_id,
        device_id=device_id,
        request_epoch_ms=request_epoch_ms,
    )
    should_clear_mirage_cookie = False
    
    # 【第一層檢測】檢查是否來自已建立的假會話
    fake_session_response = await _check_fake_session_and_respond(
        client_ip=client_ip,
        principal_id=principal_id,
        upstream_path=upstream_path,
        request=request,
        request_at=request_at,
    )
    if fake_session_response:
        # 命中假會話！直接返回虛假數據，不再進行後續檢測
        response_content, status_code, response_headers, event_meta = fake_session_response
        response_payload = bytes(response_content)
        end_perf = time.perf_counter()
        process_ms = round((end_perf - start_perf) * 1000, 3)
        
        logger.info(f"[FAKE SESSION] 命中假會話記錄，直接返回虛假數據: {client_ip}:{principal_id}")
        
        response = Response(response_payload, status_code=status_code, headers=response_headers)
        
        # 可選：記錄到流量日誌
        if background_tasks:
            background_tasks.add_task(
                lambda: logger.info(f"[FAKE SESSION LOG] {client_ip}:{principal_id} - {upstream_path} - {status_code}")
            )
        
        return response
    
    # 【第二層檢測】正常 Sentinel 檢測流程
    normalized_upstream_path = "/" + upstream_path.lstrip("/")
    render_critical_path = _is_render_critical_path(normalized_upstream_path)
    business_context, banking_action = _classify_banking_surface(upstream_path)
    login_credentials_text = _extract_login_credentials_text(
        upstream_path=upstream_path,
        query_text=query_text,
        body_text=body_text,
        content_type=content_type,
    )
    transfer_details_text = _extract_transfer_details_text(
        upstream_path=upstream_path,
        query_text=query_text,
        body_text=body_text,
        content_type=content_type,
    )
    loan_details_text = _extract_loan_details_text(
        upstream_path=upstream_path,
        query_text=query_text,
        body_text=body_text,
        content_type=content_type,
    )
    raw_payload_text = body_text
    payload_fragments = [
        fragment
        for fragment in [
            login_credentials_text,
            transfer_details_text,
            loan_details_text,
        ]
        if fragment
    ]
    if payload_fragments:
        raw_payload_text = (f"{body_text}\n" if body_text else "") + "\n".join(
            payload_fragments
        )
    detection_target = _build_values_only_detection_target(
        query_text=query_text,
        body_text=body_text,
        content_type=content_type,
    )
    if not detection_target:
        detection_target = " ".join(filter(None, [query_text, body_text])).strip()

    # 先預設為 None，稍後根據是否攻擊流量決定來源
    req_interval_ms = None
    req_time_var = None
    amount_value = _extract_amount_value(body_text, None)
    amount_deviation = None

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

    # 判斷攻擊流量前，先預設為安全值
    import random

    req_interval_ms = 0.0
    req_time_var = 0.0
    amount_deviation = 0.0

    attack_vector = _normalize_attack_vector(attack_vector)
    model_attack_type = attack_vector
    ml_intercept = is_attack and sentinel_decision == "BLOCK"
    should_intercept = ml_intercept and not render_critical_path
    effective_risk_reasons: list[str] = []
    decision_source = _decision_source(is_attack, effective_risk_reasons)
    risk_level = int(confidence * 100)
    flow_stage, deception_score, trust_level, memory_hit = (
        _compute_deception_effectiveness(
            should_intercept=should_intercept,
            risk_level=risk_level,
            confidence=confidence,
            risk_reasons_count=len(effective_risk_reasons),
        )
    )

    # 決定是否查詢真實資料庫
    if not should_intercept:
        req_interval_ms, req_time_var = _compute_timing_features(principal_id)
        amount_deviation = _compute_amount_deviation(principal_id, amount_value)
    else:
        # Mirage 分流時，這些欄位給隨機或預設安全值
        req_interval_ms = round(random.uniform(100, 1000), 3)
        req_time_var = round(random.uniform(0, 10000), 3)
        amount_deviation = round(random.uniform(0.8, 1.2), 3)

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
        "input_string": raw_payload_text,  # 戰情室明確顯示的輸入字串
        "principal_id": principal_id,
        "session_chain_id": session_chain_id,
        "principal_id": principal_id,
        "method": request.method,  # 請求方法
        "endpoint": f"/{upstream_path.lstrip('/')}",  # 完整目標路徑
        "query_string": query_text,  # 查詢參數原文
        "authorization": authorization,  # 身分驗證憑證原文
        "content_type": content_type,  # 內容類型宣告
        "content_length": content_length,  # 內容長度宣告
        "header_count": header_count,  # 標頭總數量
        "all_headers": headers_dict,  # 所有 header（for 鑑識/除錯，可選）
        "referer": referer,
        "business_context": business_context,
        "banking_action": banking_action,
        "banking_details": (
            loan_details_text or transfer_details_text or login_credentials_text or None
        ),
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
            upstream_path=upstream_path,
            request_method=request.method,
            body_text=body_text,
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
        event_payload["upstream_attempted"] = 1
        try:
            upstream_response = None
            last_exc: Exception | None = None
            for base_url in _get_vuln_bank_base_url_candidates():
                upstream_url = f"{base_url}/{upstream_path.lstrip('/')}"
                if query_text:
                    upstream_url = f"{upstream_url}?{query_text}"
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
                    break
                except httpx.RequestError as exc:
                    last_exc = exc
                    logger.warning("Upstream connect failed (%s): %s", base_url, exc)
                    continue

            if upstream_response is None:
                raise last_exc or RuntimeError("No upstream response from vuln-bank")

            status_code = upstream_response.status_code
            response_content = _inject_mouse_tracker_html(
                upstream_response.content,
                upstream_response.headers.get("content-type"),
            )
            upstream_content_type = upstream_response.headers.get("content-type", "")
            if "application/json" in upstream_content_type.lower():
                try:
                    parsed_upstream_payload = json.loads(
                        upstream_response.content.decode("utf-8", errors="ignore")
                    )
                except Exception:
                    parsed_upstream_payload = upstream_response.content.decode(
                        "utf-8", errors="ignore"
                    )
                event_payload["response_payload"] = parsed_upstream_payload

            if business_context == "banking:transfers":
                transfer_details_map = dict(
                    parse_qsl(transfer_details_text, keep_blank_values=True)
                )
                event_payload["response_payload"] = {
                    "transaction": {
                        "amount": amount_value,
                        "to_account": transfer_details_map.get("to_account")
                        or transfer_details_map.get("toaccount"),
                        "from_account": transfer_details_map.get("from_account")
                        or transfer_details_map.get("fromaccount"),
                        "currency": transfer_details_map.get("currency"),
                        "note": transfer_details_map.get("note")
                        or transfer_details_map.get("memo"),
                        "business_context": business_context,
                    },
                    "upstream_response": event_payload.get("response_payload"),
                }
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

            # 正常登入流程（未被 Mirage 攔截）要清除舊的 mirage_session，
            # 避免同一瀏覽器因殘留 cookie 被誤導回欺敵資料庫。
            should_clear_mirage_cookie = normalized_upstream_path in {"/login", "/banking/login"}

            event_payload["upstream_status_code"] = status_code
            event_payload["real_backend_touched"] = 1
            event_payload["response_origin"] = "vuln_bank_main"
            event_payload["flow_stage"] = "upstream"
        except Exception as exc:
            logger.error("banking proxy upstream failed: %s", exc)
            response_content = b'{"status":"error","message":"upstream unavailable","detail":"upstream unavailable"}'
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

    response = Response(
        content=response_content,
        status_code=status_code,
        headers=response_headers,
    )

    if not should_intercept and 'should_clear_mirage_cookie' in locals() and should_clear_mirage_cookie:
        response.headers.append(
            "set-cookie",
            "mirage_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        )

    return response


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
