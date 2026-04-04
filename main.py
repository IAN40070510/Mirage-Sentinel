"""
Mirage-Sentinel 主入口（API Gateway）

本檔案負責：
1. 啟動 FastAPI 與 middleware。
2. 初始化雙資料庫（traffic + deception memory）。
3. 提供主要對外 API：
   - /api/v1/user/{user_id}：實際流量入口
   - /api/v1/simulate_attack：攻擊模擬入口
4. 協調哨兵偵測、欺敵策略、沙盒回應與日誌落地。
"""

from fastapi import (
    FastAPI,
    Request,
    Query,
    BackgroundTasks,
    HTTPException,
    Depends,
    Header,
)
from fastapi.openapi.utils import get_openapi
import sys
import uvicorn
import time
import os
import logging
import ipaddress
import pandas as pd
from datetime import datetime
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# 配置日誌（實際輸出格式與 handler 由啟動環境決定）
logger = logging.getLogger(__name__)

# ===== 核心模組匯入 =====
# sentinel：攻擊意圖偵測（目前改為本機 AI 模型主判斷）
# deception_db：欺敵記憶讀寫（同 IP + query_id 的持續欺敵）
# deception_engine：互動深度/漏斗層級評分
# traffic_db：全量流量事件落地
# sandbox：惡意流量導向沙盒/降級假資料
from core.deception_db import setup_deception_db, get_memory, save_deception_state
from core.deception_engine import compute_interaction_metrics
from core.traffic_db import setup_traffic_db, log_traffic_event
from core.sandbox import run_attack_in_sandbox
from api import dashboard
from api import banking
from api.db.session import init_db, create_tables
import model.ai_sentinel as model

sys.modules["__main__"].SentinelModule = model.SentinelModule
sys.modules["__main__"].SecurityExtractor = model.SecurityExtractor
from fastapi.middleware.cors import CORSMiddleware

# 載入 .env（讓 API_KEY / SANDBOX_API_URL 等配置可由環境管理）
load_dotenv()

# ===== API Key 設定 =====
# 若未設定 API_KEY，lifespan 會切到開發預設值並記錄 warning。
API_KEY = os.getenv("API_KEY", "").strip()
DEFAULT_DEV_API_KEY = "dev-local-api-key-change-me"
ai_sentinel = model.load_sentinel_model()


def _env_flag(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


ENABLE_DASHBOARD = _env_flag("ENABLE_DASHBOARD", "false")
ENABLE_BANKING_API = _env_flag("ENABLE_BANKING_API", "true")
DASHBOARD_INTERNAL_ONLY = _env_flag("DASHBOARD_INTERNAL_ONLY", "true")
DASHBOARD_ADMIN_KEY = os.getenv("DASHBOARD_ADMIN_KEY", "").strip()


def _is_private_or_loopback_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        return ip_obj.is_private or ip_obj.is_loopback
    except Exception:
        return False


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
    回傳: (is_attack, confidence, attack_vector)
    """
    if not text or not str(text).strip():
        return False, 0.0, "None"

    if not ai_sentinel:
        logger.warning("AI Sentinel 未載入，降級為非攻擊判定。")
        return False, 0.0, "None"

    try:
        df_input = pd.DataFrame({"payload": [str(text).lower().strip()]})
        judgment = ai_sentinel.predict(df_input).iloc[0]

        confidence = float(judgment["attack_score"])
        attack_vector = str(judgment["top_attack_type"])
        is_attack = confidence > 0.3

        return is_attack, confidence, attack_vector
    except Exception as exc:
        logger.error(f"AI Sentinel 判斷失敗: {exc}")
        return False, 0.0, "None"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    應用生命週期：
    1) 補齊 API_KEY（開發模式 fallback）。
    2) 初始化 deception / traffic 雙資料庫。
    3) 啟動完成後交由 FastAPI 正常提供服務。
    """
    global API_KEY
    if not API_KEY:
        API_KEY = DEFAULT_DEV_API_KEY
        logger.warning("API_KEY 未設定，使用開發預設值。正式環境請務必設定 API_KEY。")

    setup_deception_db()
    setup_traffic_db()

    # Initialize PostgreSQL database if DATABASE_URL is set
    if init_db():
        create_tables()
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

if ENABLE_BANKING_API:
    app.include_router(
        banking.router,
        prefix="/api/v1",
        tags=["Banking"],
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
def custom_openapi():
    """
    生成 OpenAPI schema，當 ENABLE_DASHBOARD=false 時，隱藏 Dashboard 路由。
    符合 AGENTS.md 安全規範：公開蜜罐不應暴露敏感監控功能。
    """
    # 每次都重新生成，不使用緩存，確保 ENABLE_DASHBOARD 值被正確應用
    output = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.tags,
        servers=app.servers,
    )

    # 當 Dashboard 禁用時，移除所有 Dashboard 路由的文檔
    if not ENABLE_DASHBOARD and output.get("paths"):
        paths_to_remove = [
            path
            for path in output["paths"].keys()
            if path.startswith("/api/v1/dashboard/")
        ]
        for path in paths_to_remove:
            del output["paths"][path]

        # 移除 Dashboard tag
        if output.get("tags"):
            output["tags"] = [
                tag for tag in output["tags"] if tag.get("name") != "Dashboard"
            ]

    app.openapi_schema = output
    return app.openapi_schema


app.openapi = custom_openapi


@app.get("/")
async def root():
    """服務根節點：提供健康入口與文件連結。"""
    return {
        "service": "Mirage-Sentinel API Gateway",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "main_entry": "/api/v1/user/{user_id}",
        "simulate_entry": "/api/v1/simulate_attack",
        "dashboard_enabled": ENABLE_DASHBOARD,
        "dashboard_internal_only": DASHBOARD_INTERNAL_ONLY,
        "banking_enabled": ENABLE_BANKING_API,
    }


@app.get("/healthz")
async def healthz():
    """容器/平台健康檢查端點。"""
    return {"status": "ok"}

@app.get("/api/v1/user/llama/{user_id}")
async def get_user_data_llama(
    user_id: str,
    payload: str = Query(None, max_length=2000, description="指令測試區 (最多 2000 字)"),
    request: Request = None,
    background_tasks: BackgroundTasks = None,
):
    """
    LLaMA 專屬入口：直接由本地 LLaMA 3.1 8B 模型生成完整的假資料。
    不再依賴外部 Docker Sandbox，解決連線超時與依賴問題。
    """
    if request is None:
        raise HTTPException(status_code=400, detail="Request context is required")

    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")

    current_payload = payload if payload else ""
    detection_target = f"{user_id} {current_payload}".strip() if current_payload else str(user_id)

    # 1. 意圖分析 (本機 AI 哨兵檢測)
    is_attack, confidence, attack_vector = analyze_intent(detection_target)
    should_intercept = is_attack and confidence > 0.75

    process_ms = None
    response_at = None
    event_payload = {
        "request_at": request_at,
        "client_ip": client_ip,
        "location": "Cloud/LLaMA",
        "is_proxy": detect_proxy(request),
        "user_agent": user_agent,
        "tls_fingerprint": "N/A",
        "raw_payload": detection_target,
        "query_id": user_id,
        "attack_vector": attack_vector if is_attack else None,
        "risk_level": int(confidence * 100) if is_attack else 0,
        "is_attack": 1 if should_intercept else 0,
    }

    if should_intercept:
        # ==========================================
        # 惡意請求攔截：啟動欺敵與記憶機制
        # ==========================================
        risk_score = int(confidence * 100)

        # 查欺敵記憶
        mem = get_memory(client_ip, user_id)

        # 計算互動深度指標
        metrics = compute_interaction_metrics(
            client_ip=client_ip,
            query_id=user_id,
            current_payload=detection_target,
            has_memory_hit=bool(mem),
        )

        dwell_time = float(metrics["dwell_seconds"])
        interaction_depth = int(metrics["depth_score"])
        hits = 1

        if mem:
            # 記憶命中：沿用舊假資料，維持欺敵一致性
            hits = mem["hits"] + 1
            fake_data = mem["payload"]
            logger.info(f"[欺敵記憶命中] 攻擊者 {client_ip} 繼續餵給 LLaMA 舊資料")
        else:
            # 無記憶：直接呼叫 LLaMA 生成全新且完整的假資料
            fake_data = generate_fake_data_llama(query_id=user_id, attack_vector=attack_vector)

        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        event_payload.update({
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": fake_data,
            "hits": hits,
            "interaction_depth": interaction_depth,
            "dwell_time": dwell_time,
            "mitigation_status": "LLaMA_Generated",  # 狀態標記為 LLaMA 直出
            "risk_level": risk_score,
        })

        # 紀錄流量 (背景或同步)
        if background_tasks:
            background_tasks.add_task(log_traffic_event, event_payload)
        else:
            log_traffic_event(event_payload)

        # 寫入記憶體，供下次攔截時使用
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)

        logger.info(
            f"[LLaMA] 哨兵攔截成功：{attack_vector} (信心: {confidence}) | "
            f"深度: {interaction_depth} | 漏斗: {metrics['funnel_level']}"
        )
        return fake_data

    # ==========================================
    # 正常請求：放行
    # ==========================================
    process_ms = int((time.perf_counter() - start_perf) * 1000)
    response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    event_payload.update({
        "response_at": response_at,
        "process_ms": process_ms,
        "response_payload": None,
        "hits": 0,
        "interaction_depth": 0,
        "dwell_time": 0.0,
        "mitigation_status": "normal",
        "risk_level": 0,
    })

    if background_tasks:
        background_tasks.add_task(log_traffic_event, event_payload)
    else:
        log_traffic_event(event_payload)

    return {"user_id": user_id, "name": "真實用戶", "status": "Normal"}

@app.get("/api/v1/user/{user_id}")
async def get_user_data(
    user_id: str,
    payload: str = Query(
        None, max_length=2000, description="指令測試區 (最多 2000 字)"
    ),
    request: Request = None,
    background_tasks: BackgroundTasks = None,
):
    """
    真實入口：
    1) 分析請求是否惡意。
    2) 惡意則回傳欺敵資料；正常則回傳真實資料。
    3) 不論惡意與否，皆落地 traffic 事件（可同步或背景）。
    """
    if request is None:
        raise HTTPException(status_code=400, detail="Request context is required")

    # 入口起始時間（毫秒）與基礎請求資訊
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")

    # 將 user_id 與 payload 合併成一個偵測字串，提升命中率
    current_payload = payload if payload else ""
    detection_target = (
        f"{user_id} {current_payload}".strip() if current_payload else str(user_id)
    )

    # 哨兵引擎：回傳 (是否命中, 信心分數, 攻擊向量)
    is_attack, confidence, attack_vector = analyze_intent(detection_target)
    logger.debug(
        f"請求：{detection_target} | 信心度：{confidence} | 命中：{attack_vector}"
    )

    # 只有超過閾值才進入攔截路徑，避免過度誤判
    should_intercept = is_attack and confidence > 0.75

    # event_payload 是跨模組共享資料：
    # - 送給 sandbox（必要欄位）
    # - 寫入 traffic_db（稽核資料）
    process_ms = None
    response_at = None
    event_payload = {
        "request_at": request_at,
        "client_ip": client_ip,
        "location": "Cloud",
        "is_proxy": detect_proxy(request),
        "user_agent": user_agent,
        "tls_fingerprint": "N/A",
        "raw_payload": detection_target,
        "query_id": user_id,
        "attack_vector": attack_vector if is_attack else None,
        "risk_level": int(confidence * 100) if is_attack else 0,
        "is_attack": 1 if should_intercept else 0,
    }

    if should_intercept:
        # ===== 惡意請求路徑 =====
        risk_score = int(confidence * 100)

        # 先查記憶：同一攻擊者可維持一致假資料，避免露餡
        mem = get_memory(client_ip, user_id)

        # 計算互動指標（停留時間、漏斗層級、演化分數等）
        metrics = compute_interaction_metrics(
            client_ip=client_ip,
            query_id=user_id,
            current_payload=detection_target,
            has_memory_hit=bool(mem),
        )

        dwell_time = float(metrics["dwell_seconds"])
        interaction_depth = int(metrics["depth_score"])
        hits = 1

        if mem:
            # 已有記憶：沿用舊假資料，提升欺敵連續性
            hits = mem["hits"] + 1
            fake_data = mem["payload"]
        else:
            # 無記憶：稍後進沙盒（或降級本機假資料）生成
            fake_data = None

        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # 第一次命中才呼叫沙盒；避免重複生成不同假資料
        if fake_data is None:
            fake_data = await run_attack_in_sandbox(
                {
                    **event_payload,
                    "response_at": response_at,
                    "process_ms": process_ms,
                    "hits": hits,
                    "interaction_depth": interaction_depth,
                    "dwell_time": dwell_time,
                }
            )

        # 回填完整事件，供後續落地與 API 回傳
        event_payload.update(
            {
                "response_at": response_at,
                "process_ms": process_ms,
                "response_payload": fake_data,
                "hits": hits,
                "interaction_depth": interaction_depth,
                "dwell_time": dwell_time,
                "mitigation_status": "Sandboxed",
                "risk_level": risk_score,
            }
        )

        # 流量寫入可異步（避免延遲主請求）或同步（保持即時一致）
        if background_tasks:
            background_tasks.add_task(log_traffic_event, event_payload)
        else:
            log_traffic_event(event_payload)

        # 寫入欺敵記憶，供下一次相同攻擊者沿用
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)

        logger.info(
            f"哨兵攔截：{attack_vector} (信心: {confidence}) | "
            f"深度分數: {interaction_depth} | 漏斗層級: {metrics['funnel_level']} | 隔離: Docker沙盒"
        )
        return fake_data

    # ===== 正常請求路徑 =====
    process_ms = int((time.perf_counter() - start_perf) * 1000)
    response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    event_payload.update(
        {
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": None,
            "hits": 0,
            "interaction_depth": 0,
            "dwell_time": 0.0,
            "mitigation_status": "normal",
            "risk_level": 0,
        }
    )

    if background_tasks:
        background_tasks.add_task(log_traffic_event, event_payload)
    else:
        log_traffic_event(event_payload)

    return {"user_id": user_id, "name": "真實用戶", "status": "Normal"}


# 攻擊模擬端點：功能與 /user 類似，但來源資訊固定為測試情境
@app.post("/api/v1/simulate_attack", summary="模擬攻擊請求")
async def simulate_attack(
    user_id: str = Query(..., description="用戶 ID"),
    payload: str = Query(
        "",
        description="""模擬的攻擊指令（選填，留空為正常請求）

常見攻擊模板：
  • SQL 注入: ' OR '1'='1 / DROP TABLE users / UNION SELECT * FROM admin
  • LFI: ../../../../etc/passwd / ../../config.php / /etc/shadow
  • XSS: <script>alert('xss')</script> / javascript:alert(1)
  • RCE: ; ls -la / $(whoami) / `id`
  • 目錄遍歷: ../../../ / ..\\..\\..\\
    """,
    ),
    client_ip: str = Query("192.168.0.1", description="攻擊者 IP（可選）"),
    background_tasks: BackgroundTasks = None,
):
    """
    模擬攻擊專用：方便在測試環境快速重現攻擊流程。
    - 可透過 client_ip 模擬同一/不同攻擊者的記憶命中行為。
    """
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    user_agent = "Simulated-Attack-Client"

    detection_target = f"{user_id} {payload}".strip()

    # 偵測攻擊意圖
    is_attack, confidence, attack_vector = analyze_intent(detection_target)
    should_intercept = is_attack and confidence > 0.75

    event_payload = {
        "request_at": request_at,
        "client_ip": client_ip,
        "location": "Simulated",
        "is_proxy": 0,
        "user_agent": user_agent,
        "tls_fingerprint": "N/A",
        "raw_payload": detection_target,
        "query_id": user_id,
        "attack_vector": attack_vector if is_attack else None,
        "risk_level": int(confidence * 100) if is_attack else 0,
        "is_attack": 1 if should_intercept else 0,
    }

    if should_intercept:
        risk_score = int(confidence * 100)
        mem = get_memory(client_ip, user_id)

        metrics = compute_interaction_metrics(
            client_ip=client_ip,
            query_id=user_id,
            current_payload=detection_target,
            has_memory_hit=bool(mem),
        )

        # 四維度指標：停留時間、深度分數、命中次數
        dwell_time = float(metrics["dwell_seconds"])
        interaction_depth = int(metrics["depth_score"])
        hits = 1
        if mem:
            hits = mem["hits"] + 1
            fake_data = mem["payload"]
        else:
            fake_data = await run_attack_in_sandbox(event_payload)

        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        event_payload.update(
            {
                "response_at": response_at,
                "process_ms": process_ms,
                "response_payload": fake_data,
                "mitigation_status": "Sandboxed",
                "hits": hits,
                "interaction_depth": interaction_depth,
                "dwell_time": dwell_time,
                "risk_level": risk_score,
            }
        )

        if background_tasks:
            background_tasks.add_task(log_traffic_event, event_payload)
        else:
            log_traffic_event(event_payload)

        # 保存欺騙狀態到記憶庫，回傳最新快照供檢視
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)
        latest_memory = get_memory(client_ip, user_id)

        return {
            "status": "attack_detected",
            "fake_data": fake_data,
            "event_log": event_payload,
            "mirage_memory": latest_memory,
            "deception_memory": {
                "dwell_time": dwell_time,
                "interaction_depth": interaction_depth,
                "hits": hits,
                "funnel_level": metrics["funnel_level"],
                "endpoint_coverage": metrics["endpoint_coverage"],
                "payload_evolution_score": metrics["payload_evolution_score"],
            },
        }

    return {
        "status": "normal_request",
        "message": "未檢測到攻擊行為",
        "event_log": event_payload,
    }


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

    client_ip = request.client.host
    if is_known_proxy_ip(client_ip):
        return 1

    user_agent = request.headers.get("user-agent", "").lower()
    if "proxy" in user_agent or "crawler" in user_agent:
        return 1

    return 0


def is_known_proxy_ip(ip: str) -> bool:
    """已知代理 IP 檢測占位函式（後續可接外部黑名單/資料源）。"""
    return False


if __name__ == "__main__":
    # 生產環境通常交給 process manager / container 指令啟動。
    # 這裡保留本機開發入口，方便直接 python main.py。
    uvicorn.run("main:app", host="127.0.0.1", port=8000)
