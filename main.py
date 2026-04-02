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

from fastapi import FastAPI, Request, Query, BackgroundTasks, Security, HTTPException
import sys
import uvicorn
import time
import os
import logging
import pandas as pd
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv
from typing import Optional
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
from core.api_mirage import get_raw_ai_fake_data
import model.ai_sentinel as model
sys.modules['__main__'].SentinelModule = model.SentinelModule
sys.modules['__main__'].SecurityExtractor = model.SecurityExtractor
# ===== Dashboard API 路由與跨域設定 =====
from api import dashboard
from fastapi.middleware.cors import CORSMiddleware
# 載入 .env（讓 API_KEY / SANDBOX_API_URL 等配置可由環境管理）
load_dotenv()

# ===== API Key 設定 =====
# 若未設定 API_KEY，lifespan 會切到開發預設值並記錄 warning。
API_KEY = os.getenv("API_KEY", "").strip()
DEFAULT_DEV_API_KEY = "dev-local-api-key-change-me"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
ai_sentinel = model.load_sentinel_model()

def verify_api_key(api_key: str = Security(api_key_header)):
    """統一使用 dashboard_service 中的 API key 驗證邏輯。"""
    from services import dashboard_service as ws
    if not api_key or not ws.validate_api_key(api_key):
        raise HTTPException(status_code=403, detail="Unauthorized access")


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
        df_input = pd.DataFrame({
            "payload": [str(text).lower().strip()]
        })
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
    logger.info("Mirage-Sentinel 全時哨兵監控模式已啟動。")
    yield


# ===== FastAPI App 建立 =====
app = FastAPI(
    title="Mirage-Sentinel API Gateway",
    version="1.6-FullSentinel",
    lifespan=lifespan
)

# 掛載前端專用 API（由 router 內部處理 API Key 驗證）
app.include_router(
    dashboard.router,
    prefix="/api/v1",
    tags=["Dashboard"]
)

# CORS：目前開發期全面放行，正式環境可改為白名單。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """服務根節點：提供健康入口與文件連結。"""
    return {
        "service": "Mirage-Sentinel API Gateway",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "dashboard_base": "/api/v1/dashboard",
    }


@app.get("/healthz")
async def healthz():
    """容器/平台健康檢查端點。"""
    return {"status": "ok"}

@app.get("/api/v1/ai_fakedata", summary="AI 強化欺敵回應測試項")
async def api_generate_ai_fakedata(
    user_id: str = Query(..., description="用戶 ID"),
    payload: str = Query("", description="模擬的攻擊指令"),
    client_ip: str = Query("192.168.0.1", description="攻擊者 IP（可選）"),
    attack_vector: str = Query("General", description="預期攻擊類型"),
):
    """
    輸入參數與 simulate_attack 保持一致。
    邏輯：讀取記憶 -> (若無)AI生成 -> (若失敗)本地生成 -> 存入記憶。
    """
    # 呼叫整合過的 AI 引擎
    fake_content_str = await get_raw_ai_fake_data(
        attack_vector=attack_vector,
        payload=payload,
        client_ip=client_ip,
        query_id=user_id
    )
    
    # 解析回傳結果以便 FastAPI 渲染 JSON
    import json
    return {
        "status": "success",
        "simulated_context": {
            "client_ip": client_ip,
            "target_user": user_id,
            "vector": attack_vector
        },
        "response_data": json.loads(fake_content_str)
    }

@app.get("/api/v1/ai_sentinel", tags=["Sentinel Debug"])
async def scan_payload_debug(
    text: str = Query(..., description="要測試的 Payload 或字串"),
    method: str = Query("GET", description="HTTP 方法")
):
    """
    【AI 哨兵直連評估】
    直接使用根目錄載入的 Sentinel V14 模型進行數據驅動判斷。
    """
    start_perf = time.perf_counter()

    if not ai_sentinel:
        return {"status": "error", "msg": "模型尚未載入，請檢查根目錄 pkl 檔案"}

    # 1. 準備輸入數據 (轉小寫以確保特徵命中)
    df_input = pd.DataFrame({
        'payload': [text.lower().strip()]
    })

    try:
        judgment = ai_sentinel.predict(df_input).iloc[0]

        # 2. 獲取運算耗時
        process_ms = round((time.perf_counter() - start_perf) * 1000, 2)
        
        # 3. 取得模型輸出數據
        confidence_val = float(judgment['attack_score'])
        top_prob = float(judgment['top_attack_prob'])
        attack_vector = judgment['top_attack_type']
        decision = judgment['decision']

        return {
            "status": "success",
            "performance": {
                "process_ms": process_ms,
                "engine_version": "XGBoost-Sentinel-V14-Local"
            },
            "input": {
                "text": text,
                "method": method.upper()
            },
            "ai_analysis": {
                "is_attack": confidence_val > 0.3,
                "confidence": f"{confidence_val*100:.2f}%",
                "attack_vector": attack_vector,
                "top_category_prob": f"{top_prob*100:.2f}%",
                "risk_score": int(confidence_val * 100)
            },
            "gateway_decision": {
                "decision": decision,
                "applied_thresholds": {
                    "block_limit": 0.75,
                    "review_limit": 0.3
                }
            },
            "advice": "此接口直接呼叫本機模型權重，不經由外部模組轉手。"
        }
    except Exception as e:
        return {"status": "error", "message": f"模型預測失敗: {str(e)}"}

@app.get("/api/v1/user/{user_id}")
async def get_user_data(
    user_id: str,
    payload: str = Query(None, max_length=2000, description="指令測試區 (最多 2000 字)"),
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
    detection_target = f"{user_id} {current_payload}".strip() if current_payload else str(user_id)

    # 哨兵引擎：回傳 (是否命中, 信心分數, 攻擊向量)
    is_attack, confidence, attack_vector = analyze_intent(detection_target)
    logger.debug(f"請求：{detection_target} | 信心度：{confidence} | 命中：{attack_vector}")

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
        "location": "Cloud/Render",
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
            fake_data = await run_attack_in_sandbox({
                **event_payload,
                "response_at": response_at,
                "process_ms": process_ms,
                "hits": hits,
                "interaction_depth": interaction_depth,
                "dwell_time": dwell_time,
            })

        # 回填完整事件，供後續落地與 API 回傳
        event_payload.update({
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": fake_data,
            "hits": hits,
            "interaction_depth": interaction_depth,
            "dwell_time": dwell_time,
            "mitigation_status": "Sandboxed",
            "risk_level": risk_score,
        })

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


# 攻擊模擬端點：功能與 /user 類似，但來源資訊固定為測試情境
@app.post("/api/v1/simulate_attack", summary="模擬攻擊請求")
async def simulate_attack(
    user_id: str = Query(..., description="用戶 ID"),
    payload: str = Query("", description="""模擬的攻擊指令（選填，留空為正常請求）

常見攻擊模板：
  • SQL 注入: ' OR '1'='1 / DROP TABLE users / UNION SELECT * FROM admin
  • LFI: ../../../../etc/passwd / ../../config.php / /etc/shadow
  • XSS: <script>alert('xss')</script> / javascript:alert(1)
  • RCE: ; ls -la / $(whoami) / `id`
  • 目錄遍歷: ../../../ / ..\\..\\..\\
    """),
    client_ip: str = Query("192.168.0.1", description="攻擊者 IP（可選）"),
    background_tasks: BackgroundTasks = None
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

        event_payload.update({
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": fake_data,
            "mitigation_status": "Sandboxed",
            "hits": hits,
            "interaction_depth": interaction_depth,
            "dwell_time": dwell_time,
            "risk_level": risk_score,
        })

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
        "event_log": event_payload
    }


def detect_proxy(request: Request) -> int:
    """
    代理檢測（簡化版）：
    1) 先看常見代理標頭。
    2) 再看 IP 是否命中已知代理池（目前為占位邏輯）。
    3) 最後看 User-Agent 是否帶 proxy/crawler 關鍵字。
    """
    proxy_headers = [
        "X-Forwarded-For", "Via", "Forwarded", "Client-IP", "True-Client-IP"
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