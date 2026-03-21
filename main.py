from fastapi import FastAPI, Request
import uvicorn
import time
import json
from datetime import datetime
from contextlib import asynccontextmanager

# 匯入核心偵測與幻象引擎
from core.sentinel import analyze_intent
from core.mirage import generate_fake_data

# 匯入雙核心資料庫
from core.deception_db import setup_deception_db, get_memory, save_deception_state
from core.traffic_db import setup_traffic_db, log_attack_event

@asynccontextmanager
async def lifespan(app: FastAPI):
    """伺服器啟動時，初始化雙軌資料庫"""
    setup_deception_db()
    setup_traffic_db()
    print("[SYSTEM] Mirage-Sentinel 雙核心資料庫啟動成功，物理隔離已就緒。")
    yield

app = FastAPI(title="Mirage-Sentinel API Gateway", version="1.2-FullForensics", lifespan=lifespan)

@app.get("/api/v1/user/{user_id}")
async def get_user_data(user_id: str, request: Request):
    # --- T1: 記錄請求進入時間 (精確到毫秒) ---
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # 1. 抓取基礎情報
    client_ip = request.client.host
    query_string = str(request.query_params)
    user_agent = request.headers.get("user-agent", "Unknown")

    # 2. 呼叫哨兵進行意圖分析
    is_attack, confidence, attack_vector = analyze_intent(query_string)

    if is_attack:
        # --- 進入防禦模式 (Mirage Mode) ---
        risk_score = int(confidence * 100)
        
        # 3. 讀取記憶與計算行為特徵 (Dwell Time / Interaction Depth)
        mem = get_memory(client_ip, user_id)
        
        dwell_time = 0.0
        interaction_depth = 1
        hits = 1
        fake_data = None

        if mem:
            # 計算滯留時間：本次 Request - 上次上次系統 Response
            last_seen_dt = datetime.strptime(mem['last_seen'], "%Y-%m-%d %H:%M:%S.%f")
            current_dt = datetime.now()
            dwell_time = (current_dt - last_seen_dt).total_seconds()
            
            interaction_depth = mem['depth'] + 1
            hits = mem['hits'] + 1
            fake_data = mem['payload']
            print(f"[MEMORY] 偵測到回頭客！滯留時間: {dwell_time}s | 互動深度: {interaction_depth}")
        else:
            # 初次攻擊，生成新誘餌
            fake_data = generate_fake_data(user_id)
            print("[MIRAGE] 生成全新幻象個資...")

        # --- T2: 系統準備回傳時間 ---
        end_perf = time.perf_counter()
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        process_ms = int((end_perf - start_perf) * 1000)

        # 4. 封裝 17 欄位數據 (完全對齊試算表)
        log_data = {
            "request_at": request_at,
            "response_at": response_at,
            "process_ms": process_ms,
            "attacker_ip": client_ip,
            "location": "Processing...",  # 預留給 GeoIP 擴充
            "is_proxy": 0,                # 預留給 Proxy 偵測擴充
            "user_agent": user_agent,
            "tls_fingerprint": "N/A",     # 預留給 JA3 擴充
            "raw_payload": query_string,
            "response_payload": fake_data,
            "query_id": user_id,
            "attack_vector": attack_vector,
            "risk_level": risk_score,
            "hits": hits,
            "interaction_depth": interaction_depth,
            "dwell_time": dwell_time,
            "mitigation_status": "Camouflaged"
        }

        # 5. 執行雙軌儲存
        log_attack_event(log_data)  # 寫入 traffic_logs.db
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data) # 寫入 mirage_memory.db

        print(f"[ALERT] 採證完成！風險分數: {risk_score} | 處理耗時: {process_ms}ms")
        return fake_data

    else:
        # --- 進入正常模式 ---
        return {"user_id": user_id, "name": "真實用戶", "status": "Normal"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)