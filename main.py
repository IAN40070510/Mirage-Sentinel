from statistics import quantiles
from fastapi import FastAPI, Request, Query
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
async def get_user_data(
    user_id: str, 
    payload: str = Query(None, description="模擬惡意指令（如 DROP TABLE, <script>）"),
    request: Request = None
):
    # --- T1: 記錄請求進入時間 (精確到毫秒) ---
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # 1. 抓取基礎情報
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    # NOTE: 這裡我們優先抓取 Swagger 傳進來的 payload，如果沒有，再抓原始 query_string
    # 這樣可以同時兼顧「手動網址測試」與「Swagger UI 測試」
    current_payload = payload if payload else str(request.query_params)

    # 2. 呼叫哨兵進行意圖分析 (同時檢查 ID 與 測試內容，防止路徑與參數注入)
    # NOTE: 將 ID 與內容分開標記，有助於 Sentinel 精準判斷攻擊向量
    detection_target = f"ID: {user_id} | Payload: {current_payload}"
    is_attack, confidence, attack_vector = analyze_intent(detection_target)

    if is_attack:
        # --- 進入防禦模式 (Mirage Mode) ---
        risk_score = int(confidence * 100)
        
        # 3. 讀取記憶與計算行為特徵
        mem = get_memory(client_ip, user_id)
        
        dwell_time = 0.0
        interaction_depth = 1
        hits = 1
        fake_data = None

        if mem:
            # NOTE: mem 現在回傳的是字典，包含 last_seen, depth, hits, payload
            last_seen_dt = datetime.strptime(mem['last_seen'], "%Y-%m-%d %H:%M:%S.%f")
            current_dt = datetime.now()
            dwell_time = round((current_dt - last_seen_dt).total_seconds(), 2)
            
            interaction_depth = mem['depth'] + 1
            hits = mem['hits'] + 1
            fake_data = mem['payload']
            print(f"[MEMORY] 偵測到回頭客！深度: {interaction_depth} | 滯留: {dwell_time}s")
        else:
            fake_data = generate_fake_data(user_id)
            print("[MIRAGE] 生成全新幻象個資...")

        # --- T2: 系統準備回傳時間 ---
        end_perf = time.perf_counter()
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        process_ms = int((end_perf - start_perf) * 1000)

        # 4. 封裝數據 (完全對齊試算表)
        log_data = {
            "request_at": request_at,
            "response_at": response_at,
            "process_ms": process_ms,
            "attacker_ip": client_ip,
            "location": "Local/Render",  
            "is_proxy": 0,                
            "user_agent": user_agent,
            "tls_fingerprint": "N/A",     
            "raw_payload": current_payload, # 紀錄真正的攻擊內容
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
        log_attack_event(log_data)
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)

        print(f"[ALERT] 採證完成！深度: {interaction_depth} | 耗時: {process_ms}ms")
        return fake_data

    else:
        # --- 進入正常模式 ---
        return {"user_id": user_id, "name": "真實用戶", "status": "Normal"}
        
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)