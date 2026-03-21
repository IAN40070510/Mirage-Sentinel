from fastapi import FastAPI, Request
import uvicorn
from contextlib import asynccontextmanager

# 匯入核心偵測與幻象引擎
from core.sentinel import analyze_intent
from core.mirage import generate_fake_data

# 匯入拆分後的雙核心資料庫：一個對內記憶，一個對外日誌
from core.deception_db import setup_deception_db, get_memory, save_deception_state
from core.traffic_db import setup_traffic_db, log_attack_event

@asynccontextmanager
async def lifespan(app: FastAPI):
    """伺服器啟動時，同步初始化雙軌資料庫"""
    setup_deception_db()  # 檔案 A: mirage_memory.db
    setup_traffic_db()    # 檔案 B: traffic_logs.db
    print("[SYSTEM] 雙核心資料庫已完成物理隔離部署：")
    print("         - Deception Memory (後端一致性維護)")
    print("         - Traffic Logs (前端戰情數據源)")
    yield

# 初始化 FastAPI 伺服器
app = FastAPI(title="Mirage-Sentinel API Gateway", version="1.1-Hybrid", lifespan=lifespan)

@app.get("/api/v1/user/{user_id}")
async def get_user_data(user_id: str, request: Request, payload: str = ""):
    
    # 1. 抓取攻擊者基礎情報 (Who & How)
    client_ip = request.client.host
    # 修正：抓取包含 payload 參數在內的完整 query string
    query_string = str(request.query_params)
    user_agent = request.headers.get("user-agent", "Unknown")

    # 2. 呼叫哨兵進行意圖分析
    is_attack, confidence, attack_vector = analyze_intent(query_string)

    if is_attack:
        # --- 進入防禦模式 (Mirage Mode) ---
        risk_score = int(confidence * 100)
        print(f"\n[ALERT] 偵測到惡意請求！來源: {client_ip} | 風險: {risk_score} | 手法: {attack_vector}")
        
        # 3. 檢查「欺敵記憶庫」，確保同個駭客看到的東西是一樣的
        cached_data = get_memory(client_ip, user_id)
        if cached_data:
            # 即使命中快取，也要更新「戰情日誌」，讓前端知道這傢伙又來了
            log_attack_event(client_ip, risk_score, attack_vector, query_string, user_agent)
            print("[MEMORY] 快取命中！已同步推送到戰情日誌。")
            return cached_data
            
        # 4. 若無快取，由 AI 幻象引擎生成誘餌
        print("[MIRAGE] 正在生成全新的幻象個資...")
        fake_data = generate_fake_data(user_id)
        
        # 5. 雙軌儲存：
        # (A) 寫入後端記憶，維持之後連線的一致性
        save_deception_state(client_ip, user_id, fake_data)
        
        # (B) 寫入戰情日誌，供隊友前端 Dashboard 渲染圖表
        log_attack_event(client_ip, risk_score, attack_vector, query_string, user_agent)
        
        return fake_data

    else:
        # --- 進入正常模式 (Real Mode) ---
        # 隱私原則：正常流量不進日誌庫，也不進記憶庫
        return {
            "user_id": user_id,
            "name": "王小明 (真實用戶)",
            "email": "wang.real@company.com",
            "balance": 150.0,
            "status": "Normal"
        }

if __name__ == "__main__":
    print("[SYSTEM] Mirage-Sentinel API Gateway 啟動中...")
    uvicorn.run(app, host="0.0.0.0", port=8000)