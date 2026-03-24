# Mirage-Sentinel

Mirage-Sentinel 是一個以 FastAPI 為核心的主動式防禦 API Gateway。
系統會先做攻擊意圖判斷，對高風險請求導向沙盒並回傳假資料，同時寫入攻防日誌與欺敵記憶。

## 專案目標

1. 偵測惡意請求（SQLi、XSS、LFI、命令注入等）
2. 將高風險流量隔離到沙盒服務
3. 回傳一致的假資料（Deception）拖延攻擊者
4. 記錄完整攻防軌跡供儀表板分析

## 目前功能

1. 攻擊檢測與風險分數：由 `core/sentinel.py` 分析請求意圖
2. 沙盒隔離：由 `core/sandbox.py` 將惡意請求轉送至 `sandbox_service.py`
3. 假資料生成：由 `core/mirage.py` 產生誘餌資料
4. 狀態記憶：`data/mirage_memory.db` 會保存同一攻擊者的欺敵狀態
5. 攻防日誌：`data/traffic_logs.db` 記錄攻擊向量、風險、處置狀態
6. 監控 API：`api/dashboard.py` 提供唯讀查詢（需 API Key）

## 系統流程

1. Client 呼叫 API 入口 `main.py`
2. Sentinel 判斷是否為高風險攻擊
3. 若為攻擊：
   - 讀取 `mirage_memory.db` 是否已有記憶
   - 有記憶時回傳同一份假資料
   - 無記憶時導向沙盒，產生新假資料並寫回記憶
4. 同步寫入 `traffic_logs.db` 供後續分析

## 專案結構

```text
Mirage-Sentinel/
├── main.py
├── sandbox_service.py
├── api/
│   └── dashboard.py
├── core/
│   ├── sentinel.py
│   ├── mirage.py
│   ├── sandbox.py
│   ├── deception_db.py
│   ├── traffic_db.py
│   └── nexus_db.py
├── data/
│   ├── datasets/
│   ├── mirage_memory.db
│   └── traffic_logs.db
├── frontend/
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 環境需求

1. Python 3.10+
2. Docker + Docker Compose（選用）

## 本機啟動

```bash
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Swagger 文件：`http://127.0.0.1:8000/docs`

## Docker 啟動

```bash
docker compose up --build
```

服務預設：

1. API Gateway：`http://127.0.0.1:8000`
2. Sandbox Service：`http://127.0.0.1:8001`

## 主要 API

1. `GET /api/v1/user/{user_id}`
   - 正式入口
   - `payload` 可用於測試攻擊字串

2. `POST /api/v1/simulate_attack`
   - 測試入口
   - 參數：`user_id`、`payload`（選填）、`client_ip`（可切換攻擊者）
   - 用於驗證同攻擊者是否拿到同一份假資料

3. `GET /api/v1/dashboard/*`
   - 監控查詢 API
   - 需在 Header 帶 `X-API-Key`

## API Key（目前狀態）

目前程式從 `.env` 讀取：

```env
API_KEY=replace-with-a-strong-random-key
```

## 記憶機制說明

欺敵記憶鍵值目前為：

1. `client_ip`
2. `query_id`（對應 user_id）

效果：同一攻擊者重複攻擊同一目標時，系統會回傳一致的假資料，並更新欺敵成效指標。

## 互動深度（Deception Interaction Depth）

互動深度不再是單純請求次數，而是「騙術成功度」的綜合評分（`depth_score`，0~100）。

四個評分維度如下：

1. 攻擊鏈轉換率（`funnel_level`）
   - L1：淺層探測
   - L2：持續互動（命中記憶）
   - L3：深層探勘（跨端點、憑證/內部資源探測跡象）
2. 戰場停留時間（`dwell_seconds`）
3. 端點探索廣度（`endpoint_coverage`）
4. 惡意負載演化（`payload_evolution_score`）

實作位置：`core/deception_metrics.py`

## 深度分析 API

1. `GET /api/v1/dashboard/interaction_depth/{client_ip}?query_id=...`
   - 回傳 `depth_score` 與四維度分項分數
2. `POST /api/v1/simulate_attack`
   - 回傳 `deception_memory`，含 `funnel_level`、`endpoint_coverage`、`payload_evolution_score`

## 範例回應 JSON

`POST /api/v1/simulate_attack`

```json
{
   "status": "attack_detected",
   "fake_data": {
      "user_id": "1001",
      "name": "王小明",
      "email": "demo@example.com",
      "balance": 982341,
      "status": "active"
   },
   "event_log": {
      "request_at": "2026-03-24 21:10:45",
      "response_at": "2026-03-24 21:10:45",
      "process_ms": 27,
      "client_ip": "10.10.10.1",
      "raw_payload": "1001 ../../../../etc/passwd",
      "query_id": "1001",
      "attack_vector": "LFI",
      "risk_level": 92,
      "is_attack": 1,
      "mitigation_status": "Sandboxed",
      "interaction_depth": 74,
      "dwell_time": 181.0,
      "hits": 3
   },
   "deception_memory": {
      "dwell_time": 181.0,
      "interaction_depth": 74,
      "hits": 3,
      "funnel_level": 3,
      "endpoint_coverage": 4,
      "payload_evolution_score": 68
   }
}
```

`GET /api/v1/dashboard/interaction_depth/{client_ip}?query_id=1001`

```json
{
   "client_ip": "10.10.10.1",
   "query_id": "1001",
   "depth_score": 74,
   "funnel_level": 3,
   "dwell_seconds": 181,
   "endpoint_coverage": 4,
   "payload_evolution_score": 68,
   "dimension_scores": {
      "funnel": 100,
      "dwell_time": 20,
      "endpoint_coverage": 80,
      "payload_evolution": 68
   }
}
```

## 測試範例

```bash
# 正常請求
curl "http://127.0.0.1:8000/api/v1/user/1001"

# 攻擊測試
curl "http://127.0.0.1:8000/api/v1/user/1001?payload=DROP%20TABLE%20users"

# 切換攻擊者測試記憶
curl -X POST "http://127.0.0.1:8000/api/v1/simulate_attack?user_id=1001&payload=../../../../etc/passwd&client_ip=10.10.10.1"
```

## 已知限制

1. 正常流量分支目前回傳示意資料，尚未串接真實業務後端
2. API Key 仍為硬編碼，尚未完成環境變數化
3. AI 模型層仍在規劃中

## 開發路線圖

1. 必做：導入 XGBoost 快篩層（特徵工程 + 訓練 + 推論整合）
2. 必做：導入幻象生成模型 Llama3.1 8B（Mirage Agent）
3. 選做：Regex 前置規則層
4. 選做：向量相似度比對層
5. 選做：DistilBERT 語意複判層

## 幻象模型必做規格（Llama3.1 8B）

1. 模型用途：惡意請求命中後，生成高一致性的欺敵回應
2. 一致性要求：同駭客攻擊須維持相同角色與資料敘事
3. 安全要求：不得回傳真實後端資料，不得暴露系統內部路徑與金鑰
4. 失敗保護：Llama 逾時或失敗時，需回退至既有 Faker/模板回應
5. 記錄要求：每次生成需寫入 traffic_logs 與 mirage_memory 供稽核

## 必做驗收清單

1. XGBoost 可完成訓練、載入與線上推論
2. Mirage Agent 已串接 Llama3.1 8B 並能回傳欺敵資料
3. 同 client_ip 的重複攻擊可維持邏輯與過往回覆相同的假資料與可追蹤深度分數
4. Llama3.1 8B 異常時可自動回退，不影響 API 可用性
5. Dashboard 可查到攻擊事件、風險分數與處置狀態

## 授權

此專案目前未附正式開源授權。若要對外釋出，建議補上 LICENSE。