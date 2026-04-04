# Mirage-Sentinel 系統需求與規格書 (System Requirements Specification)

## 1. 系統概述 (System Overview)
Mirage-Sentinel 是一個結合機器學習（XGBoost）與大型語言模型（Llama 3.1）的主動防禦系統。本系統以「金融服務 API」為高價值欺敵場景，透過無縫流量轉發機制，將惡意探測導入高度隔離的 Docker 沙盒中。系統採取嚴格的資料庫解耦設計，確保威脅情報的安全收集，並透過 SOC 戰情室提供即時的視覺化監控。

---

## 2. 系統架構與模組映射 (Architecture & Module Mapping)
本系統之功能需求嚴格對應專案目錄結構，劃分為以下核心子系統：

* **閘道與路由層 (Gateway/API)：** `api/` (負責流量接收、無縫代理)
* **決策與欺敵核心 (Core Engine)：** `core/`, `model/` (負責意圖判定、假資料生成)
* **威脅情報與數據 (Data & Datasets)：** `data/`, `datasets/` (包含 SecLists 攻擊特徵庫)
* **戰情與視覺化 (SOC Frontend)：** `frontend/`, `services/` (負責即時推播與歷史趨勢)
* **基礎設施 (Infrastructure)：** `docker/`,根目錄之 `docker-compose*.yml`

---

## 3. 功能性需求 (Functional Requirements)

### 3.1 哨兵閘道與流量控制 (Sentinel Gateway)
負責第一線的請求接收與無縫路由轉發，確保攻擊者無法察覺網路拓撲變化。
* **REQ-GW-01 [無縫轉發]：** NGINX 與 FastAPI 必須支援非同步處理。當系統判定來源為惡意時，不得回傳中斷連線 (RST) 或重導向 (3xx) 狀態碼，必須於後台即時將流量 Proxy 至沙盒環境。
* **REQ-GW-02 [全封包記錄]：** 必須攔截 HTTP 請求之完整生命週期，包含 Headers、Query Parameters、Body Payload，並精確標記到達時間。

### 3.2 意圖分析模組 (Sentinel Engine)
對應路徑：`model/ai_sentinel.py`, `core/web_attack_dection.py`, `core/sentinel.py`
* **REQ-SE-01 [極速特徵辨識]：** 必須使用 XGBoost 模型進行輕量化推論，確保單次 API 請求的意圖判定延遲小於 50ms。
* **REQ-SE-02 [動態特徵提取]：** 必須整合 `datasets/SecLists/` 內之特徵庫（如 Web-Shells, LFI, SQLi 等 Payload），將流量轉換為機器學習特徵向量。
* **REQ-SE-03 [攻擊手法映射]：** 模型輸出必須包含攻擊意圖分類，並對應至具體的 MITRE ATT&CK 技術標籤。

### 3.3 動態欺敵與假資料生成 (Mirage Engine)
對應路徑：`core/mirage.py`, `core/api_mirage.py`, `core/deception_engine.py`
* **REQ-ME-01 [LLM 動態生成]：** 針對高複雜度的 API 探測，系統需透過 API 呼叫 Llama 3.1 8B 模型，動態生成語法合法但虛假的 JSON 回應。
* **REQ-ME-02 [狀態保持 (Stateful)]：** 欺敵環境必須具備記憶性。例如在 `api/banking.py` 中執行建立帳號或轉帳，該異動必須寫入欺敵記憶庫中，確保後續查詢邏輯一致。
* **REQ-ME-03 [AI 消耗戰 (Tarpitting)]：** 偵測到自動化 AI 掃描工具時，系統需注入隨機延遲（物理極限模擬），並回傳極度冗長之合法數據以消耗對方 Token 額度。
* **REQ-ME-04 [反向提示注入]：** 於動態生成的 JSON 錯誤代碼或隱藏欄位中，必須隨機安插針對 LLM 的干擾提示詞 (Reverse Prompt Injection)。

### 3.4 沙盒隔離與基礎設施 (Sandbox & Infrastructure)
對應路徑：`core/sandbox.py`, `docker-compose.oracle.yml`
* **REQ-SB-01 [容器化生命週期管理]：** 系統必須能透過程式碼自動掛載、啟動或銷毀隔離的金融誘餌 Docker 容器。
* **REQ-SB-02 [特權限制]：** 所有誘餌容器必須以 Non-root 使用者運行，嚴禁開啟 `--privileged` 模式，並移除非必要的 Linux Capabilities。

### 3.5 SOC 資安戰情室 (SOC Dashboard)
對應路徑：`frontend/`, `services/dashboard_service.py`
* **REQ-SOC-01 [即時數據推播]：** 必須透過 WebSocket 技術，將沙盒內發生的攻擊指令串流與 System Call 異常即時推播至前端。
* **REQ-SOC-02 [歷史趨勢分析]：** 必須提供 RESTful API 供前端查詢歷史攻擊數據（國別、連線數量、TTPs 排名），並支援圖表化呈現。

---

## 4. 非功能性需求 (Non-Functional Requirements)

### 4.1 時間精度與同步 (Time Precision)
* **REQ-NFR-01 [毫秒級時間戳記]：** 鑑識日誌之時間戳記必須採用精確至毫秒級之格式 (如 `DATETIME(3)` 或 Unix Epoch Time `BIGINT`)。
* **REQ-NFR-02 [NTP 強制同步]：** Oracle Cloud 宿主機與所有 Docker 容器必須強制與同一個 NTP 伺服器同步，杜絕時鐘漂移。

### 4.2 資料庫實體解耦 (Database Decoupling)
對應路徑：`api/db/`, `core/traffic_db.py`, `core/banking_db.py`
* **REQ-NFR-03 [職責與儲存分割]：** * 鑑識日誌（Traffic Logs）必須儲存於受保護的 PostgreSQL（或測試用 SQLite）資料庫中，誘餌環境僅具備單向寫入權限。
    * 虛擬互動狀態（Mirage Memory）必須儲存於獨立的資料庫實體中（如 `banking_db`）。
* **REQ-NFR-04 [時間側信道消除]：** 鑑識日誌的寫入 I/O 必須非同步化，不得影響 NGINX/FastAPI 回傳欺敵資料的反應時間。

### 4.3 雲端網路隔離 (OCI VCN Architecture)
* **REQ-NFR-05 [公用子網限制]：** 僅有 Load Balancer 與 NGINX 哨兵閘道允許暴露於 Public Subnet 接收外部 HTTP/HTTPS 流量。
* **REQ-NFR-06 [專用子網防護]：** PostgreSQL 核心資料庫、XGBoost 推論引擎與 SOC 前端伺服器必須部署於 Private Subnet，阻斷所有來自外部的直接存取。
