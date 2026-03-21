# Mirage-Sentinel (幻影哨兵)

> **基於 AI Agent 之自主偽裝與隔離防禦系統 (Autonomous Camouflage and Isolation Defense System Based on AI Agent)**
> 
> 專案負責人：林柏璋 (112AB0055) 暨開發團隊

## 專案簡介

Mirage-Sentinel 是一款建構於 API 閘道器（API Gateway）之上的主動式資安防禦系統。傳統防火牆僅能做到「阻擋」，而幻影哨兵的核心理念是**「欺敵與消耗」**。

當系統偵測到惡意攻擊（如 SQL Injection、XSS、LFI）時，不會直接切斷連線或回傳錯誤，而是將駭客無縫導向「幻象引擎（Mirage Engine）」，即時生成具備高度真實性的誘餌資料（Honeypot Data），藉此消耗駭客的攻擊成本，並同步記錄其攻擊特徵與行為模式。

## 核心功能與架構 (當前 MVP 階段)

本系統採用 **CQRS (命令查詢職責分離)** 的底層架構設計，目前已實作以下防禦模組：

1. **核心 API 閘道 (FastAPI Gateway)**
   - 基於 `FastAPI` 打造的高效能異步路由，負責攔截所有外部請求，並作為分流正常用戶與駭客的樞紐。
2. **哨兵攔截引擎 (Sentinel Filter)**
   - 採用 **Aho-Corasick 多字串比對演算法** 與 **Bloom Filter 布隆過濾器**。
   - 結合 OWASP SecLists 惡意字典檔，實現微秒級（Microsecond）的攻擊意圖分析與動態風險評估 (`risk_level`)。
3. **幻象資料模擬器 (Mirage Mock)**
   - 整合 `Faker` 動態生成台灣繁體中文情境的誘餌。具備**情境感知（Context-aware）**能力：能根據駭客查詢的目標動態切換回傳假個資、假薪資、或假系統報錯訊息。
4. **物理雙核記憶體 (Dual-DB Architecture)**
   - **`mirage_memory.db` (內部狀態庫)**：確保「欺敵一致性」。同一 IP 重複攻擊，系統將極速查閱此庫並回傳相同的誘餌資料，防止駭客識破。
   - **`traffic_logs.db` (戰情倉儲)**：背景異步寫入完整的攻防紀錄，為下一階段的戰情室視覺化做準備。

## 專案目錄結構

```text
Mirage-Sentinel/
├── data/                   # SQLite 實體資料庫掛載區
│   ├── traffic_logs.db     # (A 資料庫) 攻擊特徵與大數據日誌
│   └── mirage_memory.db    # (B 資料庫) 欺敵引擎內部狀態記憶
├── backend/                # 後端：API 閘道與核心引擎
│   ├── main.py             # FastAPI 進入點
│   ├── core/               # Sentinel 與 Mirage 邏輯
│   └── requirements.txt    
└── frontend/               # 前端：資安戰情室 (開發中)
本機端安裝與測試指南
1. 環境安裝
請確保您的環境已安裝 Python 3.10+，並執行以下指令：

Bash
git clone [https://github.com/IAN40070510/Mirage-Sentinel.git](https://github.com/IAN40070510/Mirage-Sentinel.git)
cd Mirage-Sentinel/backend
pip install -r requirements.txt
2. 啟動伺服器
Bash
uvicorn main:app --reload --port 8000
3. API 攻防演習 (Swagger UI)
請開啟瀏覽器前往 API 測試面板：http://127.0.0.1:8000/docs 進行攻防測試：

良民測試 (正常流量)

Payload: (留白) 或輸入正常字串。

結果：系統放行，回傳真實用戶資料。

駭客測試 (惡意流量攔截)

Payload: 填入 DROP TABLE 或 <script> 等惡意指令。

結果：哨兵觸發警報，系統切換至幻象模式，回傳逼真的假資料，並將攻擊情報（IP、時間、風險分數）寫入底層資料庫。

未來展望 (Next Steps)
[ ] CTI 戰情室儀表板：開發 Streamlit 前端介面，以唯讀模式介接 traffic_logs.db，將全球威脅熱點與武器特徵視覺化。

[ ] Docker 容器化部署：撰寫 docker-compose.yml，實現前後端雙引擎與資料庫掛載的一鍵部署至 Linux 伺服器。

[ ] AI 幻象升級：整合 LLM (大語言模型) API，取代靜態 Faker，實現與駭客的動態互動欺敵。

[ ] 自動化封鎖機制：結合外部防火牆 API (如 Cloudflare WAF)，當同一 IP 累積極高風險分數時，自動進行網路層級的封鎖。
