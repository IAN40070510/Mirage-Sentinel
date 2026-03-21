# Mirage-Sentinel (幻影哨兵)

> **次世代動態欺敵與隔離防禦系統 (Dynamic Deception and Isolation Defense System)**
> 
> 專案負責人：林柏璋 (112AB0055) 暨開發團隊

## 專案簡介

Mirage-Sentinel 是一款建構於 API 閘道器（API Gateway）之上的主動式資安防禦系統。傳統防火牆僅能做到「阻擋」，而幻影哨兵的核心理念是**「欺敵與消耗」**。

當系統偵測到惡意攻擊（如 SQL Injection、XSS、LFI）時，不會直接切斷連線或回傳錯誤，而是將駭客無縫導向「幻象引擎（Mirage Engine）」，即時生成具備高度真實性的誘餌資料（Honeypot Data），藉此消耗駭客的攻擊成本，並同步將攻擊特徵與行為模式即時呈現在資安戰情室中。

## 核心功能與架構 (v2.0 雙核進化版)

本系統採用 **CQRS (命令查詢職責分離)** 架構，確保前線防禦與後端數據展示的高效能與解耦：

1. **核心 API 閘道 (FastAPI Gateway)**
   - 基於 `FastAPI` 打造的高效能異步路由，負責攔截所有外部請求，並作為分流正常用戶與駭客的樞紐。
2. **哨兵攔截引擎 (Sentinel Filter)**
   - 採用 **Aho-Corasick 多字串比對演算法** 與 **Bloom Filter 布隆過濾器**。
   - 結合 OWASP SecLists 惡意字典檔，實現微秒級（Microsecond）的攻擊意圖分析與動態風險評估 (`risk_level`)。
3. **幻象資料模擬器 (Mirage Mock)**
   - 整合 `Faker` 動態生成台灣繁體中文情境的誘餌。具備**情境感知（Context-aware）**能力：能根據駭客查詢的目標動態切換回傳假個資、假薪資、或假系統報錯訊息。
4. **物理雙核記憶體 (Dual-DB Architecture)**
   - **`mirage_memory.db` (內部狀態庫)**：確保「欺敵一致性」。同一 IP 重複攻擊，系統將極速查閱此庫並回傳相同的誘餌資料，防止駭客識破。
   - **`traffic_logs.db` (戰情倉儲)**：背景異步寫入完整的攻防紀錄（含駭客 IP、手法、配發的假資料），專供前端儀表板唯讀取用。
5. **CTI 戰情室 (SOC Dashboard)**
   - 基於 `Streamlit` 打造，即時可視化 `traffic_logs.db` 內的情報，包含全球威脅熱點、武器特徵熱力圖與駭客標靶雷達。

## 專案目錄結構

```text
Mirage-Sentinel/
├── docker-compose.yml      # 雲端部署設定檔
├── data/                   # SQLite 實體資料庫掛載區
│   ├── traffic_logs.db     # 給戰情室畫圖用
│   └── mirage_memory.db    # 給欺敵引擎記憶用
├── backend/                # 後端：API 閘道與核心引擎
│   ├── main.py             # FastAPI 進入點
│   ├── core/               # Sentinel 與 Mirage 邏輯
│   └── requirements.txt    
└── frontend/               # 前端：資安戰情室
    ├── dashboard.py        # Streamlit 視覺化面板
    └── requirements.txt    
```

## 本機端安裝與測試指南

### 1. 環境安裝
請確保您的環境已安裝 Python 3.10+，並開啟兩個終端機分別啟動前後端：

```bash
git clone [https://github.com/IAN40070510/Mirage-Sentinel.git](https://github.com/IAN40070510/Mirage-Sentinel.git)
cd Mirage-Sentinel
```

### 2. 啟動服務 (雙視窗)
**[終端機 A] 啟動後端 API 閘道：**
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
**[終端機 B] 啟動前端戰情室：**
```bash
cd frontend
pip install -r requirements.txt
streamlit run dashboard.py --server.port 8501
```

### 3. API 攻防演習 (Swagger UI)
請開啟瀏覽器前往 API 測試面板：`http://127.0.0.1:8000/docs` 進行攻防測試：

* **良民測試 (正常流量)**
  * Payload: (留白) 或輸入正常字串。
  * 結果：系統放行，回傳真實用戶資料。
* **駭客測試 (惡意流量攔截)**
  * Payload: 填入 `DROP TABLE` 或 `<script>` 等惡意指令。
  * 結果：哨兵觸發警報，系統切換至幻象模式，回傳逼真的假資料。此時開啟 `http://127.0.0.1:8501` 的戰情室，即可看到該筆攻擊已被記錄並視覺化。

## 雲端伺服器部署 (Docker)
本系統已完整容器化。於 Linux 伺服器上，僅需在專案根目錄執行以下指令，即可一鍵啟動雙引擎並掛載資料庫防護：
```bash
docker-compose up -d --build
```

## 未來展望 (Next Steps)
- [x] **戰情室儀表板**：完成 Streamlit 串接與 CQRS 讀寫分離架構。
- [ ] **AI 幻象升級**：整合 LLM (大語言模型) API，取代靜態 Faker，實現與駭客的動態互動欺敵。
- [ ] **自動化封鎖機制**：結合外部防火牆 API (如 Cloudflare WAF)，當同一 IP 累積極高風險分數時，自動進行網路層級的封鎖。
```

接下來，需要我幫你檢視前端 `dashboard.py` 裡面撈取資料庫的 SQL 語法嗎？
