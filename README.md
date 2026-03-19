Markdown
# 🛡️ Mirage-Sentinel (幻影哨兵)

> **次世代動態欺敵與隔離防禦系統 (Dynamic Deception and Isolation Defense System)**
>
> 專案負責人：林柏璋 (112AB0055) 暨開發團隊

## 📝 專案簡介

Mirage-Sentinel 是一款建構於 API 閘道器（API Gateway）之上的主動式資安防禦系統。傳統防火牆僅能做到「阻擋」，而幻影哨兵的核心理念是**「欺敵與消耗」**。
當系統偵測到惡意攻擊（如 SQL Injection、XSS）時，不會直接切斷連線或回傳錯誤，而是將駭客無縫導向「幻象引擎（Mirage Engine）」，即時生成具備高度真實性的誘餌資料（Honeypot Data），藉此消耗駭客的攻擊成本，並同步記錄其攻擊特徵與行為模式。

## 🚀 核心功能與架構 (Week 1 MVP)

本系統目前已實作四大核心防禦模組：

1. **核心 API 閘道 (API Gateway)**
   - 基於 `FastAPI` 打造的高效能異步路由。
   - 負責攔截所有外部請求，並作為分流正常用戶與駭客的樞紐。
2. **哨兵攔截引擎 (Sentinel Filter)**
   - 採用 **Aho-Corasick 多字串比對演算法** 與 **Bloom Filter 布隆過濾器**。
   - 結合 OWASP SecLists 惡意字典檔，實現微秒級（Microsecond）的攻擊意圖分析與動態風險評估 (`risk_level`)。
3. **狀態記憶庫 (State Persistence)**
   - 基於 `SQLite` 的輕量級記憶體資料庫 (`sqlite_memory.db`)。
   - 確保「欺敵一致性」：同一 IP 對同一標靶的重複攻擊，系統將回傳完全相同的誘餌資料，防止駭客識破蜜罐陷阱。
4. **幻象資料模擬器 (Mirage Mock)**
   - 整合 `Faker` 動態生成台灣繁體中文情境的誘餌。
   - 具備**情境感知（Context-aware）**能力：能根據駭客查詢的目標（如 `admin`, `666`, `1001`）動態切換回傳假個資、假高階主管薪資、或假的系統報錯訊息。

## 📂 專案目錄結構

```text
Mirage-Sentinel/
├── main.py                 # API 閘道器主程式 (系統入口)
├── requirements.txt        # 環境依賴套件清單
├── .gitignore              # Git 忽略設定 (保護金鑰與本地資料庫)
├── README.md               # 專案說明文件
└── core/                   # 核心防禦模組
    ├── sentinel.py         # 惡意流量分析與攔截邏輯
    ├── database.py         # SQLite 狀態記憶與情報寫入
    └── mirage.py           # Faker 動態幻象資料生成
🛠️ 本機端安裝與測試指南
1. 環境安裝
請確保您的環境已安裝 Python 3.8+，並執行以下指令安裝所需套件：

Bash
git clone [https://github.com/IAN40070510/Mirage-Sentinel.git](https://github.com/IAN40070510/Mirage-Sentinel.git)
cd Mirage-Sentinel
pip install -r requirements.txt
2. 啟動伺服器
Bash
uvicorn main:app --reload
伺服器啟動後，本機端測試網址為：http://127.0.0.1:8000

3. API 攻防演習 (Swagger UI)
請開啟瀏覽器前往 API 測試面板：http://127.0.0.1:8000/docs

🟢 良民測試 (正常流量)

user_id: 填入 1001

payload: (留白)

結果：系統放行，回傳真實用戶資料。

🔴 駭客測試 (惡意流量攔截)

user_id: 填入 admin

payload: 填入 DROP TABLE 或 <script> 等惡意指令

結果：哨兵觸發警報，系統切換至幻象模式，回傳逼真的假資料，並將攻擊情報（IP、時間、風險分數）寫入底層資料庫。

🔮 未來展望 (Next Steps)
[ ] 戰情室儀表板：串接 Streamlit，將 SQLite 內的攻擊情報視覺化（風險折線圖、攻擊熱區）。

[ ] AI 幻象升級：整合 OpenAI API，取代靜態 Faker，實現與駭客的 LLM 動態互動欺敵。

[ ] 快取升級：導入 Redis 取代 SQLite 作為高頻攻擊防禦的記憶層。
