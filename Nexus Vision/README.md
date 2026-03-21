# INFOSECSQL

INFOSECSQL 是一個以資訊安全情境為主題的專案，整合了前端頁面、JavaScript 服務邏輯，以及 Python 腳本與 SQLite 資料處理。

## 專案目錄與分工

| 路徑 | 用途 | 負責內容 |
|---|---|---|
| `public/` | 網頁前端 | 放置前端畫面與瀏覽器端程式碼（HTML/CSS/JS） |
| `services/` | 服務層 JavaScript | 組員分工撰寫的 JS 模組、API 串接、資料處理邏輯 |
| `scripts/` | Python 腳本 | 放置 Python 程式，例如資料庫初始化、資料處理腳本 |
| `server.js` | Node.js 入口 | 伺服器啟動點（目前可依需求擴充） |
| `README.md` | 專案說明文件 | 專案架構、啟動方式與協作規則 |

## 前端區域

`public/` 是本專案的網頁前端資料夾，主要包含：

- `index.html`：前端頁面骨架
- `style.css`：前端樣式
- `main.js`：前端互動與流程邏輯

## 服務層區域

`services/` 是組員協作的 JavaScript 區域，詳細參考Excel

可依分工再細分子資料夾，重點是保持命名一致與責任單一。

## Python 腳本區域

`scripts/` 用來放置 Python 程式。現有 `scripts/database.py` 提供 SQLite 記錄能力，主要功能包含：

- 初始化資料表 `deception_logs`
- 儲存攻擊來源與假資料 payload
- 查詢既有快取資料

執行後會建立或使用本地資料庫 `traffic_nexus.db`。

## 協作規範建議

- 前端畫面相關修改集中在 `public/`。
- 組員共同開發的 JavaScript 功能集中在 `services/`，避免把共用邏輯寫進前端頁面檔。
- Python 與資料庫處理集中在 `scripts/`，避免跨資料夾混放。
- 每次新增模組時，請同步更新本 README 的「專案目錄與分工」。
