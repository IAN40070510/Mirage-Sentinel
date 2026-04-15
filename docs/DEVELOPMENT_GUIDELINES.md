# Mirage-Sentinel 開發與安全規範 (Development Guidelines)

本專案為高敏感度的資安主動防禦系統。為確保系統本身的安全性與鑑識資料的有效性，所有參與開發的工程師必須嚴格遵守以下架構邊界與安全提交流程。

## 1. 核心架構與邊界原則 (嚴格遵守)

* **資料庫解耦與單向寫入：** 處理鑑識日誌時，絕對只能對 `traffic_logs.db` 進行「單向寫入 (Append-only)」。狀態互動邏輯只能讀寫 `mirage_memory.db`，嚴禁跨庫操作。
* **消除時間側信道：** 所有涉及鑑識日誌寫入的 API 邏輯，必須使用非同步 (Asynchronous) 或 Message Queue 處理，不可阻塞 API 的回應時間。
* **時間精度要求：** 程式碼中所有時間戳記 (Timestamps) 必須精確到毫秒 (ms)。強迫使用帶有小數秒的 ISO 8601 格式 (如 `YYYY-MM-DDTHH:mm:ss.SSSZ`)。
* **誘餌擬真錯誤處理：** 在誘餌 API (`src/honeypots/`) 中，不可暴露真實的 Python 錯誤訊息。必須刻意捕捉例外，並根據場景回傳擬真的 Java/PHP/Node.js 堆疊追蹤 (Stack Trace)。

## 2. 自動化靜態分析與提交流程 (SAST & Git Workflow)

為防止有瑕疵的程式碼進入版本庫，本專案將安全護欄直接整合進 Git 工作流中。所有提交必須通過本地端的自動化檢測。

### 2.1 資安 Linter (Bandit)
專案強制導入 `bandit` 進行 Python 程式碼的安全掃描。它會在程式碼執行前，靜態分析出以下常見漏洞：
* 寫死的密碼或 API Key (Hardcoded credentials)
* 危險的系統呼叫 (如 `subprocess.Popen` 搭配 `shell=True`)
* 不安全的反序列化與弱加密演算法
* 不安全的檔案權限設定

### 2.2 Pre-commit Hooks 機制
專案根目錄配有 `.pre-commit-config.yaml`。每次執行 `git commit` 時，系統會自動在本地端觸發以下檢查：
1. 移除多餘的空白字元與修正檔案結尾。
2. 透過 `black` 與 `flake8` 進行程式碼排版與語法檢查。
3. 透過 `bandit` 執行嚴格的資安漏洞掃描。

### 2.3 未使用變數與靜態檢查提醒

- **嚴禁出現未使用的區域變數**（如 flake8 F841），所有開發者必須在提交前移除未使用的變數，否則將被 pre-commit hook 阻擋。
- 建議於開發時隨時執行 `flake8` 或 IDE 靜態分析，避免因小疏忽導致提交失敗。
- 相關規則已寫入 pre-commit，自動化流程會強制執行。

**⚠️ 注意：** 一旦發現違反安全規範的語法，`pre-commit` 將直接阻擋提交 (Commit 失敗)，開發者必須當場修正錯誤後才能再次提交。嚴禁使用 `--no-verify` 參數強制繞過檢查。
