# Mirage-Sentinel Codex 交接紀錄

## 2026-11-02：初始分析

已完成現行專案的唯讀盤點，重點包括：

- Gateway、Detector、VisitorStore、AuditQueue、Collector、Mirage 與 SOC。
- real/sandbox Medusa、PostgreSQL、Docker network 與 volume 隔離。
- append-only forensic database、非同步鑑識提交、visitor routing 與模型 fallback。
- Python 測試與部署設定。

分析時確認：

- 現行電商入口在 `services/commerce/` 與 `docker-compose.commerce.yml`。
- Gateway 依規則及模型將訪客分流至 real 或 sandbox。
- Mirage 只應使用 disposable memory，不能讀取 forensic DB。
- Collector 的 forensic events 只允許 append，不應由 Gateway 或 Mirage 掛載。
- Compose 預設 `SENTINEL_MODEL_MODE=shadow`，五分類模型尚未完成 deployment validation。
- host 測試曾有 3 個五分類模型測試因 bundle 與 host 的 NumPy 依賴不一致而失敗；本次沒有修復。
- 另識別出 AuditQueue 長時間重試、forensic retention、Mirage 同步 SQLite I/O、Docker/browser integration 與歷史文件落差等後續議題；本次沒有修復。

初始測試結果：

```text
python -m compileall -q services scripts tests
通過

python -m pytest tests -q
26 passed, 3 failed
```

## 2026-11-02：戰情室時間需求

使用者要求：

- 戰情室顯示台灣時間。
- 時間精度到毫秒。
- 後續對話與動作持續整理到本文件，供 Codex 接手。

實作決策：

- 保留後端與 forensic event 的 UTC ISO 8601 timestamp 作為 canonical value。
- 後端 `now_iso()` 已以 `isoformat(timespec="milliseconds")` 產生毫秒精度。
- 只在 SOC 前端顯示層使用 `Intl.DateTimeFormat` 的 `Asia/Taipei` 與 `fractionalSecondDigits: 3`。
- 顯示加上 `GMT+8`，原始 API/export JSON 仍保留 UTC 值。
- 不改變事件排序、API 查詢或鑑識資料格式。

## 2026-11-02：Push 前工作

Git checkout 位於 `artifacts/publish-repo`；workspace 根目錄不是 Git repository。該 checkout 有大量未追蹤研究/資料集檔案，本次不得整批加入。

本次只修改：

- `services/commerce/soc.html`
  - 現行版本的事件列表時間改為台灣時間，固定顯示三位毫秒。
  - 即時更新狀態列的更新時間也改為同一格式。
  - 保留現行版本的即時刷新、IP 篩選、分頁與其他功能。
- `docs/CODEX_HANDOFF_ANALYSIS.md`
  - 保存本次分析、未修復議題、時間需求、實作決策與驗證紀錄。

驗證：

- 使用 Node 直接讀取並編譯 SOC 內嵌 JavaScript。
- 驗證 `2026-11-01T18:42:55.846Z` 顯示為 `2026/11/02 02:42:55.846 GMT+8`。
- 尚未啟動 Docker 或實際瀏覽器 rendering。
- 未修改其他程式碼、依賴、模型、資料庫或部署設定。

接手注意：

- 不要把 legacy pickle pipeline 接回現行 Gateway。
- 不要把 forensic volume 掛載給 Gateway、Mirage 或 sandbox。
- 不要對正式資料執行 `down -v` 或 `volume prune`。
- 不要提交 `.env.commerce`、credentials、Cookie 或完整事件 log。
- 在模型完成獨立 deployment validation 前，不要把 shadow 改為 enforce。
