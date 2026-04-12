# Mirage-Sentinel Status Report

本文件用於核對 Mirage-Sentinel 目前的實作進度，並以專案硬規則作為驗收基準：

1. `traffic_logs.db` 僅允許 append-only，honeypot 流程不可依賴其讀取作為主要決策來源。
2. 鑑識寫入不得阻塞公開 API 回應，時間戳需保留毫秒或微秒精度。
3. 誘餌與 SOC 相關容器需遵守最小權限與隔離原則。

更新日期：2026-04-12

## 名詞說明

- `principal_id`
  - 新的建議語意名稱。
  - 表示「互動主體識別」。
  - 目前在 banking proxy 中，優先對應 `X-User-Id`，通常就是 `vuln-bank-main` 的 CIF 或 customer id。
  - 若請求未帶主體識別，則退回 `proxy:<client_ip>`。

- `query_id`
  - 既有歷史命名。
  - 在目前程式裡實際上大多承載的是 `principal_id` 語意，而不是 query string id。
  - 現階段保留是為了相容既有資料表、回放 API 與分析函式；後續新功能應優先使用 `principal_id`。

- `request_chain_id`
  - 建議下一階段補上的欄位。
  - 用來表示單次攻擊鏈或單次互動鏈，不應與 `principal_id` 混用。

## 一、整體判定

- 專案目前屬於「可運行整合原型」階段。
- 核心骨架、代理、SOC API、部署與 smoke gate 已初步落地。
- 真正最緊急的缺口已從一般工程 backlog 轉為防禦成效缺口：
  1. `Sentinel` 無法完整攔截 `vuln-bank-main` 的漏洞探測與攻擊流量。
  2. `Mirage` 尚未在主路徑上產生穩定的替代回應，引誘攻擊者深入。
  3. `SOC` 已有查詢 API，但尚未完全落實成可回放、可分流、可驗證成效的事件中樞。

## 二、目前優先級

### P0：Sentinel 攔截與 Mirage 替代回應

這是目前最緊急的工作，直接影響專案是否真的具備欺敵防禦價值。

#### 現況

- 主入口目前會先將請求代理到 `vuln-bank-main`，之後才記錄事件與計算 `should_intercept`。
- 專案其實已存在一條「部分幻象回應」路徑：當 `should_intercept=true` 時，主流程會嘗試呼叫 `core.ai_agent_orchestrator`，並以 AI 或 fallback fake data 改寫回應。
- 但這條路徑啟動得太晚，因為 upstream request 仍已先送到 `vuln-bank-main`，所以目前仍不能視為真正的前置攔截或安全分流。
- 偵測輸入面目前以 `path + query + body` 為主，對 header、cookie、auth token、multipart、GraphQL 結構等面向覆蓋不足。

#### 已有基礎

- `main.py` 已具備代理、風險判斷、事件記錄、裝置特徵與部分 Counter-AI 判斷接點。
- `core/sentinel.py`、`model/ai_sentinel.py` 已有規則與模型推論能力。
- `core/deception_db.py`、`model/llama.py` 已有欺敵狀態與假資料生成基礎。

#### 主要缺口

- `Sentinel` 仍偏向旁路觀測，未真正成為前置決策器。
- 高風險流量雖然可在部分情況下被改寫為 Mirage/AI 回應，但時序上仍可能已命中真實 `vuln-bank-main`。
- 缺少針對 `vuln-bank-main` 常見攻擊入口的端點級欺敵策略。

#### 下個驗收點

1. 當 `should_intercept=true` 時，不再先請求 `vuln-bank-main`。
2. 至少為以下入口提供最小可用 Mirage 回應：
   - `/login`
   - `/transfer`
   - `/balance`
   - `/admin`
   - `/graphql`
3. 事件中需明確記錄：
   - `route_before`
   - `route_after`
   - `deception_reason`
   - `policy_hit`

#### P0 細部實作任務

##### P0-1：前置分流重構

- 在 `_proxy_banking_request()` 中將流程拆成兩段：
  1. `pre_upstream_risk_decision`
  2. `upstream_or_mirage_response`
- 規則為：
  - 若 `should_intercept=false`，才允許送往 `vuln-bank-main`
  - 若 `should_intercept=true`，直接走 Mirage/AI deception path
- 驗收：
  - 不再出現「先打上游，再改寫回應」的時序
  - 攻擊攔截決策發生在發送 upstream request 之前

##### P0-2：攻擊分類到回應模板映射

- 先以目前已能攔截的 attack vector 建立第一版映射，不等待完整 LLM 幻象。
- 建議最小映射：
  - `sqli` -> 假查詢錯誤、假交易資料、延遲型資料頁
  - `xss` -> 假表單回顯、假 preview 頁、可追蹤回應片段
  - `lfi/path-traversal` -> 假設定檔、假路徑清單、假錯誤堆疊
  - `cmdi/rce` -> 假 shell 執行結果、假 job 狀態、假 admin task queue
  - `rate_limit/replication/anomalous_amount` -> 假風控審查、假 OTP、假人工覆核流程
- 驗收：
  - 不同 attack vector 至少回不同 Mirage payload family
  - 不再只回單一 generic fallback JSON

##### P0-3：高價值端點欺敵模板

- 先針對以下端點實作靜態但可狀態化的 Mirage 回應：
  - `/login`
  - `/transfer`
  - `/balance`
  - `/admin`
  - `/graphql`
- 這些回應應來自 `mirage_memory.db` 或可拋棄 feature store，而非真實業務資料。
- 驗收：
  - 同一 `client_ip + query_id` 後續可得到連貫回應
  - 攻擊者可在假流程中繼續互動至少 2 到 3 步

##### P0-4：擴充偵測輸入面

- 將 `detection_target` 從 `path + query + body` 擴充為標準化特徵封包，至少納入：
  - path
  - query
  - body
  - headers
  - cookies
  - auth header/token
  - content-type
  - multipart filename
  - GraphQL query/mutation 文字
- 驗收：
  - 同一攻擊若僅藏在 header/cookie/token，也能被 Sentinel 納入判斷

##### P0-5：分流證據欄位

- 每一筆事件都要能回答「這次到底有沒有真的進 Mirage」。
- 建議新增欄位：
  - `decision_source`：`rule` / `ml` / `hybrid`
  - `upstream_attempted`：`true/false`
  - `upstream_status_code`
  - `deception_engaged`：`true/false`
  - `deception_mode`：`ai_deception` / `template_deception` / `fallback_deception`
  - `real_backend_touched`：`true/false`
  - `response_origin`：`vuln_bank_main` / `mirage` / `sandbox_ai`
- 驗收：
  - SOC 可直接區分「已成功導入幻象」與「仍打到真實上游」

##### P0-6：最小回歸測試

- 新增 smoke/integration 檢查：
  - 可疑 SQLi 請求不得觸發 upstream
  - 正常查詢仍可正常代理到 `vuln-bank-main`
  - 幻象回應必須帶有可辨識的 `response_origin=mirage|sandbox_ai`
- 驗收：
  - PR 或本地 smoke 能直接看出 P0 是否退化

#### Mirage 是否可先根據目前已攔截的攻擊做出回應

可以，而且應該先這樣做。

- 目前系統已經具備：
  - `Sentinel` 規則檢測
  - AI Sentinel 模型分數
  - `ai_agent_orchestrator`
  - `core.mirage` / fallback fake data
- 代表 Mirage 不需要等到「完整理解所有 `vuln-bank-main` 漏洞」才開始上線。
- 正確做法是先針對「目前已經能攔截的 attack vector」建立對應回應模板，先做到：
  - 能攔
  - 能假回
  - 能持續互動
  - 能被 SOC 驗證是否成功

#### SOC 如何區分幻象成功與否

SOC 必須以事件欄位明確區分兩件事：

1. 這次請求是否曾真正打到 `vuln-bank-main`
2. 最終回給攻擊者的是 Mirage 還是真實上游回應

最低可用判斷規則如下：

- `real_backend_touched=false` 且 `response_origin in {mirage, sandbox_ai}`
  - 視為「成功進入幻象」
- `real_backend_touched=true` 且 `response_origin=vuln_bank_main`
  - 視為「打到真實上游」
- `real_backend_touched=true` 且 `response_origin in {mirage, sandbox_ai}`
  - 視為「晚攔截」，不可算成功前置欺敵

這一點必須寫進 SOC 事件模型，否則資安人員無法核對 Mirage 的真實成效。

### P1：SOC 完整落地

SOC 是次急項目，優先級緊跟在 P0 之後。

#### 現況

- 已有 `services/dashboard_service.py` 與 dashboard API。
- 已提供健康檢查、recent traffic、IP bundle、heatmap、compare 等基本能力。
- Runbook 已存在，但回放與分析模型尚未完全對齊真實資料結構。

#### 已有基礎

- SOC backend 與 frontend 已有雙服務部署。
- `traffic_logs.db` 中已有事件欄位可供聚合與分析。
- `docs/RUNBOOK.md` 已定義事件回放與排障流程。

#### 主要缺口

- SOC 目前偏向查詢介面，尚未成為完整事件中樞。
- 缺少明確的分流結果、欺敵成效與攻擊鏈欄位。
- 尚未完整回答以下問題：
  - 哪些流量被成功攔截並導入欺敵？
  - 攻擊者在 Mirage 停留多久？
  - 哪些 Mirage 回應成功促使深入互動？
  - 哪些端點最常漏接或誤判？

#### 建議補齊欄位

- `route_before`
- `route_after`
- `session_chain_id`
- `deception_reason`
- `policy_hit`
- `flow_stage`
- `deception_score`
- `memory_hit`
- `trust_level`

#### 下個驗收點

1. SOC 可依單一 `session_chain_id` 回放完整攻擊鏈。
2. SOC 可區分 real path 與 deception path。
3. SOC 可顯示 Mirage 成效指標，而不只是原始流量清單。

### P2：資料庫解耦、安全硬化、測試補強

這些仍然重要，但現階段應排在 P0 與 P1 之後。

#### 現況

- 雙資料庫已存在，但 honeypot 主流程仍有直接讀取 `traffic_logs.db` 的邏輯。
- `sandbox` 容器已實作最小權限，但主 backend/SOC backend 尚未全面對齊。
- 目前測試以 smoke 為主，第一方單元測試仍不足。

#### 主要缺口

- 交易風險與重放檢測目前仍依賴鑑識庫讀取，不完全符合解耦原則。
- 主應用容器仍需補非 root、read-only 與最小 writable mount 設計。
- 缺少針對安全不變量的回歸測試。

#### 下個驗收點

1. 主流程不再讀取 `traffic_logs.db` 作為風險決策來源。
2. 所有鑑識寫入都以非阻塞模式完成。
3. backend 容器權限與 sandbox 基線一致。

## 三、目前完成項

- 主入口代理與健康檢查可運作。
- SOC backend 與 frontend 已有部署基礎。
- OCI deploy、PR smoke、post-deploy smoke 已建立。
- `RUNBOOK.md`、`README.md`、docs index 已建立。
- 欺敵記憶庫與鑑識庫的物理拆分已存在。

## 四、目前阻塞項

- `Sentinel` 攔截沒有真正改寫主路由。
- `Mirage` 回應尚未接入銀行代理主流程。
- `SOC` 欄位模型尚不足以支援完整攻擊回放與欺敵成效驗證。
- 資料庫解耦規則仍有違反點。

## 五、建議執行順序

1. 先完成 P0：讓 `Sentinel` 真正前置分流，並由 `Mirage` 回替代回應。
2. 接著完成 P1：補齊 SOC 事件鏈與成效分析欄位。
3. 最後完成 P2：收斂資料庫解耦、容器硬化與回歸測試。

## 六、每週核對用 Checklist

### P0 核對

- [ ] 高風險請求不再直接命中 `vuln-bank-main`
- [ ] 至少 5 個高價值入口具備替代回應
- [ ] 事件包含分流前後路徑與策略命中資訊

### P1 核對

- [ ] 可依 `session_chain_id` 重建攻擊鏈
- [ ] SOC 可區分 real/deception path
- [ ] SOC 可呈現 Mirage 成效指標

### P2 核對

- [ ] honeypot 不再讀取 `traffic_logs.db`
- [ ] 鑑識寫入完全非阻塞
- [ ] backend 容器最小權限落地
- [ ] 新增安全不變量回歸測試
