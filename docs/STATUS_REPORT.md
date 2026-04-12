# Mirage-Sentinel Status Report

本文件用於核對 Mirage-Sentinel 目前的實作進度，並以專案硬規則作為驗收基準：

1. `traffic_logs.db` 僅允許 append-only，honeypot 流程不可依賴其讀取作為主要決策來源。
2. 鑑識寫入不得阻塞公開 API 回應，時間戳需保留毫秒或微秒精度。
3. 誘餌與 SOC 相關容器需遵守最小權限與隔離原則。

更新日期：2026-04-12

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
- 目前 `should_intercept` 只影響 event log 欄位，沒有真正改寫回應路徑。
- `Mirage` 生成模組尚未接入銀行代理主流程，因此高風險流量仍可能直接得到上游真實回應。
- 偵測輸入面目前以 `path + query + body` 為主，對 header、cookie、auth token、multipart、GraphQL 結構等面向覆蓋不足。

#### 已有基礎

- `main.py` 已具備代理、風險判斷、事件記錄、裝置特徵與部分 Counter-AI 判斷接點。
- `core/sentinel.py`、`model/ai_sentinel.py` 已有規則與模型推論能力。
- `core/deception_db.py`、`model/llama.py` 已有欺敵狀態與假資料生成基礎。

#### 主要缺口

- `Sentinel` 仍偏向旁路觀測，未真正成為前置決策器。
- 高風險流量未穩定導入 Mirage 回應支線。
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
