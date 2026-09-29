# Medusa／DTC 攻擊面查核

查核日期：2026-09-20（Asia/Taipei）。專案 commit：fcbea45a62eae597a9a214c81b1efbdf9d4b1540。

## 範圍與限制

檢查目前 GitHub checkout 的自訂程式、Gateway、部署設定，以及原下載工作目錄已安裝的 Medusa 2.21.0 套件程式。後者是本機依賴證據，未核對 OCI 容器內容或套件完整性。Storefront 宣告 Next.js 15.5.24、React 19.0.5。

本次未對公開 OCI 執行攻擊測試。Docker Desktop 啟動後引擎仍無回應，本機 8080、9100 無法連線，因此未完成動態漏洞驗證；既有功能 smoke test 不等於安全測試。本報告不是完整依賴 CVE 稽核，也不宣稱任何類別不存在漏洞。

## 查核結果

| 類型 | 已取得的證據 | 判定 |
|---|---|---|
| SQLi | 自訂後端沒有發現將輸入拼入 SQL 的路徑；Medusa 商品 API 使用 query.graph／query.index 與 filterableFields。 | 未證實可利用 SQLi；未全面追查所有 ORM 與擴充套件。 |
| XSS | 商品描述在 `apps/storefront/src/modules/products/templates/product-info/index.tsx:33` 使用 `{product.description}`；自訂前後端搜尋未找到 dangerouslySetInnerHTML／innerHTML 寫入。 | 該顯示點使用 React 文字插值；其他 DOM、URL、依賴與管理頁仍需測試。 |
| SSTI | 自訂程式未找到將請求輸入交給模板編譯器的路徑。Next.js 伺服器渲染本身不構成 SSTI。 | 未證實；未來新增郵件、發票或可編輯模板時需重新查核。 |
| LFI／Path traversal | 自訂程式未找到由請求指定本機檔案讀取的功能；Gateway 解碼路徑後拒絕 `.`、`..` 路徑片段及反斜線。 | 存在入口防護，未證實任意檔案讀取；不能推論涵蓋全部編碼與上游靜態檔案路徑。 |
| Command injection | 自訂前後端未找到將買家輸入交給 exec／spawn／shell 執行的路徑。 | 未證實；部署建置腳本和全部第三方套件未逐一稽核。 |
| SSRF | 自訂 storefront 的直接 fetch 使用設定好的 Gateway URL；圖片設定為 unoptimized；未找到買家可自由指定後端抓取 URL 的自訂 API。 | 未證實；外掛、管理員功能、webhook 與完整依賴仍須另外檢查。 |
| 訂單權限／BOLA | `GET /store/orders/:id` 預設不要求 customer authentication；本專案沒有補上 ownership middleware。 | 已確認原始碼層級的存取設計風險，尚未動態重現跨使用者讀取。 |
| 管理員越權 | Gateway 公開入口阻擋 admin／app 等路徑，並限制 auth 路徑。 | 有入口限制；不能替代 Medusa 身分與角色權限驗證，未證實可繞過。 |
| 價格／數量竄改 | Store 購物車新增項目 schema 沒有 unit_price 欄位，quantity 必須大於 0；更新數量允許 0（刪除項目）。 | 未證實直接改價或負數數量漏洞；仍須驗證最終計價、優惠、庫存與併發。 |
| 撞庫／註冊濫用 | 查核的 Gateway、部署與自訂後端沒有找到明確的登入限速／帳號鎖定設定。 | 防護缺口候選；未檢查外部 WAF，也未進行壓力或撞庫測試。 |

上表自訂程式路徑均以專案 `commerce/` 為基準。Gateway 位於 `services/commerce/gateway.py`。

## 最重要的訂單存取問題

本機 `@medusajs/medusa/dist/api/store/orders/[id]/route.js` 明示以持有訂單 ID 作為存取依據。`orders/middlewares.js` 對訂單列表要求 customer authentication，對單筆訂單則只有查詢驗證；`orders/query-config.js` 的單筆預設欄位包含 email、shipping_address、billing_address。

官方文件亦說明此設計並提供登入與擁有者驗證範例：
https://docs.medusajs.com/resources/commerce-modules/order/secure-order-retrieval

這不代表攻擊者可直接列舉所有訂單，也不應直接宣稱為 Medusa 已確認 CVE。但若訂單 ID 從網址、紀錄或分享內容洩漏，持有者可能取得訂單資料。公開 publishable API key 不是買家身分驗證。Gateway 的訪客 Cookie 與正式／沙盒分流，也沒有驗證同一環境內的訂單擁有者。

若補強：會員訂單應驗證登入者與擁有者；訪客結帳須設計獨立、限時且綁定訂單的存取憑證，避免直接加登入限制破壞訪客流程。此改動應保留正式／沙盒獨立資料庫、非同步鑑識寫入及容器隔離；不應讓誘餌讀取鑑識資料庫來判定權限。

## 優惠券競態的版本差異

公開紀錄 CVE-2025-69871 描述 v2.12.2 及更早版本的 promotion registerUsage 競態；GitHub 項目目前標示 Unreviewed，結構化修補版本欄位為 Unknown：
https://github.com/advisories/GHSA-6r9h-3c6p-4chm

本機 2.21.0 的 `@medusajs/promotion/dist/services/promotion-module.js:132` 已有交易要求、promotion／budget 資料列 forUpdate 鎖定、鎖定後重新讀取與用量檢查。因此不能將舊版公告直接套用到本專案；也不能只憑這段程式就宣稱所有優惠券競態已消失，仍需併發回歸測試並核對實際部署版本。

## 對專題分類器的意義

依 2026-09-21 的專題範圍決定，電商規則已移除 SSTI，保留 SQLi、XSS、CMDi、LFI／Traversal 的「攻擊嘗試」紀錄；未成功不等於正常流量。分類結果、Gateway 處置、Medusa／Mirage 回應與利用是否成功應分開記錄；Mirage 擬真成功回應不代表正式環境被攻破。

BOLA、登入濫用、優惠券濫用通常沒有明顯惡意字串，須使用身分、資源擁有者、操作序列、失敗次數及交易狀態判定。不能只新增一個標籤就期待目前 payload 特徵能辨識。現有規則式判定分數也不是經過校準的攻擊機率。

## 待補的本機驗證

1. 用合成會員 A 下單，再用無登入與會員 B 嘗試取得 A 訂單；紀錄狀態碼與是否含敏感欄位，不輸出個資或 Token。
2. 檢查會員／訪客購物車與訂單的擁有權契約，以及登入後的綁定行為。
3. 測試未知單價欄位、負數數量、最終付款金額，以及有限次數的優惠券併發。
4. 在本機測試 XSS 顯示上下文、無害 SSTI 標記是否被當文字，以及登入限速；區分 Gateway 攔截與 Medusa 本身處理結果。

本次僅新增查核報告，未修改應用程式、模型、部署配置或推送 GitHub。

2026-09-21 更新：本機電商偵測已移除 SSTI 規則，特徵契約升為 v2，並保留舊模型原始標籤以避免類別錯位。SSTI 不再因該規則單獨觸發分流；若同時命中其他規則或模型判為可疑，仍會分流。這項範圍決定不等於證實沒有 SSTI 漏洞。尚未部署此更新。

同次回歸測試發現並修正：query／form body 的 `+` 空白編碼未還原，導致 `UNION+SELECT` 無法命中 SQLi 規則。現只在相應編碼上下文還原，JSON／headers 保留加號。變更後 commerce 測試 22 項通過，Ruff 與 git diff --check 通過；測試使用模擬上游，並非 Medusa 動態漏洞測試。其餘訂單 ownership、SOC HTTPS、鑑識佇列持久化與登入限速仍待處理。
