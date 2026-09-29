# Copilot 接手：目前問題與驗收清單

日期：2026-09-20。審查基準：GitHub `main` commit `fcbea45a62eae597a9a214c81b1efbdf9d4b1540`。這是程式碼審查與唯讀 HTTP 查驗，不是完整滲透測試；沒有取得 OCI 的即時容器設定或登入戰情室。

## 先開對專案

真正包含 Git 歷史與 origin 的工作副本在原下載資料夾的 **`artifacts/publish-repo`**，已快轉到上述版本。原下載資料夾不是 Git repository，部分檔案仍是舊版本。請用 VS Code 開啟 `artifacts/publish-repo` 再使用 Copilot，不要直接以外層舊檔覆蓋新 main。

最新 [部署工作](https://github.com/IAN40070510/Mirage-Sentinel/actions/runs/35462465458) 與 [部署後檢查](https://github.com/IAN40070510/Mirage-Sentinel/actions/runs/35462749396) 顯示 success。公開網站 `/` 實測 307 到 `/dk`；公開 SOC `http://161.33.154.211:3000/` 實測 401 並要求 Basic authentication。不能把「部署成功」解讀為以下安全與可靠性問題已解決。

## 優先處理的確認問題

### P1：公開 SOC 透過 HTTP 傳送 Basic 登入

證據：[Compose 第 107 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/docker-compose.commerce.yml#L107) 將 collector 發佈到 `0.0.0.0:3000`；[collector 第 21 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/services/commerce/collector.py#L21) 使用 HTTP Basic。此次實測也確實可由公開 HTTP 收到 Basic challenge。Basic 本身不加密密碼；目前沒有 TLS 保護這條存取路徑。這組帳密可讀鑑識紀錄及解除訪客沙盒標記。

修正：SOC 回到 loopback + SSH tunnel，或放在具 HTTPS 的受控管理入口後，阻擋直接公開 HTTP 存取。不要僅加密碼卻保留明文傳輸。

驗收：外部不能再直接透過 HTTP 存取管理 API；管理員透過指定安全入口仍可查詢事件及解除標記。

### P1：鑑識事件可能遺失，永久失敗事件會堵住後續事件

證據：[audit.py 第 17–51 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/services/commerce/audit.py#L17) 使用有界記憶體 queue，滿了直接增加 dropped；未送達事件在程序重啟後不保留。單一 worker 對所有 HTTP 錯誤無限重試，連 400/413 等永久錯誤也不分流，後续事件會一直排隊。

修正：使用持久化訊息佇列，保留非同步寫入；暫時錯誤有限退避重試，永久錯誤進入可稽核的 dead-letter queue。保留 event_id 去重。

驗收：collector 中斷及 gateway 強制重啟後，事件可補送且不重複；一筆不合法／過大的事件不阻塞後續合法事件；誘餌回應不等待鑑識 DB 寫入。

### P1：資料持續成長，缺少保留、封存及容量限制

證據：[collector.py](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/services/commerce/collector.py#L31) 持續追加事件，沒有分區封存或容量政策；[state.py 第 54 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/services/commerce/state.py#L54) 的 30 天只影響狀態有效性，不會主動刪除過期訪客資料列。商店訂單也沒有對應 30 天清理流程。每個新 Cookie 都能建立新訪客，沒有入口速率限制；正常靜態資源也會產生事件。OCI 剩餘磁碟有限，持續流量可能影響同機正式資料庫。

修正：先明確區分「Cookie 有效期、沙盒資料保留期、鑑識封存期」。對鑑識採 append-only 分段檔／分區封存與容量警示，不可直接以 DELETE 破壞 AGENTS.md 規則；對可拋棄狀態與測試資料採定時清理。加入適當入口速率與資源限制。

驗收：以可控時間驗證過期清理；驗證持續流量下磁碟成長與警示；隔離環境不得取得鑑識資料庫的讀取／刪改權限。

### P2：部署回復只有應用版本，沒有資料庫復原

證據：[deploy_oci_commerce.py 第 96 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/scripts/deploy_oci_commerce.py#L96) 在 preview 驗收前執行 migration；[第 160 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/scripts/deploy_oci_commerce.py#L160) 失敗時只啟動前版容器。若未來 migration 與舊程式不相容，無法保證回復。preview 也共用同一個 Compose project 與資料卷，不能稱為完整藍綠部署。

修正：migration 前備份、驗證還原流程；採相容性遷移，記錄應用與 schema 版本。不要自動對正式資料執行未知的逆向 migration。

### P2：Semgrep 綠燈不是資安閘門

證據：[semgrep-scan.yml 第 44 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/.github/workflows/semgrep-scan.yml#L44) 及第 56 行使用 `|| true`；阻擋高風險 finding 的步驟仍被註解。deploy 僅依賴 commerce validation，沒有等待 Semgrep 結果。

修正：區分掃描器失敗、finding 及已接受的誘餌範例；為真正要阻擋的問題設定門檻，並讓 deploy 依賴該檢查。

### P2：鑑識內容不等於完整原始互動，也沒有完整遮罩

證據：gateway 的 capture 只保留 body／response 前 32 KiB；[第 377 行](https://github.com/IAN40070510/Mirage-Sentinel/blob/fcbea45/services/commerce/gateway.py#L377) 將 query 原樣記錄，沒有套用敏感欄位遮罩。SOC 只會顯示已手動載入的事件頁面，不是自動完整回放。

修正：記錄截斷旗標與原始長度，訂定哪些互動要保存完整內容；依政策遮罩 query 中的 token 等敏感資料；SOC 加入分頁載入／追蹤狀態提示。若需求只是「完整操作順序」而非全部 bytes，請明確註記兩者差異。

## 功能缺口，不應誤稱已完成

- **XGBoost 尚未完成新資料集訓練與準確率驗證。** Repository 只有 `model/commerce/features.json` 與 README，沒有 `xgb.json`。目前缺少模型時使用 rules_only；0.95／0.05 是規則分數，不是校準過的攻擊機率。這符合先用規則的階段決定，但專題展示必須說明。
- **預設部署未啟用 Ollama profile。** Compose 的 Ollama 使用 `profiles: [llm]`，預設腳本不啟用它。Mirage 可以使用固定模板及記憶回應；不能據此宣稱 Foundation-Sec 已參與生成。OCI 是否有人另外手動啟用模型，此次未查證。2 秒生成 timeout 在 ARM CPU 上是否足夠，也尚未量測。
- **Cookie 只辨識保留同一 Cookie 的瀏覽器。** 刪除 Cookie／使用新瀏覽器會成為新訪客，不能承諾永遠辨識同一名攻擊者。若需更強的關聯，先定義需求及誤判接受度。
- **文件已有版本落差。** 既有 migration report 仍有「尚未部署」及 SOC loopback 3100 的舊說明；部署腳本成功訊息也仍說 3100，但最新版本已改公開 3000。安全修正後要一起更新。

## 已有測試與避免誤判

- 本機上一階段 19 項 Python 測試通過；商品、會員、購物車、模擬下單、正式／沙盒 API 隔離與回訪測試通過。
- 本機正常訪客的瀏覽器流程已完成尺寸選擇、購物車、地址、運送、Manual Payment 及訂單確認；管理員登入和 `/admin/users/me`、`/app` 曾回傳 200。
- 沙盒瀏覽器測試的 `Cart item missing` 是測試腳本寫死 `Medusa Shorts`，但實際選到 `Medusa Sweatshirt`。截取內容顯示 Cart (1) 和正確商品。應修正測試比對實際選中的商品，不能直接認定沙盒購物車壞掉。沙盒完整 UI 結帳因此未完成該次測試。
- 最新 GitHub CI／OCI 部署成功是另一份證據，不代表上述所有負載、故障復原、模型或瀏覽器案例皆已驗證。
- 舊獨立 Ollama 曾發佈 11434；此次公開 HTTP 連線逾時，因此**未確認目前仍可從外網存取**，不要把它寫成已證實的現行漏洞。

## 可貼給 Copilot 的接手指令

先閱讀 AGENTS.md 與本文件，確認工作目錄是含 `.git` 的最新 Mirage-Sentinel repository。以目前 main 為基準，優先修正公開 SOC 的 HTTP Basic 傳輸，以及鑑識佇列的持久性與永久錯誤阻塞。保持正式／沙盒／鑑識資料庫隔離、append-only 鑑識、非同步記錄與非 root 唯讀容器。每項修正加上能重現故障的測試，再處理資料保留、migration 備份與 Semgrep 部署閘門。不得將本機舊下載資料夾整份覆蓋 main；不要把規則分數宣稱為 XGBoost 機率，也不要把未啟用的 LLM 宣稱為已完成。
