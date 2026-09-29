# 電商遷移與舊版程式清理檢查

檢查日期：2026-09-29（Asia/Taipei）。本次僅檢查與新增此報告，未刪除程式、資料庫、Docker volumes，未推送或部署。

## 範圍與結論

- 工作區外層是下載副本；`artifacts/publish-repo` 才是 Git checkout。兩者的 main.py、電商偵測器、測試、模型契約及 README 已有差異，不可直接覆蓋或視為完全重複。
- Git checkout 有既存未提交修改，以及未追蹤的資料集、資料生成與驗證程式。因此不可整個刪除 artifacts。
- 本機 workflow 的正式入口是 `.github/workflows/deploy.yml` → commerce-ci.yml → scripts/deploy_oci_commerce.py → docker-compose.commerce.yml。
- 電商 Python 映像只複製 services/__init__.py 與 services/commerce；未把舊 main.py、core、api、frontend 或 vuln-bank-main 放進該映像。
- 舊程式不是全部無人引用：舊 Compose、手動工作流程、舊測試與文件仍引用它們。應以「不屬於目前電商執行路徑」判斷退役範圍，不能宣稱每個函式都是死碼。
- 沒有確認 OCI 當下實際容器與遠端最新 commit；本報告以本機程式和部署設定為準。

## 優先修改

### 1. 修正首次切換時的 SOC 埠衝突

`scripts/deploy_oci_commerce.py:55` 設定 SOC_PORT=3000；該腳本先呼叫 deploy_commerce.py --preview，再於約第 143–149 行停止 mirage_sentinel_frontend_soc。

但 `scripts/deploy_commerce.py:134` 的 preview 分支已啟動 collector，而 Compose 的 collector 會發布 SOC_PORT。若舊 SOC 還占用 3000，新版啟動可能在停止舊版之前就失敗。

建議讓 preview 不發布正式 SOC 埠，通過驗證後才切換；或在切換時明確停止舊 SOC，並將恢復舊 SOC 納入失敗復原。不能只調換一行而忽略復原。

同一腳本約第 154 行仍印出 3100/SSH tunnel 提示，但目前 Compose 預設為 0.0.0.0:3000，應同步修正說明。

### 2. 更新預設入口與文件

根目錄 README 仍說 main.py、vuln-bank-main、金融 API 與旧 SOC 是目前架構；AGENTS.md、AI_AGENT_README.md 及銀行相關文件也需整理成現行電商與歷史版說明。

根目錄 docker-compose.yml 仍啟動舊 main.py 與 sandbox_service.py，容易讓 `docker compose up` 啟動錯版。建議將預設入口統一為電商，舊版改由封存版本保留。

### 3. 凭證與打包

`.env.oracle.public`、`.env.oracle.soc` 已被 Git 追蹤；舊 Nginx 設定存在寫死的 API key。應停止追蹤部署實值、保留 example，輪替仍有效的值。停止追蹤並不能清除歷史紀錄。

舊根 Dockerfile 使用 COPY . .，沒有根 .dockerignore 或 Dockerfile.dockerignore。若保留此建置入口，必須排除 Git、秘密、資料庫與本機產物；若電商已完全取代它，則隨舊入口一起退役。

## 可退役的舊版群組

以下以不再需要啟動銀行版為前提；先保留可追溯的歷史版本及必要資料，再同步移除引用。

| 群組 | 檔案或目錄 | 理由與相依性 |
| --- | --- | --- |
| 銀行應用 | vuln-bank-main/ | 電商使用 commerce/ 的 Medusa 與 storefront；舊 Oracle Compose 仍引用銀行應用，需一起處理。 |
| 舊 Gateway / 沙盒 | main.py、sandbox_service.py | 電商入口為 services.commerce.gateway、mirage、collector，不能只替換舊 URL 就視為完成遷移。 |
| 舊防禦 / 資料 API | core/、api/、services/dashboard_service.py | 本次檢查未見電商執行模組 import 它們；舊測試、sanity_checks 與舊日誌工具仍依賴它們。若保留歷史鑑識查詢，需另留讀取工具。 |
| 舊前端 | frontend/ | 電商購物站在 commerce/apps/storefront；新版 SOC 使用 services/commerce/soc.html。刪除前應確認舊 SOC 專有報表是否仍是專題需求。 |
| 舊部署 | docker-compose.yml、docker-compose.oracle.yml、docker-compose.oracle.dual-demo.yml、根 Dockerfile、deploy/nginx/ | 舊銀行啟動與路由設定；新版使用 docker-compose.commerce.yml、deploy/commerce/。不要刪除新版目錄。 |
| 舊安装腳本 | scripts/setup_vuln_bank.sh、scripts/setup_vuln_bank.ps1 | 僅用於取得並安裝舊銀行應用。 |
| 舊 CI / 驗證 | .github/workflows/pr-smoke.yml、scripts/ci/ 中銀行測試、根目錄 test_*.py | pr-smoke 仍可手動啟動舊堆疊；刪舊程式時需同步退役或把有效驗證情境改寫到電商測試。 |
| 舊環境依賴 | requirements.txt、requirements.runtime.txt | 目前電商映像使用 deploy/commerce/requirements.txt；舊版含 TensorFlow、Torch 等依賴。若保存舊訓練實驗，應保留獨立研究環境，不能未檢查用途就全刪。 |

不建議把 core/mirage.py 的 banking 字樣全域取代為 commerce：舊版帳戶、轉帳、餘額與模板契約，不等於商品、購物車、會員與訂單 API。

## 可清理但要辨別用途

- `.pytest_cache`、`.ruff_cache`、`__pycache__`、*.pyc 是可重建快取；本次未執行刪除。
- 舊測試報告、封裝 ZIP 可在確認可重建及不需留作專題證據後移除。
- 不要把 artifacts 整個刪掉：其下包含真正 Git checkout 與未提交成果。
- 不要以 transfer、bank 等關鍵字直接批次刪除 Medusa 程式：訂單所有權轉移、登入後購物車轉移及付款流程是合法電商功能。

## 必須保留或先完成替代

- commerce/、services/commerce/、deploy/commerce/、docker-compose.commerce.yml。
- commerce-ci.yml、deploy.yml、post-deploy-smoke.yml 及 prepare/deploy/deploy_oci/wait/smoke_commerce 腳本。
- services/__init__.py：仍被新版 Dockerfile 複製。
- tests/test_commerce.py、資料集與其生成、整合、驗證、品質檢查工具。
- model/commerce/features.json：當前推論契約所需。
- model/Sentinel/XGBoost/：目前不被電商 Gateway 使用，但包含歷史模型、前處理產物與研究程式；宜先封存作比較基準，不直接刪除。當前 model/commerce 沒有 xgb.json，因此新版仍以規則判斷，不能因已有資料集就宣稱訓練完成。
- 舊鑑識紀錄、模型實驗紀錄、既存数据库與 Docker volumes 不在程式清理範圍。若保存舊紀錄，留獨立的唯讀查詢或匯出途徑，不能將其接回誘餌權限。
- deploy_oci_commerce.py 對舊容器的停止/復原邏輯仍具有遷移用途；確認 OCI 已完成切換後，才將它與正常電商更新流程分離。

## CI 與驗證補強

- Semgrep 仍掃描整個含有故意脆弱銀行應用的 repository，且部署未依賴其結果。應把退役應用與現行應用的檢查範圍區分清楚，不直接關掉安全掃描。
- post-deploy-smoke 只檢查首頁與 /store/regions，不驗證 SOC、會話隔離或購物流程；不能把此檢查成功視為完整上線驗證。
- 本次執行 Git checkout 的 `python -m pytest tests/test_commerce.py -q`：22 passed，13.08 秒。環境另出現 requests 依賴版本警告，未造成測試失敗。
- 本次未執行 Docker 建置、完整 Medusa 整合測試或 OCI 部署；22 項測試不能證明刪除後部署一定成功。

## 建議順序

1. 確立唯一工作 checkout，保留兩份目錄的差異及未提交成果。
2. 修正部署 SOC 衝突、過期操作說明與憑證處理。
3. 建立銀行版歷史封存，確認舊報表需求與資料保存方式。
4. 同一批變更退役銀行應用、舊入口、其專屬依賴、CI、測試及文件引用。
5. 檢查剩餘引用，執行電商 Python 測試、Docker/ARM 建置、購物及分流驗證，再經現有 OCI 工作流程發布。

清理需維持正式與誘餌資料庫隔離、鑑識 append-only 與非同步寫入、毫秒時間戳，以及容器 non-root/read-only/cap_drop 設定。
