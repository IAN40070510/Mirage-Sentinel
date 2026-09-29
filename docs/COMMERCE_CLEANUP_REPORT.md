# 電商程式清理結果

日期：2026-09-29。本次僅修改本機程式，未推送 GitHub、未觸發 OCI 部署或操作遠端資料库。

## 已完成

- 移除 107 個列入清理清單的舊版原始檔：vuln-bank、舊 main/sandbox/core/api、舊戰情室、銀行 Compose/Nginx、安裝腳本與專屬測試/手動 CI。
- 銀行版 BANKING_API_BASE_URL、VULN_BANK_BASE_URL、banking_action 等所在的舊模組已退役；現行商品、購物車、會員、訂單由 Medusa 提供，不把銀行轉帳欄位硬改成訂單欄位。
- 現行部署只管理 mirage-commerce，不再啟停銀行容器；去除舊 SOC 停止時序及銀行 fallback，保留前一個電商 release 的應用復原。
- 保持現有電商 Compose project、服務、資料卷、Cookie、資料庫路徑及環境變數識別碼，不因名稱整理建立空資料庫或失去訪客狀態。
- 更新 README、AGENTS 的電商情境、操作手冊、資料庫/AI 文件、VS Code 測試設定及 runtime requirements。
- 根 requirements 指向電商依賴；歷史模型及其研究依賴 model/legacy-requirements.txt 保留。新版模型仍未訓練，資料集與既有修改不受刪除。
- .env.oracle.public/.soc 停止 Git 追蹤，但私有本機檔案仍在；.gitignore 加入 .env.* 排除及 example/template 例外。已提交歷史中的值並未被清除，也沒有聲稱已輪替 OCI 憑證。
- commerce-ci 執行整個 tests/，包括新增的部署成功與失敗回復測試；Semgrep setup-python 更新為 v5 以通過 actionlint。
- 兩份原始碼的待刪及待改檔案已先封裝到工作區 artifacts/local-secrets/pre-commerce-cleanup-*.zip；此路徑被忽略，內含舊配置，請勿公開或提交。這是原始碼復原快照，不是資料庫備份。

## 保留與操作界線

- 不刪 OCI 銀行 PostgreSQL、SQLite、Redis、上傳檔案、資料卷或 db-backups。
- 不刪本機資料庫、上傳資料、資料集、歷史模型；殘留目錄可能因此仍存在。
- ops/kernel、cgroup smoke 與 SecLists 工具保留為研究用途，並非現行電商必要 runtime。
- 舊版報告是歷史紀錄；其中提到的被刪檔案及舊行號不再作為當前指引。
- 沒有預設 docker-compose.yml；必須明確使用 --env-file .env.commerce -f docker-compose.commerce.yml，或使用 scripts/deploy_commerce.py。
- 部署前應確保 80/3000 沒有非電商服務占用。本次不連線 OCI；使用者提供的資料顯示舊 Nginx/SOC 已停止，其他銀行容器仍存在。

## 驗證

- 電商功能與隔離、部署成功/失敗復原：24 項 Python 測試通過。
- Python 語法、workflow YAML、runtime import 與持久資料卷名稱檢查通過。
- Docker Compose config --quiet 通過；不顯示展開後的秘密。
- 本機 Docker Desktop Linux Engine 不可連線，因此未完成 Docker 映像重建、Medusa 整合測試或 ARM/OCI 部署。
- 本機 requests 有依賴版本警告，測試仍通過；未為消除此警告而改動使用者的全域 Python 環境。

追加驗證：actionlint 通過全部四份現行 workflows；git diff --check 通過；電商 ZIP CRC 檢查通過且不含舊銀行原始碼、Git 目錄或私有環境檔。
