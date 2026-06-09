# cgroup v2 設計說明（MSDSS）

本文檔說明在 MirSen Defense System (MSDSS) 中採用 Linux cgroup v2 作為沙盒資源限制與保護的設計要點、範例與測試計畫。

目的
- 在 Kernel 層限制高風險或偽裝流程的資源使用（CPU / memory / PIDs / I/O / cpuset），避免惡意請求或測試流程耗盡宿主資源。
- 提供可被自動化腳本與 CI 驗證的建立流程，並方便與監控整合。

分群策略
- 建議依服務角色建立 cgroup：`gateway`、`sandbox`、`mirage`、`soc`。
- 對於高風險請求，將處理流程移入 `sandbox` 群組；一般請求維持在 `gateway` 或 `mirage`（視 policy）。

主要限制項目
- CPU：`cpu.max`（quota/period）或透過 runtime flag (`--cpus`) 設定。
- Memory：`memory.max`、`memory.high`、`memory.swap.max`。
- PIDs：`pids.max`。
- I/O：`io.max`（major:minor rbps/wbps 或 iops 限制）。
- Cpuset：`cpuset.cpus` / `cpuset.mems`（若需隔離 CPU）。

部署模式
- 宿主機腳本（推薦）：由 `ops/create_cgroups.sh` 在宿主機建立並管理 cgroup。適合生產/測試環境精準控制。
- Container runtime：Compose 的 `sandbox` 服務已設定 `cgroup: private`、`cpus: 0.20`、`mem_limit: 256m`、`memswap_limit: 256m`、`pids_limit: 64`，由 Docker runtime 映射到 cgroup v2 控制器。
- 資料隔離：Compose 的 `sandbox` 服務使用專用 `sandbox_memory` volume 掛載 `/app/data`，只保存可拋棄的 `mirage_memory.db`，避免直接掛載鑑識資料目錄。
- Kernel Programming：`ops/kernel/sandbox_cgroup_audit.c` 提供可選 Linux Kernel Module，透過 procfs 暴露 `/proc/sandbox_cgroup_audit`，用於稽核 sandbox cgroup v2 policy 與 kernel timestamp。

參考數值（初始建議，可依 CI 與壓力測試調整）
- `sandbox`：memory.max=256M, pids.max=64, cpu 20%（quota 20000/period 100000）
- `mirage`：memory.max=512M, pids.max=128, cpu 40%
- `gateway`：memory.max=1G, pids.max=512, cpu 60%

操作範例
請參考 `ops/create_cgroups.sh`，該腳本會檢查 cgroup v2 是否掛載，建立群組目錄並寫入屬性。

監控與告警
- 建議收集的指標：`memory.current`、`memory.max`、`cpu.stat`、`io.stat`、`cgroup.events`、PSI 指標 (`/proc/pressure/*`)。
- 可使用 node_exporter 的 cgroup collector 或自建 exporter 將上述指標推送到 Prometheus。
- 若作業或實驗環境允許載入 kernel module，可使用 `ops/kernel/` 的 procfs audit module 取得 kernel-space 稽核輸出。

測試計畫
- `tests/cgroup_smoke.sh`：建立測試 cgroup，執行記憶體/CPU/IO 負載（使用 Python 或 `stress`），驗證限制是否生效並檢查 OOM/限制事件。
- 在 CI 中加入 smoke 測試，以確保變更不會破壞限制行為。

安全與運維注意事項
- 預設採取保守限制，避免過嚴設定導致正常服務失效。
- 明確記錄誰能修改 cgroup（Unix 權限 / 操作流程）與變更流程（PR + Review）。
- 日誌與告警必須能追溯到觸發限制的請求或 Session ID，以便 SOC 分析。

Git 分工建議
- `feature/cgroup-design`：撰寫文件（本檔）與設計討論。
- `feature/cgroup-scripts`：實作 `ops/create_cgroups.sh`、`tests/cgroup_smoke.sh`。
- `feature/container-integration`：已在 `docker-compose.yml`、`docker-compose.oracle.yml`、`docker-compose.oracle.dual-demo.yml` 的 `sandbox` 服務加入 cgroup v2 runtime 限制。
`feature/kernel-audit-module`：實作 `ops/kernel/sandbox_cgroup_audit.c`，提供 Kernel Programming 證據與 host-side audit surface。

--
作者：MSDSS 團隊
日期：2026-06-01
