# SecLists 自動更新指南

## 概述

此工具自動下載完整的 **SecLists** 開源漏洞掃描列表庫，並將其合併到 `attack_signatures.txt` 中，支援自動化與定期更新。

## 📥 快速開始

### 方式 1：使用 git clone（推薦，支援增量更新）

```bash
python scripts/update_seclists.py
```

**優點**：
- ✅ 首次克隆完整庫（約 500MB）
- ✅ 後續只同步變更（git pull）
- ✅ 支援回退、分支切換
- ⚠️ 需要安裝 git

### 方式 2：使用 wget 下載 ZIP（備用）

若無 git，腳本自動回退到 wget：

```bash
python scripts/update_seclists.py
```

**優點**：
- ✅ 無需 git
- ✅ 自動解壓
- ⚠️ 每次都重新下載完整檔案

---

## 📊 下載內容

腳本會掃描以下 SecLists 目錄：

```
SecLists/
├── Fuzzing/              → Fuzzing payload、WebShell 簽名
├── Web-Shells/           → WebShell 樣本檢測
├── Credentials/          → 常見密碼、用戶名、API keys
├── Discovery/            → 目錄、檔案名稱、虛擬主機列表
├── Passwords/            → 密碼字典
├── Usernames/            → 用戶名字典
└── Payloads/             → 各類 payload
```

合併後的簽名：
- **原有簽名**：95 個標記 + 272 個工具簽名
- **SecLists 簽名**：+100~200 個分類
- **總計**：超過 500+ 個分類簽名

---

## ⏰ 定期自動更新

### Windows（使用 Task Scheduler）

```batch
# 1. 開啟 Task Scheduler
tasksched.msc

# 2. 建立基本任務
# 名稱: Update-Mirage-SecLists
# 觸發條件: 每週一次（例如週一 02:00）

# 3. 操作
# 程式: C:\Users\Ian\Desktop\Mirage-Sentinel\.venv\Scripts\python.exe
# 引數: scripts\update_seclists.py
# 開始位置: C:\Users\Ian\Desktop\Mirage-Sentinel
```

### Linux / macOS（使用 cron）

```bash
# 編輯 crontab
crontab -e

# 每週日 2:00 執行
# 0 2 * * 0 cd /path/to/Mirage-Sentinel && python scripts/update_seclists.py
```

### Windows PowerShell（計劃工作 XML）

```powershell
# 建立排程工作
$taskName = "Update-Mirage-SecLists"
$taskPath = "C:\Users\Ian\Desktop\Mirage-Sentinel"
$pythonPath = "$taskPath\.venv\Scripts\python.exe"
$scriptPath = "$taskPath\scripts\update_seclists.py"

$action = New-ScheduledTaskAction -Execute $pythonPath -Argument $scriptPath -WorkingDirectory $taskPath
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am
$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -AsJob
```

---

## 📁 輸出結果

執行後會生成/更新：

```
data/
├── attack_signatures.txt       ← 文本格式（易編輯）
├── attack_signatures.json      ← JSON 格式（向後相容）
└── datasets/
    └── SecLists/               ← 完整 SecLists 庫（首次下載）
        ├── Fuzzing/
        ├── Web-Shells/
        ├── Credentials/
        └── ...
```

---

## 🔍 簽名檔內容示例

```ini
# attack_signatures.txt

[admin_endpoints]
/api/admin, /admin, /administrator, ...

[fuzzing_common]
../../../etc/passwd, ..%2f..%2f..%2fetc%2fpasswd, ...

[web_shells]
c99, c100, shell.php, shell.asp, ...

[passwords_common]
password, 123456, admin, root, ...

[cve_payloads]
cve-2021-44228, log4j, struts2, ...
```

---

## 🛠️ 進階用法

### 只下載不生成簽名

```bash
python scripts/update_seclists.py --download-only
```

### 強制重新下載（忽略已存在）

```bash
python scripts/update_seclists.py --force
```

### 只生成簽名（不下載）

```bash
python scripts/update_seclists.py --no-download
```

### 自訂輸出路徑

```bash
python scripts/update_seclists.py --output /custom/path/attack_signatures.txt
```

---

## 📊 簽名統計

執行後會輸出：

```
[統計]
  深層標記: 95
  工具簽名: 500+
  分類數: 123+
  總計: 595+
```

---

## ⚠️ 注意事項

### 磁碟空間
- SecLists 完整庫：**~500MB**
- 建議預留：**1GB**

### 網路
- 首次下載需要穩定網路
- 推薦在非工作時間執行

### 效能
- 首次掃描所有 .txt 檔案需要數分鐘
- 後續更新（git pull）通常 < 1 分鐘

### 許可證
- SecLists：CC0（公共領域）
- 可自由使用、修改、分發

---

## 🔧 故障排除

### 問題 1：找不到 git

**症狀**：
```
! 未檢測到 git，嘗試 wget 下載...
```

**解決**：
- 安裝 git：https://git-scm.com/download
- 或確保 git 在 PATH 中

### 問題 2：wget 不可用

**症狀**：
```
✗ 下載失敗
```

**解決**（Windows）：
```powershell
# 使用 curl 替代
# 腳本已內建備用方案
```

### 問題 3：磁碟空間不足

**解決**：
```bash
# 清理舊簽名
rm data/datasets/SecLists -r
python scripts/update_seclists.py
```

### 問題 4：簽名檔太大

**症狀**：
```
attack_signatures.txt 超過 10MB
```

**解決**：
- 腳本已限制每分類 100 個簽名
- 可進一步調整 `scripts/update_seclists.py` 第 176 行

---

## 📚 相關資源

- **SecLists 官網**：https://github.com/danielmiessler/SecLists
- **OWASP 攻擊向量**：https://owasp.org
- **Payload 參考**：https://github.com/swisskyrepo/PayloadsAllTheThings

---

## 📝 版本歷史

| 版本 | 日期 | 內容 |
|------|------|------|
| 1.0 | 2026-03-28 | 初始版本，支援 git/wget |
