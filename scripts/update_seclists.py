#!/usr/bin/env python3
"""
自動下載並整合完整 SecLists
支援增量更新，避免重複下載
"""

import json
import argparse
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from urllib.request import urlopen
from urllib.error import URLError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SECLISTS_DIR = DATA_DIR / "datasets" / "SecLists"
PAYLOADS_DIR = DATA_DIR / "payloads"

SECLISTS_REPO = "https://github.com/danielmiessler/SecLists.git"
SECLISTS_ZIP = "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip"


def _file_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _make_backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup_dir = DATA_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"{path.stem}_{timestamp}{path.suffix}"
    shutil.copy2(path, backup_path)
    return backup_path

def has_git() -> bool:
    """檢查系統是否安裝 git"""
    try:
        result = subprocess.run(["git", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False

def download_seclists_with_git() -> bool:
    """使用 git clone 下載 SecLists（推薦，支援增量更新）"""
    try:
        print(f"[*] 使用 git clone 下載 SecLists...")
        print(f"    目標: {SECLISTS_REPO}")
        print(f"    到: {SECLISTS_DIR}")
        print(f"    (首次下載需要時間，大約 500MB+)")
        
        # 如果已存在，則更新
        if SECLISTS_DIR.exists():
            print(f"    [!] 目錄已存在，執行 git pull 更新...")
            result = subprocess.run(
                ["git", "-C", str(SECLISTS_DIR), "pull"],
                capture_output=True,
                timeout=300
            )
            if result.returncode != 0:
                print(f"    ✗ 更新失敗: {result.stderr.decode()}")
                return False
            print(f"    ✓ 更新完成")
        else:
            # 首次克隆
            result = subprocess.run(
                ["git", "clone", "--depth", "1", SECLISTS_REPO, str(SECLISTS_DIR)],
                capture_output=True,
                timeout=600
            )
            if result.returncode != 0:
                print(f"    ✗ 克隆失敗: {result.stderr.decode()}")
                return False
            print(f"    ✓ 克隆完成")
        
        return True
    except subprocess.TimeoutExpired:
        print(f"    ✗ 下載超時")
        return False
    except Exception as e:
        print(f"    ✗ 錯誤: {e}")
        return False

def download_seclists_with_wget() -> bool:
    """備用方案：使用 wget 下載 ZIP（較慢，但通用性強）"""
    try:
        print(f"[*] 使用 wget 下載 SecLists ZIP...")
        print(f"    URL: {SECLISTS_ZIP}")
        
        zip_path = DATA_DIR / "SecLists-master.zip"
        
        result = subprocess.run(
            ["wget", "-O", str(zip_path), SECLISTS_ZIP],
            capture_output=True,
            timeout=600
        )
        
        if result.returncode != 0:
            print(f"    ✗ 下載失敗")
            return False
        
        print(f"    ✓ 下載完成，解壓中...")
        
        # 解壓
        shutil.unpack_archive(str(zip_path), str(DATA_DIR / "datasets"))
        
        # 重命名
        extracted = DATA_DIR / "datasets" / "SecLists-master"
        if extracted.exists() and not SECLISTS_DIR.exists():
            extracted.rename(SECLISTS_DIR)
        
        # 刪除 ZIP
        zip_path.unlink()
        
        print(f"    ✓ 解壓完成")
        return True
    except Exception as e:
        print(f"    ✗ 錯誤: {e}")
        return False

def extract_payloads_from_seclists() -> dict:
    """遞歸掃描 SecLists 所有 .txt 檔案並提取簽名"""
    print(f"\n[+] 掃描 SecLists...")
    signatures = {}
    
    if not SECLISTS_DIR.exists():
        print(f"  ! 目錄不存在")
        return signatures
    
    # 統計
    total_files = 0
    total_payloads = 0
    
    # 主要掃描目錄
    scan_dirs = [
        "Fuzzing",
        "Web-Shells",
        "Credentials",
        "Discovery",
        "Passwords",
        "Usernames",
        "Payloads",
    ]
    
    for scan_dir_name in scan_dirs:
        scan_dir = SECLISTS_DIR / scan_dir_name
        if not scan_dir.exists():
            continue
        
        print(f"  - 掃描: {scan_dir_name}/")
        
        for txt_file in scan_dir.rglob("*.txt"):
            total_files += 1
            category = txt_file.stem.lower()
            
            try:
                payloads = []
                with open(txt_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        # 排除空行、註解、太短的項目
                        if line and not line.startswith("#") and len(line) > 2:
                            payloads.append(line.lower())
                
                if payloads:
                    # 去重並限制數量（避免檔案過大）
                    payloads = list(set(payloads))[:200]
                    if category not in signatures:
                        signatures[category] = []
                    signatures[category].extend(payloads)
                    total_payloads += len(payloads)
            except Exception as e:
                print(f"      ! 讀取 {txt_file.name} 失敗: {e}")
    
    # 去重合併
    for category in signatures:
        signatures[category] = list(set(signatures[category]))[:200]
    
    print(f"  ✓ 完成: {total_files} 個檔案, {total_payloads} 個 payloads")
    
    return signatures

def build_complete_signatures() -> dict:
    """構建完整簽名（包含 SecLists）"""
    print(f"\n[*] 構建完整簽名庫...")
    
    # 基礎簽名
    base_signatures = {
        "deep_markers": {
            "admin_endpoints": [
                "/api/admin", "/api/salary", "/api/internal",
                "/admin", "/administrator", "/wp-admin",
                "/user/admin", "/account/admin", "/admin.php", "/admin.aspx", "/admin.jsp",
                "/superadmin", "/sysadmin", "/staff", "/panel", "/backend"
            ],
            "auth_theft": [
                "bearer ", "token=", "session=", "cookie:",
                "authorization:", "x-api-key", "x-token", "x-auth-token",
                "api-key=", "auth:", "jwt=", "refresh_token=", "access_token="
            ],
            "file_operations": [
                "upload", "delete", "write", "chmod",
                "file_put_contents", "fopen", "fwrite", "mkdir", "rmdir"
            ],
            "rce_general": [
                "exec", "eval", "system", "passthru",
                "proc_open", "shell_exec", "pcntl_exec", "command", "invoke"
            ]
        },
        "tool_signatures": {
            "shell": [
                "shell", "cmd", "powershell", "pwsh",
                "bash", "sh", "zsh", "ksh", "csh", "tcsh", "mksh", "ash", "dash"
            ],
            "script_interpreters": [
                "perl", "python", "ruby", "php", "node", "java",
                "python3", "lua", "groovy", "scala"
            ],
            "shell_paths": [
                "/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/python",
                "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/env"
            ],
            "exec": [
                "exec", "eval", "system", "passthru", "proc_open",
                "execute", "shell_exec", "popen"
            ],
            "scanner": [
                "nikto", "burp", "sqlmap", "nmap", "masscan", "zap",
                "metasploit", "hydra", "acunetix", "qualys"
            ],
            "rce": [
                "nc ", "ncat ", "netcat", "bash -i", "/bin/bash",
                "socat", "telnet"
            ]
        }
    }
    
    # 合併 SecLists 簽名
    seclists_sigs = extract_payloads_from_seclists()
    if seclists_sigs:
        base_signatures["tool_signatures"].update(seclists_sigs)
        print(f"  ✓ 合併 {len(seclists_sigs)} 個 SecLists 分類")
    
    return base_signatures

def save_signatures_as_txt(signatures: dict, filepath: Path) -> None:
    """儲存為文本格式"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# 深層攻擊標記庫 (包含 SecLists)\n")
        f.write("# 最後更新: " + str(Path(filepath).stat().st_mtime) + "\n")
        f.write("# 格式：[分類] 標記 1, 標記 2, ...\n\n")
        
        # 深層標記
        for category, items in signatures.get("deep_markers", {}).items():
            f.write(f"[{category}]\n")
            f.write(", ".join(items) + "\n\n")
        
        f.write("# 工具簽名庫\n\n")
        
        # 工具簽名
        for category, items in signatures.get("tool_signatures", {}).items():
            f.write(f"[{category}]\n")
            f.write(", ".join(items[:100]) + "\n\n")  # 限制每個分類 100 個

def main():
    parser = argparse.ArgumentParser(description="SecLists 自動下載與簽名更新工具")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="實際寫入 data/attack_signatures.(txt|json)。未提供時只預覽差異，不會覆寫檔案。",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("SecLists 自動下載與簽名更新工具")
    print("=" * 70)
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "datasets").mkdir(parents=True, exist_ok=True)
    
    # 第一步：下載 SecLists
    print("\n[步驟 1] 下載 SecLists...")
    
    if has_git():
        print("  ✓ 檢測到 git，使用 git clone...")
        success = download_seclists_with_git()
    else:
        print("  ! 未檢測到 git，嘗試 wget 下載...")
        success = download_seclists_with_wget()
    
    if not success:
        print("  ✗ 下載失敗，使用備用簽名")
    
    # 第二步：構建簽名
    print("\n[步驟 2] 構建完整簽名庫...")
    signatures = build_complete_signatures()
    
    # 第三步：產生輸出內容（預設不覆寫）
    print(f"\n[步驟 3] 產生簽名輸出...")
    output_json = DATA_DIR / "attack_signatures.json"
    output_txt = DATA_DIR / "attack_signatures.txt"

    new_json = json.dumps(signatures, indent=2, ensure_ascii=False)
    temp_txt = DATA_DIR / "._attack_signatures_preview.txt"
    save_signatures_as_txt(signatures, temp_txt)
    new_txt = _file_text(temp_txt)
    if temp_txt.exists():
        temp_txt.unlink()

    old_json = _file_text(output_json)
    old_txt = _file_text(output_txt)

    json_changed = old_json != new_json
    txt_changed = old_txt != new_txt

    print(f"  - JSON 變更: {'是' if json_changed else '否'}")
    print(f"  - TXT 變更: {'是' if txt_changed else '否'}")

    if not args.apply:
        print("\n[安全模式] 未提供 --apply，本次不會覆寫任何檔案。")
        print("如需寫入請執行: python scripts/update_seclists.py --apply")
    else:
        print("\n[寫入模式] 開始備份並寫入...")
        backup_json = _make_backup(output_json)
        backup_txt = _make_backup(output_txt)

        output_json.write_text(new_json, encoding="utf-8")
        output_txt.write_text(new_txt, encoding="utf-8")

        print(f"  ✓ JSON: {output_json}")
        print(f"  ✓ 文本: {output_txt}")
        if backup_json:
            print(f"  ✓ JSON 備份: {backup_json}")
        if backup_txt:
            print(f"  ✓ TXT 備份: {backup_txt}")
    
    # 統計
    print(f"\n[統計]")
    total_deep = sum(len(v) for v in signatures.get("deep_markers", {}).values())
    total_tools = sum(len(v) for v in signatures.get("tool_signatures", {}).values())
    print(f"  深層標記: {total_deep}")
    print(f"  工具簽名: {total_tools}")
    print(f"  分類數: {len(signatures.get('tool_signatures', {}))}")
    print(f"  總計: {total_deep + total_tools}")
    
    print(f"\n[✓] 完成!")
    print(f"\n定期更新提示：")
    print(f"  python scripts/update_seclists.py  (日常更新)")
    print(f"  或在 cron/task scheduler 中設定定時執行")

if __name__ == "__main__":
    main()
