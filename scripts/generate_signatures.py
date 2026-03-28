#!/usr/bin/env python3
"""
自動下載並整合開源攻擊簽名庫
支援：SecLists、PayloadsAllTheThings
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
SECLISTS_DIR = DATA_DIR / "datasets" / "SecLists"
PAYLOADS_DIR = DATA_DIR / "payloads"

def download_file(url: str, dest_path: Path) -> bool:
    """下載檔案"""
    try:
        print(f"[*] 下載: {url}")
        with urlopen(url, timeout=10) as response:
            content = response.read().decode("utf-8", errors="replace")
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"    ✓ 完成 -> {dest_path}")
        return True
    except URLError as e:
        print(f"    ✗ 失敗: {e}")
        return False

def extract_payloads_from_file(filepath: Path, category: str) -> list[str]:
    """從檔案中提取 payload（排除註解和空行）"""
    payloads = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                # 排除空行和註解
                if line and not line.startswith("#") and not line.startswith("//"):
                    payloads.append(line.lower())
    except Exception as e:
        print(f"  ! 讀取 {filepath} 失敗: {e}")
    
    return list(set(payloads))  # 去重

def parse_seclists() -> dict:
    """解析 SecLists 檔案"""
    print("\n[+] 解析 SecLists...")
    signatures = {}
    
    if not SECLISTS_DIR.exists():
        print("  ! SecLists 目錄不存在，略過")
        return signatures
    
    # 掃描 Fuzzing 目錄
    fuzzing_dir = SECLISTS_DIR / "Fuzzing"
    if fuzzing_dir.exists():
        print(f"  - 掃描: {fuzzing_dir}")
        for file in fuzzing_dir.glob("*.txt"):
            category = file.stem.lower()
            payloads = extract_payloads_from_file(file, category)
            if payloads:
                signatures[category] = payloads[:100]  # 限制數量
                print(f"    ✓ {category}: {len(payloads)} 條")
    
    # Web-Shells
    shells_dir = SECLISTS_DIR / "Web-Shells"
    if shells_dir.exists():
        print(f"  - 掃描: {shells_dir}")
        shells = []
        for file in shells_dir.glob("**/*.txt"):
            payloads = extract_payloads_from_file(file, "shells")
            shells.extend(payloads)
        if shells:
            signatures["webshells"] = list(set(shells))[:50]
            print(f"    ✓ webshells: {len(shells)} 條")
    
    return signatures

def parse_payloads_all_the_things() -> dict:
    """解析 PayloadsAllTheThings 目錄（如果已下載）"""
    print("\n[+] 解析 PayloadsAllTheThings...")
    signatures = {}
    
    if not PAYLOADS_DIR.exists():
        print("  ! 目錄不存在，略過")
        return signatures
    
    # 掃描所有 .md 檔案中的代碼塊
    for md_file in PAYLOADS_DIR.glob("**/*.md"):
        content = md_file.read_text(encoding="utf-8", errors="replace")
        
        # 提取代碼塊中的 payload
        # 格式: ```<lang> ... ```
        code_blocks = re.findall(r"```(?:\w+)?\n(.*?)\n```", content, re.DOTALL)
        
        category = md_file.parent.name.lower()
        payloads = []
        for block in code_blocks:
            for line in block.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append(line.lower())
        
        if payloads:
            signatures[category] = list(set(payloads))[:50]
    
    return signatures

def build_attack_signatures() -> dict:
    """構建完整的 attack_signatures.json"""
    print("\n[*] 構建攻擊簽名庫...")
    
    # 基礎簽名
    base_signatures = {
        "deep_markers": {
            "admin_endpoints": [
                "/api/admin", "/api/salary", "/api/internal",
                "/admin", "/administrator", "/wp-admin",
                "/user/admin", "/account/admin"
            ],
            "auth_theft": [
                "bearer ", "token=", "session=", "cookie:",
                "authorization:", "x-api-key", "x-token"
            ],
            "file_operations": [
                "upload", "delete", "write", "chmod",
                "file_put_contents", "fopen", "fwrite"
            ],
            "rce_general": [
                "exec", "eval", "system", "passthru",
                "proc_open", "shell_exec", "pcntl_exec"
            ]
        },
        "tool_signatures": {
            "shell": [
                "shell", "cmd", "powershell", "pwsh",
                "bash", "sh", "zsh", "ksh", "csh", "tcsh",
                "mksh", "ash", "dash", "command.com"
            ],
            "script_interpreters": [
                "perl", "python", "ruby", "php", "node",
                "java", "python3", "perl5", "ruby2"
            ],
            "shell_paths": [
                "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ksh",
                "/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
                "/bin/ash", "/bin/dash", "/bin/tcsh",
                "/usr/local/bin/python3", "/usr/bin/env"
            ],
            "script_tags": [
                "cscript", "wscript", "jscript", "vbscript"
            ],
            "exec": [
                "exec", "eval", "system", "passthru",
                "proc_open", "execute", "shell_exec", "popen"
            ],
            "scanner": [
                "nikto", "burp", "sqlmap", "nmap",
                "masscan", "zap", "metasploit", "hydra",
                "acunetix", "qualys", "rapid7", "tenable"
            ],
            "rce": [
                "nc ", "ncat ", "netcat", "bash -i",
                "/bin/bash", "/bin/sh", "socat", "telnet"
            ],
            "path_trick": [
                "..%2f", "%2e%2e", "..%5c", "%2e%2e%2f",
                "..\\", "..%5c%5c", "%2e%2e%2f%2e%2e"
            ]
        }
    }
    
    # 合併來自 SecLists 的簽名
    seclists_sigs = parse_seclists()
    if seclists_sigs:
        if "tool_signatures" not in base_signatures:
            base_signatures["tool_signatures"] = {}
        base_signatures["tool_signatures"].update(seclists_sigs)
    
    # 合併來自 PayloadsAllTheThings 的簽名
    payloads_sigs = parse_payloads_all_the_things()
    if payloads_sigs:
        if "tool_signatures" not in base_signatures:
            base_signatures["tool_signatures"] = {}
        base_signatures["tool_signatures"].update(payloads_sigs)
    
    return base_signatures

def main():
    print("=" * 60)
    print("攻擊簽名庫生成器")
    print("=" * 60)
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # 嘗試下載 PayloadsAllTheThings
    print("\n[+] 下載 PayloadsAllTheThings...")
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
    
    # 下載關鍵檔案
    payloads_files = [
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md", "payloads/SQL_Injection.md"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md", "payloads/Command_Injection.md"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Web%20Shell/README.md", "payloads/Web_Shell.md"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Path%20Traversal/README.md", "payloads/Path_Traversal.md"),
    ]
    
    for url, local_path in payloads_files:
        download_file(url, DATA_DIR.parent / local_path)
    
    # 構建簽名
    signatures = build_attack_signatures()
    
    # 儲存為 JSON
    output_json = DATA_DIR / "attack_signatures.json"
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(signatures, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] JSON: {output_json}")
    
    # 儲存為文本（易於編輯）
    output_txt = DATA_DIR / "attack_signatures.txt"
    save_signatures_as_txt(signatures, output_txt)
    print(f"[✓] 文本: {output_txt}")
    
    # 統計
    total_markers = sum(len(v) for v in signatures.get("deep_markers", {}).values())
    total_tools = sum(len(v) for v in signatures.get("tool_signatures", {}).values())
    print(f"\n統計:")
    print(f"  深層標記: {total_markers} 個")
    print(f"  工具簽名: {total_tools} 個")
    print(f"  分類: {len(signatures.get('tool_signatures', {}))} 項")


def save_signatures_as_txt(signatures: dict, filepath: Path) -> None:
    """將簽名字典儲存為文本格式（INI-like）
    
    格式：
    [分類]
    簽名1, 簽名2, ...
    """
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# 深層攻擊標記庫\n")
        f.write("# 格式：[分類] 標記 1, 標記 2, 標記 3, ...\n")
        f.write("# 使用逗號分隔，#開頭的行被視為註解\n\n")
        
        # 深層標記
        for category, items in signatures.get("deep_markers", {}).items():
            f.write(f"[{category}]\n")
            f.write(", ".join(items) + "\n\n")
        
        f.write("# 工具簽名庫\n\n")
        
        # 工具簽名
        for category, items in signatures.get("tool_signatures", {}).items():
            f.write(f"[{category}]\n")
            f.write(", ".join(items) + "\n\n")

if __name__ == "__main__":
    main()
