import json
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

from core.traffic_db import get_connection

# 模組層級快取：簽名檔案（避免重複讀檔）
_SIGNATURES_CACHE: dict[str, Any] | None = None


def _load_attack_signatures() -> dict[str, Any]:
    """從 data/attack_signatures.txt 或 .json 載入攻擊特徵簽名
    
    優先順序：
    1. attack_signatures.txt（文本格式，易於編輯）
    2. attack_signatures.json（JSON 格式，向後相容）
    
    使用模組層級快取避免重複 I/O
    """
    global _SIGNATURES_CACHE
    
    if _SIGNATURES_CACHE is not None:
        return _SIGNATURES_CACHE
    
    sig_file_txt = Path(__file__).parent.parent / "data" / "attack_signatures.txt"
    sig_file_json = Path(__file__).parent.parent / "data" / "attack_signatures.json"
    
    # 優先嘗試文本檔
    if sig_file_txt.exists():
        try:
            _SIGNATURES_CACHE = _parse_signature_txt(sig_file_txt)
            return _SIGNATURES_CACHE
        except Exception as e:
            print(f"[!] 解析文本簽名檔失敗: {e}，嘗試 JSON")
    
    # 回退 JSON
    if sig_file_json.exists():
        try:
            with open(sig_file_json, "r", encoding="utf-8") as f:
                _SIGNATURES_CACHE = json.load(f)
                return _SIGNATURES_CACHE
        except Exception as e:
            print(f"[!] 解析 JSON 簽名檔失敗: {e}，使用內建簽名")
    
    # 回退：內建簽名
    _SIGNATURES_CACHE = {
        "deep_markers": {
            "admin_endpoints": ["/api/admin", "/api/salary", "/api/internal"],
            "auth_theft": ["bearer ", "token=", "session=", "cookie:"],
            "file_operations": ["upload", "delete", "write", "chmod"],
            "rce_general": ["exec", "eval", "system"],
        },
        "tool_signatures": {
            "shell": ["shell", "cmd", "powershell", "pwsh", "bash", "sh"],
            "scanner": ["nikto", "burp", "sqlmap", "nmap"],
        },
    }
    
    return _SIGNATURES_CACHE


def _parse_signature_txt(filepath: Path) -> dict[str, Any]:
    """解析 attack_signatures.txt（INI-like 格式）
    
    格式：
    [分類名]
    簽名1, 簽名2, 簽名3, ...
    
    # 這是註解
    """
    signatures = {"deep_markers": {}, "tool_signatures": {}}
    current_category = None
    is_tool_section = False
    
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            # 略過空行和註解
            if not line or line.startswith("#"):
                continue
            
            # 檢測分類標籤 [category_name]
            if line.startswith("[") and line.endswith("]"):
                current_category = line[1:-1]
                # 判斷是否為工具簽名（根據行號推測，實際應根據上下文）
                is_tool_section = current_category not in ["admin_endpoints", "auth_theft", "file_operations", "rce_general"]
                continue
            
            # 解析簽名
            if current_category:
                # 分割並去除空白
                items = [item.strip() for item in line.split(",")]
                items = [item for item in items if item]  # 移除空白項
                
                if items:
                    if is_tool_section:
                        signatures["tool_signatures"][current_category] = items
                    else:
                        signatures["deep_markers"][current_category] = items
    
    return signatures


def parse_db_timestamp(ts: str | None) -> datetime | None:
    # 兼容兩種 DB 時間格式（含毫秒 / 不含毫秒）
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def _normalize_payload(payload: str) -> str:
    """多層消毒：URL 解碼 → 移除路徑冗余 → 小寫化
    
    防禦方法：
    - 迭代 URL 解碼（防止雙重編碼如 %252f）
    - 移除路徑遍歷（../、/./ 等）
    - 統一空白符（多空格 → 單空格）
    """
    # 迭代 URL 解碼（防止雙重編碼，最多 3 層）
    prev = payload
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(prev, errors='replace')
            if decoded == prev:
                break
            prev = decoded
        except Exception:
            break
    
    normalized = prev
    
    # 移除路徑冗余
    normalized = re.sub(r'/+', '/', normalized)  # //// → /
    normalized = re.sub(r'/\./+', '//', normalized)  # /./ → //
    normalized = re.sub(r'/[^/]+/\.\./+', '/', normalized)  # /a/.. → /
    
    # 統一空白符（多空格、Tab、換行 → 單空格）
    normalized = re.sub(r'\s+', ' ', normalized)
    
    # 十六進制解碼（如 \x2f = /）
    try:
        normalized = normalized.encode('utf-8').decode('unicode_escape', errors='replace')
    except Exception:
        pass
    
    return normalized.lower()


def _detect_attack_pattern(payload: str, tool_signatures: dict) -> tuple[bool, str]:
    """檢測是否包含已知攻擊工具或模式簽名
    
    返回：(是否匹配, 匹配的簽名類別)
    """
    normalized = _normalize_payload(payload)
    
    for category, signatures in tool_signatures.items():
        for sig in signatures:
            if sig in normalized:
                return True, category
    
    return False, ""


def _payload_complexity(payload: str) -> float:
    # 以特殊符號比例估算 payload 複雜度
    if not payload:
        return 0.0
    specials = sum(1 for ch in payload if not ch.isalnum() and not ch.isspace())
    return specials / max(len(payload), 1)


def _funnel_level(payload: str, endpoint_coverage: int, has_memory_hit: bool, attack_times: list | None = None) -> int:
    """漏斗層級判定（L1~L3），加強防禦編碼/工具化攻擊
    
    L3 觸發條件：
    - 已探索 ≥2 端點 OR
    - 包含深層攻擊標記 OR
    - 偵測到已知工具簽名 OR
    - 快速掃描紋樣（<1秒間隔 >50%）
    
    L2 觸發條件：
    - 有記憶命中（該 IP 曾進行過攻擊）
    
    L1：新手初次探測
    """
    
    # 從檔案讀取工具簽名與深層標記
    signatures = _load_attack_signatures()
    tool_signatures = signatures.get("tool_signatures", {})
    
    # 抽取所有深層標記（展平所有類別）
    deep_markers_by_category = signatures.get("deep_markers", {})
    deep_markers = set()
    for category_marks in deep_markers_by_category.values():
        deep_markers.update(category_marks)
    
    normalized = _normalize_payload(payload or "")
    
    # 條件 1：端點廣度 ≥2 → L3
    if endpoint_coverage >= 2:
        return 3
    
    # 條件 2：包含深層標記 → L3
    if any(marker in normalized for marker in deep_markers):
        return 3
    
    # 條件 3：工具簽名偵測 → L3
    is_tool_detected, category = _detect_attack_pattern(payload or "", tool_signatures)
    if is_tool_detected:
        return 3
    
    # 條件 4：快速掃描紋樣（頻率分析）→ L3
    if attack_times and len(attack_times) >= 3:
        intervals = [
            (attack_times[i+1] - attack_times[i]).total_seconds()
            for i in range(len(attack_times) - 1)
        ]
        rapid_fire_ratio = sum(1 for i in intervals if 0 < i < 1) / len(intervals)
        if rapid_fire_ratio > 0.5:  # >50% 攻擊間隔 < 1 秒 = 工具化掃描
            return 3
    
    # 條件 5：記憶命中 → L2
    if has_memory_hit:
        return 2
    
    # 預設：L1 初次探測
    return 1


def compute_interaction_metrics(
    client_ip: str,
    query_id: str,
    current_payload: str | None,
    has_memory_hit: bool,
) -> dict[str, Any]:
    """以欺敵成效量化互動深度，輸出四維度與總分。"""
    # 讀取同一攻擊者歷史攻擊資料，作為四維度評分基礎
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT t.request_at, t.query_id, d.raw_payload
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE c.ip = ? AND t.is_attack = 1
            ORDER BY t.request_at ASC
            """,
            (client_ip,),
        )
        rows = cursor.fetchall()

    attack_times = []
    query_ids = set()
    payloads = []
    for row in rows:
        ts = parse_db_timestamp(row[0])
        if ts:
            attack_times.append(ts)
        if row[1]:
            query_ids.add(row[1])
        if row[2]:
            payloads.append(row[2])

    # 停留時間：首筆攻擊到最後一筆攻擊（秒）
    if attack_times:
        first_seen = attack_times[0]
        last_seen = attack_times[-1]
        dwell_seconds = max(int((last_seen - first_seen).total_seconds()), 0)
    else:
        dwell_seconds = 0

    # 端點探索廣度：攻擊過多少不重複 query_id
    if query_id:
        query_ids.add(query_id)
    endpoint_coverage = max(len(query_ids), 1)

    if current_payload:
        payloads.append(current_payload)

    # 演化程度：同一攻擊者 payload 是否變多、變長、變複雜
    unique_payloads = len(set(payloads)) if payloads else 1
    if payloads:
        lengths = [len(p) for p in payloads]
        min_len = min(lengths)
        max_len = max(lengths)
        length_growth = max_len - min_len
        complexity_growth = max(_payload_complexity(p) for p in payloads) - min(_payload_complexity(p) for p in payloads)
    else:
        length_growth = 0
        complexity_growth = 0.0

    # 漏斗層級判定（傳入攻擊時序進行頻率分析）
    funnel_level = _funnel_level(
        current_payload or "",
        endpoint_coverage,
        has_memory_hit,
        attack_times=attack_times  # 用於檢測快速掃描紋樣
    )

    # 四維度分項分數（0~100）
    funnel_score = {1: 25, 2: 60, 3: 100}[funnel_level]
    dwell_score = min(100, int(dwell_seconds / 900 * 100))
    coverage_score = min(100, endpoint_coverage * 20)
    payload_evolution_score = min(
        100,
        int((unique_payloads - 1) * 20 + length_growth * 0.6 + complexity_growth * 100),
    )

    # 綜合深度分數：偏重攻擊鏈與停留時間，反映欺敵成功度
    depth_score = int(
        funnel_score * 0.35
        + dwell_score * 0.25
        + coverage_score * 0.20
        + payload_evolution_score * 0.20
    )

    return {
        "depth_score": depth_score,
        "funnel_level": funnel_level,
        "dwell_seconds": dwell_seconds,
        "endpoint_coverage": endpoint_coverage,
        "payload_evolution_score": payload_evolution_score,
        "funnel_score": funnel_score,
        "dwell_score": dwell_score,
        "coverage_score": coverage_score,
        "unique_payloads": unique_payloads,
    }
