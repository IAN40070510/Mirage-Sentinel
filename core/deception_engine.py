import json
import re
import urllib.parse
from datetime import datetime
from pathlib import Path

from core.traffic_db import get_connection


# 模組層級快取：簽名檔案（避免重複讀檔）
_signatures_cache: dict[str, dict[str, list[str]]] | None = None


def _default_signatures() -> dict[str, dict[str, list[str]]]:
    return {
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


def _merge_signatures(
    base: dict[str, dict[str, list[str]]], incoming: dict[str, dict[str, list[str]]]
) -> dict[str, dict[str, list[str]]]:
    # 逐分類合併並去重，保留原始順序。
    for section in ("deep_markers", "tool_signatures"):
        base.setdefault(section, {})
        incoming_section = incoming.get(section, {})
        for category, items in incoming_section.items():
            existing: list[str] = base[section].setdefault(category, [])
            seen = set(existing)
            for item in items:
                normalized = item.strip().lower()
                if normalized and normalized not in seen:
                    existing.append(normalized)
                    seen.add(normalized)
    return base


def _load_attack_signatures() -> dict[str, dict[str, list[str]]]:
    """載入並合併多來源簽名，避免單一來源覆蓋造成資料遺失。"""
    global _signatures_cache

    if _signatures_cache is not None:
        return _signatures_cache

    repo_root = Path(__file__).parent.parent
    # 單一可信來源：僅讀取 data/，避免 scripts/data 舊檔污染評分。
    candidate_files = [
        repo_root / "data" / "attack_signatures.txt",
        repo_root / "data" / "attack_signatures.json",
    ]

    merged: dict[str, dict[str, list[str]]] = {
        "deep_markers": {},
        "tool_signatures": {},
    }
    loaded_any = False

    for sig_file in candidate_files:
        if not sig_file.exists():
            continue
        try:
            if sig_file.suffix.lower() == ".txt":
                parsed = _parse_signature_txt(sig_file)
            else:
                with open(sig_file, "r", encoding="utf-8") as f:
                    parsed = json.load(f)
            _merge_signatures(merged, parsed)
            loaded_any = True
        except Exception as e:
            print(f"[!] 解析簽名檔失敗 {sig_file}: {e}")

    _signatures_cache = merged if loaded_any else _default_signatures()
    return _signatures_cache


def _parse_signature_txt(filepath: Path) -> dict[str, dict[str, list[str]]]:
    """解析 attack_signatures.txt（INI-like 格式）

    格式：
    [分類名]
    簽名1, 簽名2, 簽名3, ...

    # 這是註解
    """
    signatures: dict[str, dict[str, list[str]]] = {
        "deep_markers": {},
        "tool_signatures": {},
    }
    current_category = None
    current_section = "deep_markers"
    deep_categories = {
        "admin_endpoints",
        "auth_theft",
        "file_operations",
        "rce_general",
    }

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # 略過空行和註解
            if not line:
                continue

            if line.startswith("#"):
                if "工具簽名庫" in line:
                    current_section = "tool_signatures"
                continue

            # 檢測分類標籤 [category_name]
            if line.startswith("[") and line.endswith("]"):
                current_category = line[1:-1]

                # 支援明確前綴：
                # [deep_markers.category] / [tool_signatures.category]
                if "." in current_category:
                    prefix, category = current_category.split(".", 1)
                    if prefix in ("deep_markers", "tool_signatures"):
                        current_section = prefix
                        current_category = category
                else:
                    # 無前綴時，依已知 deep 類別自動判斷，避免依賴註解文字。
                    current_section = (
                        "deep_markers"
                        if current_category in deep_categories
                        else "tool_signatures"
                    )
                continue

            # 解析簽名
            if current_category:
                # 分割並去除空白
                items = [item.strip() for item in line.split(",")]
                items = [item for item in items if item]  # 移除空白項

                if items:
                    signatures[current_section][current_category] = items

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
            decoded = urllib.parse.unquote(prev, errors="replace")
            if decoded == prev:
                break
            prev = decoded
        except Exception:
            break

    normalized = prev

    # 移除路徑冗余
    normalized = re.sub(r"/+", "/", normalized)  # //// → /
    normalized = re.sub(r"/\./+", "//", normalized)  # /./ → //
    normalized = re.sub(r"/[^/]+/\.\./+", "/", normalized)  # /a/.. → /

    # 統一空白符（多空格、Tab、換行 → 單空格）
    normalized = re.sub(r"\s+", " ", normalized)

    # 十六進制解碼（如 \x2f = /）
    try:
        normalized = normalized.encode("utf-8").decode(
            "unicode_escape", errors="replace"
        )
    except Exception:
        pass

    return normalized.lower()


def _detect_attack_pattern(
    payload: str, tool_signatures: dict[str, list[str]]
) -> tuple[bool, str]:
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


from typing import Optional
from datetime import datetime


def _funnel_level(
    payload: str,
    endpoint_coverage: int,
    has_memory_hit: bool,
    attack_times: Optional[list[datetime]] = None,
) -> int:
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
    deep_markers: set[str] = set()
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
    is_tool_detected, _ = _detect_attack_pattern(payload or "", tool_signatures)
    if is_tool_detected:
        return 3

    # 條件 4：快速掃描紋樣（頻率分析）→ L3
    if attack_times and len(attack_times) >= 3:
        intervals = [
            (attack_times[i + 1] - attack_times[i]).total_seconds()
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
    principal_id: str,
    current_payload: str | None,
    has_memory_hit: bool,
) -> dict[str, int]:
    """
    [SOC 專用] 量化駭客對誘餌系統的信任度與擬真度指標。

    本函式會分析單一攻擊者(client_ip)在 Mirage-Sentinel 誘餌環境中的互動行為，
    綜合評分其「攻擊深度」、「探索廣度」、「行為演化」與「停留時間」，
    以推估攻擊者是否誤信本系統為真實目標，並提供給 SOC 前端儀表板做可視化。

    主要用途：
    - 讓 SOC 團隊一眼判斷誘餌成效(駭客是否投入大量資源、是否進行多樣化攻擊、是否長時間停留)。
    - 作為誘餌系統「擬真度」與「攻擊者信任度」的量化依據。

    回傳欄位說明：
        depth_score (int): 綜合擬真度分數(0~100，愈高代表駭客愈信任誘餌、互動愈深入)
        funnel_level (int): 漏斗層級(1=新手/試探，2=重複攻擊，3=高信任/自動化工具)
        dwell_seconds (int): 攻擊者在誘餌系統的總停留秒數
        endpoint_coverage (int): 攻擊過的不同 API/端點數量(愈多代表探索愈廣)
        payload_evolution_score (int): 攻擊 payload 的多樣性與複雜度分數
        funnel_score (int): 層級分數(依 funnel_level 對應 25/60/100)
        dwell_score (int): 停留時間分數(愈久愈高)
        coverage_score (int): 端點探索分數(愈多愈高)
        unique_payloads (int): 不同 payload 數量

    SOC 可依 depth_score 與 funnel_level 快速判斷誘餌成效，
    其餘欄位可用於細部行為分析與報表。
    """
    # 讀取同一攻擊者歷史攻擊資料，作為四維度評分基礎
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT t.request_at, t.principal_id, d.raw_payload
            FROM traffic_logs t
            JOIN clients c ON t.client_id = c.id
            LEFT JOIN attack_details d ON d.traffic_log_id = t.id
            WHERE c.ip = ? AND t.is_attack = 1
            ORDER BY t.request_at ASC
            """,
            (client_ip,),
        )
        rows = cursor.fetchall()

    attack_times: list[datetime] = []
    principal_ids: set[str] = set()
    payloads: list[str] = []
    for row in rows:
        ts = parse_db_timestamp(row[0])
        if ts:
            attack_times.append(ts)
        if row[1]:
            principal_ids.add(row[1])
        if row[2]:
            payloads.append(row[2])

    # 停留時間：首筆攻擊到最後一筆攻擊（秒）
    if attack_times:
        first_seen: datetime = attack_times[0]
        last_seen: datetime = attack_times[-1]
        dwell_seconds = max(int((last_seen - first_seen).total_seconds()), 0)
    else:
        dwell_seconds = 0

    # 端點探索廣度：攻擊過多少不重複 principal_id
    if principal_id:
        principal_ids.add(principal_id)
    endpoint_coverage = max(len(principal_ids), 1)

    if current_payload:
        payloads.append(current_payload)

    # 演化程度：同一攻擊者 payload 是否變多、變長、變複雜
    unique_payloads = len(set(payloads)) if payloads else 1
    if payloads:
        lengths = [len(p) for p in payloads]
        min_len = min(lengths)
        max_len = max(lengths)
        length_growth = max_len - min_len
        complexity_growth = max(_payload_complexity(p) for p in payloads) - min(
            _payload_complexity(p) for p in payloads
        )
    else:
        length_growth = 0
        complexity_growth = 0.0

    # 漏斗層級判定（傳入攻擊時序進行頻率分析）
    funnel_level = _funnel_level(
        current_payload or "",
        endpoint_coverage,
        has_memory_hit,
        attack_times=attack_times,  # 用於檢測快速掃描紋樣
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
