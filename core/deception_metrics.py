from datetime import datetime
from typing import Any

from core.traffic_db import get_connection


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


def _payload_complexity(payload: str) -> float:
    # 以特殊符號比例估算 payload 複雜度
    if not payload:
        return 0.0
    specials = sum(1 for ch in payload if not ch.isalnum() and not ch.isspace())
    return specials / max(len(payload), 1)


def _funnel_level(payload: str, endpoint_coverage: int, has_memory_hit: bool) -> int:
    # 漏斗層級：L1 初次探測、L2 持續互動、L3 深層探勘
    normalized = (payload or "").lower()
    deep_markers = [
        "/api/admin",
        "/api/salary",
        "/api/internal",
        "bearer ",
        "token=",
        "session=",
        "cookie:",
        "upload",
        "shell",
        "cmd=",
    ]

    if endpoint_coverage >= 2 or any(marker in normalized for marker in deep_markers):
        return 3
    if has_memory_hit:
        return 2
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

    funnel_level = _funnel_level(current_payload or "", endpoint_coverage, has_memory_hit)

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
