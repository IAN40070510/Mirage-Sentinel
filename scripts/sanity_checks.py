import os
import shutil
import sqlite3
import sys
from datetime import datetime


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core import deception_db, nexus_db, traffic_db
from core.deception_metrics import compute_interaction_metrics
from services import web_service


def _assert(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def _reset_temp_dir(temp_dir: str):
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)


def run():
    temp_dir = os.path.join(PROJECT_ROOT, "data", "_sanity_tmp")
    _reset_temp_dir(temp_dir)

    temp_traffic_db = os.path.join(temp_dir, "traffic_logs_test.db")
    temp_memory_db = os.path.join(temp_dir, "mirage_memory_test.db")

    original_paths = {
        "traffic_db.DB_PATH": traffic_db.DB_PATH,
        "nexus_db.DB_PATH": nexus_db.DB_PATH,
        "web_service.DB_PATH": web_service.DB_PATH,
        "deception_db.DB_PATH": deception_db.DB_PATH,
    }

    try:
        # 將所有資料層指向測試 DB，避免污染正式資料
        traffic_db.DB_PATH = temp_traffic_db
        nexus_db.DB_PATH = temp_traffic_db
        web_service.DB_PATH = temp_traffic_db
        deception_db.DB_PATH = temp_memory_db

        traffic_db.setup_traffic_db()
        deception_db.setup_deception_db()

        # Case 1: 驗證唯一鍵 + Upsert 不會產生重複列
        client_ip = "10.0.0.10"
        query_id = "u1001"
        deception_db.save_deception_state(client_ip, query_id, "SQLi", 80, {"token": "fake-a"})
        deception_db.save_deception_state(client_ip, query_id, "SQLi", 90, {"token": "fake-b"})

        with sqlite3.connect(temp_memory_db) as conn:
            cursor = conn.execute(
                "SELECT COUNT(1), MAX(hits), MAX(interaction_count) FROM deception_memory WHERE client_ip=? AND query_id=?",
                (client_ip, query_id),
            )
            count_rows, hits, interaction_count = cursor.fetchone()

        _assert(count_rows == 1, "Case 1 failed: 重複 key 產生多筆 deception_memory")
        _assert(hits == 2 and interaction_count == 2, "Case 1 failed: Upsert 累加 hits/interaction_count 不正確")

        # Case 2: 驗證 dwell_seconds 為 first->last，不受閒置時間膨脹
        attack_client = "10.0.0.20"
        event_common = {
            "client_ip": attack_client,
            "location": "test",
            "is_proxy": 0,
            "user_agent": "pytest",
            "tls_fingerprint": "N/A",
            "query_id": "u2001",
            "is_attack": 1,
            "attack_vector": "LFI",
            "risk_level": 88,
            "response_payload": {"ok": True},
            "raw_payload": "../../../../etc/passwd",
            "mitigation_status": "Sandboxed",
            "hits": 1,
            "interaction_depth": 10,
            "dwell_time": 0.0,
            "process_ms": 10,
        }

        traffic_db.log_traffic_event(
            {
                **event_common,
                "request_at": "2026-01-01 00:00:00.000",
                "response_at": "2026-01-01 00:00:00.100",
            }
        )
        traffic_db.log_traffic_event(
            {
                **event_common,
                "request_at": "2026-01-01 01:00:00.000",
                "response_at": "2026-01-01 01:00:00.100",
            }
        )

        metrics = compute_interaction_metrics(
            client_ip=attack_client,
            query_id="u2001",
            current_payload="../../../../etc/passwd",
            has_memory_hit=True,
        )
        _assert(metrics["dwell_seconds"] == 3600, f"Case 2 failed: dwell_seconds={metrics['dwell_seconds']}，預期 3600")

        # Case 3: 驗證 has_memory_hit 只看攻擊事件，不受正常流量影響
        normal_client = "10.0.0.30"
        traffic_db.log_traffic_event(
            {
                "request_at": "2026-01-01 02:00:00.000",
                "response_at": "2026-01-01 02:00:00.050",
                "process_ms": 5,
                "client_ip": normal_client,
                "location": "test",
                "is_proxy": 0,
                "user_agent": "pytest",
                "tls_fingerprint": "N/A",
                "query_id": "u3001",
                "is_attack": 0,
            }
        )

        depth = web_service.analyze_interaction_depth(normal_client, "u3001")
        _assert(depth["funnel_level"] == 1, f"Case 3 failed: funnel_level={depth['funnel_level']}，預期 1")

        print("[PASS] Case 1: 唯一鍵 + Upsert 正常")
        print("[PASS] Case 2: dwell_seconds 不會因閒置時間膨脹")
        print("[PASS] Case 3: has_memory_hit 僅由攻擊事件決定")
        print("All sanity checks passed.")

    finally:
        # 還原模組 DB 路徑
        traffic_db.DB_PATH = original_paths["traffic_db.DB_PATH"]
        nexus_db.DB_PATH = original_paths["nexus_db.DB_PATH"]
        web_service.DB_PATH = original_paths["web_service.DB_PATH"]
        deception_db.DB_PATH = original_paths["deception_db.DB_PATH"]


if __name__ == "__main__":
    run()
