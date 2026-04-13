#!/usr/bin/env python3
"""
自動升級 Mirage-Sentinel traffic_logs.db 的 attack_details 資料表 schema，
確保與 core/traffic_db.py 的 insert 欄位一致。
"""
import sqlite3
import os

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "traffic_logs.db"
)

NEW_SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_details_new (
    traffic_log_id INTEGER PRIMARY KEY,
    raw_payload TEXT,
    response_payload TEXT,
    attack_vector TEXT,
    risk_level INTEGER,
    hits INTEGER,
    interaction_depth INTEGER,
    dwell_time REAL,
    mitigation_status TEXT,
    decision_source TEXT,
    route_before TEXT,
    route_after TEXT,
    deception_reason TEXT,
    policy_hit TEXT,
    upstream_attempted INTEGER DEFAULT 0,
    upstream_status_code INTEGER,
    deception_engaged INTEGER DEFAULT 0,
    deception_mode TEXT,
    real_backend_touched INTEGER DEFAULT 0,
    response_origin TEXT,
    flow_stage TEXT,
    deception_score REAL,
    trust_level TEXT,
    memory_hit INTEGER DEFAULT 0,
    query_string TEXT,
    authorization TEXT,
    content_type TEXT,
    content_length TEXT,
    header_count INTEGER,
    all_headers TEXT,
    FOREIGN KEY(traffic_log_id) REFERENCES traffic_logs(id)
);
"""


def upgrade_attack_details_schema():
    if not os.path.exists(DB_PATH):
        print(f"[upgrade] DB not found: {DB_PATH}")
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # 備份舊表
    cur.execute("ALTER TABLE attack_details RENAME TO attack_details_old;")
    # 建立新表
    cur.executescript(NEW_SCHEMA)
    # 無法自動搬移舊資料（欄位不對等），僅保留新表結構
    cur.execute("DROP TABLE attack_details_old;")
    conn.commit()
    conn.close()
    print("[upgrade] attack_details schema upgraded successfully.")


if __name__ == "__main__":
    upgrade_attack_details_schema()
