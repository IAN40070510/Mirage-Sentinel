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
    traffic_log_id INTEGER PRIMARY KEY,         -- 1
    raw_payload TEXT,                          -- 2
    response_payload TEXT,                     -- 3
    attack_vector TEXT,                        -- 4
    risk_level INTEGER,                        -- 5
    hits INTEGER,                             -- 6
    interaction_depth INTEGER,                 -- 7
    dwell_time REAL,                           -- 8
    mitigation_status TEXT,                    -- 9
    decision_source TEXT,                      -- 10
    route_before TEXT,                         -- 11
    route_after TEXT,                          -- 12
    deception_reason TEXT,                     -- 13
    policy_hit TEXT,                           -- 14
    upstream_attempted INTEGER DEFAULT 0,      -- 15
    upstream_status_code INTEGER,              -- 16
    deception_engaged INTEGER DEFAULT 0,       -- 17
    deception_mode TEXT,                       -- 18
    real_backend_touched INTEGER DEFAULT 0,    -- 19
    response_origin TEXT,                      -- 20
    flow_stage TEXT,                           -- 21
    deception_score REAL,                      -- 22
    trust_level TEXT,                          -- 23
    memory_hit INTEGER DEFAULT 0,              -- 24
    query_string TEXT,                         -- 25
    authorization TEXT,                        -- 26
    content_type TEXT,                         -- 27
    content_length TEXT,                       -- 28
    header_count INTEGER,                      -- 29
    all_headers TEXT,                          -- 30
    dummy_padding TEXT,                        -- 31 (for legacy insert bug, can be always NULL)
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
