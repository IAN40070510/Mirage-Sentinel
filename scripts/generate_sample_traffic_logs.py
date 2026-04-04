import argparse
import os
import random
import sqlite3
import sys
from datetime import datetime, timedelta


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core import traffic_db


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "curl/8.6.0",
    "python-httpx/0.27.0",
    "sqlmap/1.8.1",
]

LOCATIONS = [
    "/api/v1/user",
    "/api/v1/login",
    "/api/v1/orders",
    "/api/v1/admin",
    "/api/v1/search",
]
ATTACK_VECTORS = ["SQLi", "XSS", "LFI", "CMD Injection"]
ATTACK_PAYLOADS = {
    "SQLi": [
        "' OR 1=1 --",
        "admin' UNION SELECT * FROM users --",
        "1; DROP TABLE users; --",
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><svg/onload=confirm(1)>',
    ],
    "LFI": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
    "CMD Injection": ["; cat /etc/passwd", "&& whoami", "| powershell -c Get-Process"],
}


def export_sql_dump(db_path: str, sql_path: str):
    with sqlite3.connect(db_path) as conn:
        script = "\n".join(conn.iterdump())
    with open(sql_path, "w", encoding="utf-8") as f:
        f.write(script)


def build_event(base_time: datetime, idx: int) -> dict:
    client_ip = f"10.20.{idx % 8}.{(idx % 40) + 10}"
    query_id = f"user_{1000 + (idx % 50)}"
    is_attack = 1 if random.random() < 0.35 else 0

    request_at = base_time + timedelta(seconds=idx * random.randint(8, 40))
    process_ms = random.randint(12, 240)
    response_at = request_at + timedelta(milliseconds=process_ms)

    event = {
        "request_at": request_at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "response_at": response_at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "process_ms": process_ms,
        "client_ip": client_ip,
        "location": random.choice(LOCATIONS),
        "is_proxy": 1 if random.random() < 0.08 else 0,
        "user_agent": random.choice(USER_AGENTS),
        "tls_fingerprint": f"tls-{random.randint(100000, 999999)}",
        "query_id": query_id,
        "is_attack": is_attack,
    }

    if is_attack:
        vector = random.choice(ATTACK_VECTORS)
        payload = random.choice(ATTACK_PAYLOADS[vector])
        hits = random.randint(1, 6)
        interaction_depth = random.randint(20, 95)

        event.update(
            {
                "raw_payload": payload,
                "response_payload": {
                    "status": "decoy",
                    "hint": "fake-record",
                    "token": f"fx-{random.randint(10000, 99999)}",
                },
                "attack_vector": vector,
                "risk_level": random.randint(55, 99),
                "hits": hits,
                "interaction_depth": interaction_depth,
                "dwell_time": float(random.randint(10, 600)),
                "mitigation_status": random.choice(
                    ["Sandboxed", "Blocked", "Monitored"]
                ),
            }
        )

    return event


def generate_sample_data(db_path: str, sql_path: str, rows: int, seed: int):
    random.seed(seed)

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    original_db_path = traffic_db.DB_PATH

    try:
        traffic_db.DB_PATH = db_path
        if os.path.exists(db_path):
            os.remove(db_path)

        traffic_db.setup_traffic_db()

        start_time = datetime.now() - timedelta(days=3)
        for i in range(rows):
            traffic_db.log_traffic_event(build_event(start_time, i))

        export_sql_dump(db_path, sql_path)
    finally:
        traffic_db.DB_PATH = original_db_path


def main():
    parser = argparse.ArgumentParser(
        description="Generate sample traffic_logs DB and SQL dump."
    )
    parser.add_argument(
        "--rows", type=int, default=180, help="Number of traffic rows to generate"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260325,
        help="Random seed for deterministic output",
    )
    parser.add_argument(
        "--db-path",
        default=os.path.join(PROJECT_ROOT, "data", "traffic_logs_sample.db"),
        help="Output SQLite DB path",
    )
    parser.add_argument(
        "--sql-path",
        default=os.path.join(PROJECT_ROOT, "data", "traffic_logs_sample.sql"),
        help="Output SQL dump path",
    )
    args = parser.parse_args()

    generate_sample_data(args.db_path, args.sql_path, args.rows, args.seed)
    print(f"[OK] Sample DB: {args.db_path}")
    print(f"[OK] SQL dump : {args.sql_path}")
    print(f"[OK] Rows      : {args.rows}")


if __name__ == "__main__":
    main()
