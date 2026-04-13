import sqlite3
import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, cast

logger = logging.getLogger(__name__)

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column_sql: str):
    """當資料庫升級時，為既有表補上缺少欄位。"""
    column_name = column_sql.strip().split()[0]
    cursor = conn.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column_name not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_sql}")


def setup_traffic_db():
    """初始化日誌庫，含 3NF 正規化表結構（clients, fingerprints, traffic_logs, attack_details）"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        polluted_status INTEGER DEFAULT 0
    )
    """
    )

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_agent TEXT,
        tls_fingerprint TEXT,
        UNIQUE(user_agent, tls_fingerprint)
    )
    """
    )

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_at TEXT NOT NULL,
        response_at TEXT,
        process_ms INTEGER,
        method TEXT,
        endpoint TEXT,
        client_id INTEGER NOT NULL,
        fingerprint_id INTEGER,
        principal_id TEXT,
        session_chain_id TEXT,
        query_id TEXT,
        device_id TEXT,
        referer TEXT,
        header_entropy REAL,
        req_interval_ms REAL,
        req_time_var REAL,
        user_device_ratio REAL,
        device_user_ratio REAL,
        req_rate_5m REAL,
        graph_feature_source TEXT,
        mouse_entropy REAL,
        mouse_source TEXT,
        amount_value REAL,
        amount_deviation REAL,
        is_attack INTEGER DEFAULT 0,
        location TEXT,
        is_proxy INTEGER DEFAULT 0,
        query_string TEXT,
        authorization TEXT,
        content_type TEXT,
        content_length TEXT,
        header_count INTEGER,
        all_headers TEXT,
        FOREIGN KEY(client_id) REFERENCES clients(id),
        FOREIGN KEY(fingerprint_id) REFERENCES fingerprints(id)
    )
    """
    )

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS attack_details (
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
        deception_score INTEGER,
        trust_level TEXT,
        memory_hit INTEGER DEFAULT 0,
        query_string TEXT,
        authorization TEXT,
        content_type TEXT,
        content_length TEXT,
        header_count INTEGER,
        all_headers TEXT,
        FOREIGN KEY(traffic_log_id) REFERENCES traffic_logs(id)
    )
    """
    )
    # 兼容既有 DB，補齊新欄位
    _ensure_column(conn, "traffic_logs", "query_string TEXT")
    _ensure_column(conn, "traffic_logs", "authorization TEXT")
    _ensure_column(conn, "traffic_logs", "content_type TEXT")
    _ensure_column(conn, "traffic_logs", "content_length TEXT")
    _ensure_column(conn, "traffic_logs", "header_count INTEGER")
    _ensure_column(conn, "traffic_logs", "all_headers TEXT")
    _ensure_column(conn, "attack_details", "query_string TEXT")
    _ensure_column(conn, "attack_details", "authorization TEXT")
    _ensure_column(conn, "attack_details", "content_type TEXT")
    _ensure_column(conn, "attack_details", "content_length TEXT")
    _ensure_column(conn, "attack_details", "header_count INTEGER")
    _ensure_column(conn, "attack_details", "all_headers TEXT")

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_is_attack ON traffic_logs(is_attack)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_request_at ON traffic_logs(request_at)"
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip)")

    # 兼容既有 DB：若 traffic_logs 為舊 schema，補齊新特徵欄位。
    _ensure_column(conn, "traffic_logs", "method TEXT")
    _ensure_column(conn, "traffic_logs", "endpoint TEXT")
    _ensure_column(conn, "traffic_logs", "principal_id TEXT")
    _ensure_column(conn, "traffic_logs", "session_chain_id TEXT")
    _ensure_column(conn, "traffic_logs", "device_id TEXT")
    _ensure_column(conn, "traffic_logs", "referer TEXT")
    _ensure_column(conn, "traffic_logs", "header_entropy REAL")
    _ensure_column(conn, "traffic_logs", "req_interval_ms REAL")
    _ensure_column(conn, "traffic_logs", "req_time_var REAL")
    _ensure_column(conn, "traffic_logs", "user_device_ratio REAL")
    _ensure_column(conn, "traffic_logs", "device_user_ratio REAL")
    _ensure_column(conn, "traffic_logs", "req_rate_5m REAL")
    _ensure_column(conn, "traffic_logs", "graph_feature_source TEXT")
    _ensure_column(conn, "traffic_logs", "mouse_entropy REAL")
    _ensure_column(conn, "traffic_logs", "mouse_source TEXT")
    _ensure_column(conn, "traffic_logs", "amount_value REAL")
    _ensure_column(conn, "traffic_logs", "amount_deviation REAL")
    _ensure_column(conn, "attack_details", "decision_source TEXT")
    _ensure_column(conn, "attack_details", "route_before TEXT")
    _ensure_column(conn, "attack_details", "route_after TEXT")
    _ensure_column(conn, "attack_details", "deception_reason TEXT")
    _ensure_column(conn, "attack_details", "policy_hit TEXT")
    _ensure_column(conn, "attack_details", "upstream_attempted INTEGER DEFAULT 0")
    _ensure_column(conn, "attack_details", "upstream_status_code INTEGER")
    _ensure_column(conn, "attack_details", "deception_engaged INTEGER DEFAULT 0")
    _ensure_column(conn, "attack_details", "deception_mode TEXT")
    _ensure_column(conn, "attack_details", "real_backend_touched INTEGER DEFAULT 0")
    _ensure_column(conn, "attack_details", "response_origin TEXT")
    _ensure_column(conn, "attack_details", "flow_stage TEXT")
    _ensure_column(conn, "attack_details", "deception_score INTEGER")
    _ensure_column(conn, "attack_details", "trust_level TEXT")
    _ensure_column(conn, "attack_details", "memory_hit INTEGER DEFAULT 0")

    conn.commit()
    conn.close()
    logger.info(f"Traffic Log Engine Ready: {DB_PATH}")


def log_traffic_event(data: dict[str, Any]) -> None:
    """寫入全流量紀錄（包含正常 / 攻擊），攻擊進一步寫入 attack_details"""
    conn = get_connection()
    cursor = conn.cursor()

    client_ip = data.get("client_ip")
    if not client_ip:
        raise ValueError("log_traffic_event requires 'client_ip' in data")

    if not data.get("request_at"):
        data["request_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    user_agent = data.get("user_agent")
    tls_fingerprint = data.get("tls_fingerprint")
    is_proxy = 1 if data.get("is_proxy") else 0
    is_attack = 1 if data.get("is_attack") else 0

    cursor.execute(
        "INSERT OR IGNORE INTO clients (ip, polluted_status) VALUES (?, ?)",
        (client_ip, is_proxy),
    )
    cursor.execute("SELECT id FROM clients WHERE ip = ?", (client_ip,))
    client_id = cursor.fetchone()["id"]

    cursor.execute(
        "INSERT OR IGNORE INTO fingerprints (user_agent, tls_fingerprint) VALUES (?, ?)",
        (user_agent, tls_fingerprint),
    )
    cursor.execute(
        "SELECT id FROM fingerprints WHERE user_agent = ? AND tls_fingerprint = ?",
        (user_agent, tls_fingerprint),
    )
    fingerprint_id = cursor.fetchone()["id"]

    route_before = data.get("route_before") or "banking_proxy"
    route_after = data.get("route_after") or (
        "mirage" if is_attack else "vuln_bank_main"
    )
    response_origin = data.get("response_origin") or (
        "sandbox_ai" if is_attack else "vuln_bank_main"
    )
    flow_stage = data.get("flow_stage") or ("deception" if is_attack else "upstream")
    deception_score = data.get("deception_score")
    trust_level = data.get("trust_level") or ("medium" if is_attack else "low")
    real_backend_touched = 1 if data.get("real_backend_touched") else 0
    deception_engaged = 1 if data.get("deception_engaged") else 0
    upstream_attempted = 1 if data.get("upstream_attempted") else 0
    risk_level = int(data.get("risk_level") or 0)
    if not is_attack:
        deception_score = 0
        risk_level = 0

    cursor.execute(
        """
        INSERT INTO traffic_logs (
            request_at, response_at, process_ms, method, endpoint, client_id, fingerprint_id,
            principal_id, session_chain_id, query_id, device_id, referer, header_entropy, req_interval_ms, req_time_var,
            user_device_ratio, device_user_ratio, req_rate_5m, graph_feature_source,
            mouse_entropy, mouse_source, amount_value, amount_deviation, is_attack, location, is_proxy,
            query_string, authorization, content_type, content_length, header_count, all_headers
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("request_at"),
            data.get("response_at"),
            data.get("process_ms"),
            data.get("method"),
            data.get("endpoint"),
            client_id,
            fingerprint_id,
            data.get("principal_id", data.get("query_id")),
            data.get("session_chain_id"),
            data.get("query_id"),
            data.get("device_id"),
            data.get("referer"),
            data.get("header_entropy"),
            data.get("req_interval_ms"),
            data.get("req_time_var"),
            data.get("user_device_ratio"),
            data.get("device_user_ratio"),
            data.get("req_rate_5m"),
            data.get("graph_feature_source"),
            data.get("mouse_entropy"),
            data.get("mouse_source"),
            data.get("amount_value"),
            data.get("amount_deviation"),
            is_attack,
            data.get("location"),
            is_proxy,
            data.get("query_string"),
            data.get("authorization"),
            data.get("content_type"),
            data.get("content_length"),
            data.get("header_count"),
            (
                json.dumps(data.get("all_headers"), ensure_ascii=False)
                if data.get("all_headers")
                else None
            ),
        ),
    )

    traffic_log_id = cursor.lastrowid

    cursor.execute(
        """
        INSERT OR REPLACE INTO attack_details (
            traffic_log_id, raw_payload, response_payload, attack_vector,
            risk_level, hits, interaction_depth, dwell_time, mitigation_status,
            decision_source, route_before, route_after, deception_reason,
            policy_hit, upstream_attempted, upstream_status_code,
            deception_engaged, deception_mode, real_backend_touched, response_origin,
            flow_stage, deception_score, trust_level, memory_hit,
            query_string, authorization, content_type, content_length, header_count, all_headers
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            traffic_log_id,
            data.get("raw_payload"),
            (
                json.dumps(data.get("response_payload"), ensure_ascii=False)
                if data.get("response_payload") is not None
                else None
            ),
            data.get("attack_vector") if is_attack else None,
            risk_level,
            data.get("hits") if is_attack else 0,
            data.get("interaction_depth") if is_attack else 0,
            data.get("dwell_time") if is_attack else 0.0,
            data.get("mitigation_status"),
            data.get("decision_source") if is_attack else "normal_flow",
            route_before,
            route_after,
            data.get("deception_reason") if is_attack else None,
            data.get("policy_hit") if is_attack else None,
            upstream_attempted,
            data.get("upstream_status_code"),
            deception_engaged,
            data.get("deception_mode") if is_attack else None,
            real_backend_touched,
            response_origin,
            flow_stage,
            deception_score,
            trust_level,
            1 if data.get("memory_hit") else 0,
            data.get("query_string"),
            data.get("authorization"),
            data.get("content_type"),
            data.get("content_length"),
            data.get("header_count"),
            (
                json.dumps(data.get("all_headers"), ensure_ascii=False)
                if data.get("all_headers")
                else None
            ),
        ),
    )

    conn.commit()
    conn.close()


def get_recent_traffic(limit: int = 100) -> list[dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT t.*, c.ip AS client_ip, f.user_agent, f.tls_fingerprint,
               d.attack_vector, d.risk_level, d.hits, d.interaction_depth, d.dwell_time, d.mitigation_status,
               d.decision_source, d.route_before, d.route_after, d.deception_reason,
               d.policy_hit, d.upstream_attempted, d.upstream_status_code,
               d.deception_engaged, d.deception_mode, d.real_backend_touched, d.response_origin,
               d.flow_stage, d.deception_score, d.trust_level, d.memory_hit,
               t.query_string, t.authorization, t.content_type, t.content_length, t.header_count, t.all_headers,
               d.query_string AS attack_query_string, d.authorization AS attack_authorization,
               d.content_type AS attack_content_type, d.content_length AS attack_content_length,
               d.header_count AS attack_header_count, d.all_headers AS attack_all_headers
        FROM traffic_logs t
        JOIN clients c ON t.client_id = c.id
        LEFT JOIN fingerprints f ON t.fingerprint_id = f.id
        LEFT JOIN attack_details d ON d.traffic_log_id = t.id
        ORDER BY t.request_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_transactions_by_user(
    user_id: str, limit_seconds: int = 300, max_results: int = 50
) -> list[dict[str, Any]]:
    """查詢使用者最近 X 秒內的交易。用於檢測重放與高頻規則。"""
    from datetime import datetime, timedelta

    conn = get_connection()
    cursor = conn.cursor()

    # 計算時間下限（UTC）
    cutoff_time = (
        datetime.now(timezone.utc) - timedelta(seconds=limit_seconds)
    ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    cursor.execute(
        """
        SELECT t.*, c.ip AS client_ip, d.raw_payload, d.response_payload, d.attack_vector
        FROM traffic_logs t
        JOIN clients c ON t.client_id = c.id
        LEFT JOIN attack_details d ON d.traffic_log_id = t.id
        WHERE t.query_id = ? AND t.request_at > ?
        ORDER BY t.request_at DESC
        LIMIT ?
        """,
        (user_id, cutoff_time, max_results),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_transactions_by_ip(
    client_ip: str, limit_seconds: int = 60, max_results: int = 100
) -> list[dict[str, Any]]:
    """查詢 IP 最近 X 秒內的 API 呼叫。用於檢測速率限制 (DDoS/Rate-limit) 規則。"""
    from datetime import datetime, timedelta

    conn = get_connection()
    cursor = conn.cursor()

    cutoff_time = (
        datetime.now(timezone.utc) - timedelta(seconds=limit_seconds)
    ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    cursor.execute(
        """
        SELECT t.*, f.user_agent
        FROM traffic_logs t
        JOIN clients c ON t.client_id = c.id
        LEFT JOIN fingerprints f ON t.fingerprint_id = f.id
        WHERE c.ip = ? AND t.request_at > ?
        ORDER BY t.request_at DESC
        LIMIT ?
        """,
        (client_ip, cutoff_time, max_results),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_transaction_amounts_by_user(
    user_id: str, limit_hours: int = 24, max_results: int = 100
) -> list[int]:
    """查詢使用者過去 X 小時的所有交易金額。用於檢測異常金額序列。"""
    from datetime import datetime, timedelta
    import json

    conn = get_connection()
    cursor = conn.cursor()

    cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=limit_hours)).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]

    # 查詢所有轉帳請求（不只是攻擊），從 traffic_logs 和 response_payload 提取金額
    cursor.execute(
        """
        SELECT d.response_payload
        FROM traffic_logs t
        LEFT JOIN attack_details d ON d.traffic_log_id = t.id
        WHERE t.query_id = ? AND t.request_at > ?
        AND t.location = 'banking:transfers'
        AND d.response_payload IS NOT NULL
        ORDER BY t.request_at DESC
        LIMIT ?
        """,
        (user_id, cutoff_time, max_results),
    )
    rows = cursor.fetchall()
    conn.close()

    amounts: list[int] = []
    for row in rows:
        try:
            payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            if isinstance(payload, dict):
                payload_dict = cast(dict[str, Any], payload)
                transaction_value = payload_dict.get("transaction")
                if not isinstance(transaction_value, dict):
                    continue
                transaction_data = cast(dict[str, Any], transaction_value)
                amount = transaction_data.get("amount")
                if amount is not None and isinstance(amount, (int, float)):
                    amounts.append(int(amount))
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    return amounts
