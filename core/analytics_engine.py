import sqlite3
import os

# 分析引擎：只負責查詢/分析流量日誌，寫入由 traffic_db 處理
CURRENT_FILE_PATH = os.path.abspath(__file__)
CORE_DIR = os.path.dirname(CURRENT_FILE_PATH)
PROJECT_ROOT = os.path.dirname(CORE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_logs.db")


def get_connection():
    """
    取得 traffic_logs.db 的 SQLite 連線（僅供 SOC/後台分析使用）。
    若資料庫不存在則拋出 FileNotFoundError。
    嚴禁於 Mirage-Sentinel 誘餌主機直接調用。
    """
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Traffic DB not initialized: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_attack_summary(limit: int = 100):
    """
    取得近期攻擊事件摘要。
    僅供 SOC/後台分析模組查詢 traffic_logs.db，回傳攻擊事件的詳細欄位。
    參數：
        limit (int): 回傳筆數上限，預設 100。
    回傳：
        list[dict]: 攻擊事件列表，每筆為 dict。
    注意：禁止於 Mirage-Sentinel 誘餌主機直接調用。
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT t.id, t.request_at, t.response_at, c.ip AS client_ip,
               f.user_agent, f.tls_fingerprint, d.attack_vector, d.risk_level,
               d.hits, d.interaction_depth, d.dwell_time, d.mitigation_status
        FROM traffic_logs t
        JOIN clients c ON t.client_id = c.id
        LEFT JOIN fingerprints f ON t.fingerprint_id = f.id
        LEFT JOIN attack_details d ON d.traffic_log_id = t.id
        WHERE t.is_attack = 1
        ORDER BY t.request_at DESC
        LIMIT ?
    """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_traffic_stats():
    """
    統計 traffic_logs.db 內總流量、攻擊流量、正常流量與攻擊率。
    僅供 SOC/後台分析模組查詢。
    回傳：
        dict: {"total", "attacks", "normals", "attack_rate"}
    注意：禁止於 Mirage-Sentinel 誘餌主機直接調用。
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(1) AS total FROM traffic_logs")
    total = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(1) AS attacks FROM traffic_logs WHERE is_attack = 1")
    attacks = cursor.fetchone()["attacks"]
    cursor.execute("SELECT COUNT(1) AS normals FROM traffic_logs WHERE is_attack = 0")
    normals = cursor.fetchone()["normals"]
    conn.close()
    return {
        "total": total,
        "attacks": attacks,
        "normals": normals,
        "attack_rate": round(attacks / (total or 1), 4),
    }


def get_client_profile(client_ip: str):
    """
    查詢指定 IP 的客戶端資料與互動事件紀錄。
    僅供 SOC/後台分析模組查詢。
    參數：
        client_ip (str): 目標客戶端 IP。
    回傳：
        dict: {"client": {...}, "events": [...]}
    """
