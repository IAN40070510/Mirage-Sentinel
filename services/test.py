import sqlite3
import os

# 路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "traffic_nexus.db")
ERROR_LOG_DIR = os.path.join(PROJECT_ROOT, "data", "error_log")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

conn = get_db_connection()
cursor = conn.cursor()
cursor.execute('''
    SELECT *
    FROM nexus_activity 
    WHERE attacker_ip = "192.168.1.1" 
''',)

row = cursor.fetchone()

print(dict(row))