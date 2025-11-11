# =========================================
# db.py – module kết nối cơ sở dữ liệu MySQL
# =========================================

import mysql.connector
from mysql.connector import Error
from app.core.config import Config

def get_connection():
    """Tạo kết nối đến MySQL sử dụng thông tin từ Config."""
    try:
        conn = mysql.connector.connect(**Config.db_config())
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"[DB ERROR] {e}")
        return None

def test_connection():
    """Test thử kết nối khi setup."""
    conn = get_connection()
    if conn:
        print(f"✅ Connected to MySQL database `{Config.DB_NAME}` at {Config.DB_HOST}:{Config.DB_PORT}")
        conn.close()
    else:
        print("❌ Failed to connect to MySQL.")

if __name__ == "__main__":
    test_connection()