import datetime
import mysql.connector
from app.core.config import Config
from app.database.db import get_connection

class BlockedIPModel:
    """Model thao tác bảng ip_blocked trong database."""

    @staticmethod
    def block_ip(ip_address: str, reason: str, duration_minutes: int = 15):
        """Chặn IP trong thời gian duration_minutes (mặc định 15 phút)."""
        expires_at = datetime.datetime.now() + datetime.timedelta(minutes=duration_minutes)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        sql = """
        INSERT INTO ip_blocked (ip_address, reason, blocked_at, expires_at, status)
        VALUES (%s, %s, NOW(), %s, 'blocked')
        ON DUPLICATE KEY UPDATE
            reason = VALUES(reason),
            blocked_at = NOW(),
            expires_at = VALUES(expires_at),
            status = 'blocked';
        """
        cursor.execute(sql, (ip_address, reason, expires_at))
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[+] IP {ip_address} đã bị chặn đến {expires_at}.")

    @staticmethod
    def unblock_ip(ip_address: str):
        """Gỡ chặn IP thủ công."""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE ip_blocked
            SET status = 'unblocked'
            WHERE ip_address = %s AND status = 'blocked';
        """, (ip_address,))
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[-] IP {ip_address} đã được gỡ chặn thủ công.")

    @staticmethod
    def get_blocked_ips():
        """Lấy danh sách IP đang bị chặn."""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM ip_blocked WHERE status = 'blocked';")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows

    @staticmethod
    def auto_unblock_expired():
        """Tự động gỡ IP đã hết hạn (expires_at <= NOW())."""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Chọn IP đã hết hạn
        cursor.execute("""
            SELECT ip_address FROM ip_blocked
            WHERE status = 'blocked' AND expires_at <= NOW();
        """)
        expired_ips = cursor.fetchall()

        # Gỡ chặn chúng
        if expired_ips:
            cursor.execute("""
                UPDATE ip_blocked
                SET status = 'unblocked'
                WHERE status = 'blocked' AND expires_at <= NOW();
            """)
            conn.commit()

            for ip in expired_ips:
                print(f"[AUTO] Gỡ chặn IP {ip['ip_address']} do đã hết hạn.")

        cursor.close()
        conn.close()

    @staticmethod
    def get_all_blocked():
        """Lấy tất cả IP đang bị chặn với thông tin chi tiết."""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM ip_blocked WHERE status = 'blocked';")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    
    @staticmethod
    def get_all():
        """Lấy tất cả IP trong bảng ip_blocked."""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM ip_blocked;")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows

# if __name__ == "__main__":
#     # Ví dụ sử dụng
#     BlockedIPModel.block_ip("1.2.3.4", "Spamming")
#     BlockedIPModel.unblock_ip("1.2.3.4")
#     blocked_ips = BlockedIPModel.get_blocked_ips()
#     print("Danh sách IP bị chặn:", blocked_ips)