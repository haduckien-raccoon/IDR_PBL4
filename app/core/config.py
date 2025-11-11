# =========================================
# config.py – cấu hình hệ thống IDS Honeypot
# =========================================

import os
from dotenv import load_dotenv

# Tự động load biến môi trường từ file .env (nếu có)
load_dotenv()

class Config:
    """
    Class Config cho phép truy cập cấu hình toàn hệ thống.
    Có thể mở rộng sang Redis, SMTP, API, Logging...
    """

    # Database (MySQL)
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", 3306))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "ids_honeypot")

    # Firewall
    FIREWALL_CMD = os.getenv("FIREWALL_CMD", "iptables")
    FIREWALL_CHECK_INTERVAL = int(os.getenv("FIREWALL_CHECK_INTERVAL", 60))

    # Logging
    LOG_FILE = os.getenv("LOG_FILE", "/var/log/ipblock.log")

    @classmethod
    def db_config(cls):
        """Trả về dict cấu hình MySQL (cho mysql.connector)"""
        return {
            "host": cls.DB_HOST,
            "port": cls.DB_PORT,
            "user": cls.DB_USER,
            "password": cls.DB_PASSWORD,
            "database": cls.DB_NAME,
        }
# app/core/config.py
import os
from typing import Optional

# ✅ Nạp .env TRƯỚC khi đọc os.getenv (đặt đường dẫn đúng dự án của bạn)
try:
    from dotenv import load_dotenv
    load_dotenv("/media/haduckien/E/Studying/HK5/PBL4(3)/idr_project/.env")
except Exception:
    pass

def as_bool(val, default=False):
    if isinstance(val, bool): 
        return val
    if val is None: 
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")

class Settings:
    # ===============================
    # 🔹 PostgreSQL Database Config
    # ===============================
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "mysql+mysqldb://idr_user:Idr@1234@localhost:3306/ids_honeypot"
    )

    # ===============================
    # 🔹 SMTP (Gửi email cảnh báo)
    # ===============================
    # ƯU TIÊN ENV; để trống thì alert code sẽ tự suy luận từ SMTP_USERNAME
    SMTP_HOST: Optional[str] = os.getenv("SMTP_HOST")  # không ép "localhost"
    SMTP_PORT: int = int(os.getenv("SMTP_PORT") or 587)  # mặc định 587 (STARTTLS)
    SMTP_USE_TLS: bool = as_bool(os.getenv("SMTP_USE_TLS"), True)  # mặc định True
    SMTP_USERNAME: Optional[str] = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")

    # FROM/TO: lấy từ .env; nếu FROM trống thì fallback = SMTP_USERNAME; TO bắt buộc có
    ALERT_FROM: Optional[str] = os.getenv("ALERT_FROM") or os.getenv("SMTP_USERNAME")
    ALERT_TO: Optional[str] = os.getenv("ALERT_TO")  # KHÔNG set default 'admin@example.local'

    # ===============================
    # 🔹 Flask
    # ===============================
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    def validate(self):
        # Có thể gọi validate() ở app startup để báo lỗi cấu hình sớm
        missing = []
        if not self.ALERT_TO:
            missing.append("ALERT_TO")
        if not self.SMTP_USERNAME:
            missing.append("SMTP_USERNAME")
        if not self.SMTP_PASSWORD:
            missing.append("SMTP_PASSWORD")
        if missing:
            raise ValueError(f"Missing required email settings in .env: {', '.join(missing)}")

settings = Settings()
# Gợi ý (tuỳ bạn): bật validate ở startup để bắt cấu hình sai sớm
# settings.validate()