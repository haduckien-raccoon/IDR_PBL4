"""
block_worker.py — worker gửi lệnh lên Redis
Chạy dưới user thường, không cần root.
app/workers/block_worker.py
"""

import redis
import logging
import threading
from datetime import datetime, timedelta
from app.models import BlockedIPModel
import logging

logging.basicConfig(
    filename="app/logs/block_worker.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


redis_conn = redis.Redis(host="localhost", port=6379, db=0)
logger = logging.getLogger("block_worker")

BLOCK_DURATION_MINUTES = 10

def enqueue_block(ip: str, reason="unknown"):
    """Gửi lệnh chặn IP (block) lên Redis service"""
    BlockedIPModel.block_ip(ip, reason, duration_minutes=BLOCK_DURATION_MINUTES)
    redis_conn.publish("iptables_commands", f"BLOCK {ip}")
    logger.warning(f"[PUBLISH] Block {ip} ({reason})")

    timer = threading.Timer(BLOCK_DURATION_MINUTES * 60, enqueue_unblock, args=[ip])
    timer.start()

def enqueue_unblock(ip: str):
    """Gửi lệnh gỡ IP (unblock) lên Redis service"""
    redis_conn.publish("iptables_commands", f"UNBLOCK {ip}")
    BlockedIPModel.unblock_ip(ip)
    logger.info(f"[PUBLISH] Unblock {ip} (hết thời gian)")

def auto_unblock_expired_ips():
    """Tự động gỡ các IP đã hết hạn trong database"""
    while True:
        try:
            BlockedIPModel.auto_unblock_expired()
        except Exception as e:
            logger.error(f"Lỗi khi tự động gỡ IP hết hạn: {e}")
        threading.Event().wait(300)  # chờ 5 phút rồi kiểm tra lại

