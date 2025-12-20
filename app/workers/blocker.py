# """
# block_worker.py — Redis-based IP block worker (REFactor)
# Chạy user thường, không cần root
# """

# import time
# import redis
# import logging
# from datetime import datetime, timedelta
# from app.models import BlockedIPModel

# # ==============================
# # CONFIG
# # ==============================
# REDIS_HOST = "localhost"
# REDIS_PORT = 6379
# REDIS_DB = 0

# BLOCK_DURATION_MINUTES = 10
# BLOCK_KEY_PREFIX = "block:ip:"

# UNBLOCK_POLL_INTERVAL = 60  # seconds

# # ==============================
# # LOGGING
# # ==============================
# logging.basicConfig(
#     filename="app/logs/block_worker.log",
#     level=logging.INFO,
#     format="%(asctime)s [%(levelname)s] %(message)s"
# )

# logger = logging.getLogger("block_worker")

# # ==============================
# # REDIS CONNECTION
# # ==============================
# redis_conn = redis.Redis(
#     host=REDIS_HOST,
#     port=REDIS_PORT,
#     db=REDIS_DB,
#     decode_responses=True  # trả string thay vì bytes
# )

# # ==============================
# # CORE FUNCTIONS
# # ==============================

# def _redis_block_key(ip: str) -> str:
#     return f"{BLOCK_KEY_PREFIX}{ip}"


# def is_ip_blocked(ip: str) -> bool:
#     """
#     Check IP bị block hay chưa
#     O(1) Redis EXISTS
#     """
#     return redis_conn.exists(_redis_block_key(ip)) == 1


# def enqueue_block(ip: str, reason: str = "unknown"):
#     """
#     Block IP:
#     - Set Redis key với TTL
#     - Ghi DB
#     - Publish iptables command
#     """
#     key = _redis_block_key(ip)
#     ttl = BLOCK_DURATION_MINUTES * 60

#     # Nếu IP đã bị block thì bỏ qua
#     if redis_conn.exists(key):
#         logger.info(f"[SKIP] IP {ip} already blocked")
#         return

#     # Redis TTL
#     redis_conn.setex(key, ttl, reason)

#     # Database
#     BlockedIPModel.block_ip(
#         ip=ip,
#         reason=reason,
#         duration_minutes=BLOCK_DURATION_MINUTES
#     )

#     # Notify firewall worker
#     redis_conn.publish("iptables_commands", f"BLOCK {ip}")

#     logger.warning(f"[BLOCK] {ip} ({reason}) for {BLOCK_DURATION_MINUTES} minutes")


# def enqueue_unblock(ip: str, reason: str = "expired"):
#     """
#     Unblock IP:
#     - Xóa Redis key (nếu còn)
#     - Update DB
#     - Publish iptables command
#     """
#     redis_conn.delete(_redis_block_key(ip))

#     BlockedIPModel.unblock_ip(ip)

#     redis_conn.publish("iptables_commands", f"UNBLOCK {ip}")

#     logger.info(f"[UNBLOCK] {ip} ({reason})")


# # ==============================
# # BACKGROUND WORKER
# # ==============================

# def auto_unblock_expired_ips():
#     """
#     Poll database để tìm IP đã hết hạn block
#     (backup mechanism, an toàn nếu Redis restart)
#     """
#     logger.info("[WORKER] Auto-unblock worker started")

#     while True:
#         try:
#             expired_ips = BlockedIPModel.auto_unblock_expired()

#             for ip in expired_ips:
#                 enqueue_unblock(ip, reason="db_expired")

#         except Exception as e:
#             logger.error(f"[ERROR] auto_unblock_expired_ips: {e}")

#         time.sleep(UNBLOCK_POLL_INTERVAL)


# # ==============================
# # MAIN (OPTIONAL)
# # ==============================

# if __name__ == "__main__":
#     auto_unblock_expired_ips()
"""
block_worker.py — Redis-based IP block worker (REFactor)
Chạy user thường, không cần root
"""

from ipaddress import ip_address
import time
import redis
import logging
from datetime import datetime, timedelta
from app.models import BlockedIPModel

# ==============================
# CONFIG
# ==============================
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

BLOCK_DURATION_MINUTES = 10
BLOCK_KEY_PREFIX = "block:ip:"

UNBLOCK_POLL_INTERVAL = 3600  # seconds

# ==============================
# LOGGING
# ==============================
logging.basicConfig(
    filename="app/logs/block_worker.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("block_worker")

# ==============================
# REDIS CONNECTION
# ==============================
redis_conn = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True  # trả string thay vì bytes
)

# ==============================
# CORE FUNCTIONS
# ==============================

def _redis_block_key(ip: str) -> str:
    return f"{BLOCK_KEY_PREFIX}{ip}"


def is_ip_blocked(ip: str) -> bool:
    """
    Check IP bị block hay chưa
    O(1) Redis EXISTS
    """
    return redis_conn.exists(_redis_block_key(ip)) == 1


def enqueue_block(ip: str, reason: str = "unknown", duration_minutes: int = BLOCK_DURATION_MINUTES):
    """
    Block IP:
    - Set Redis key với TTL
    - Ghi DB
    - Publish iptables command
    """
    key = _redis_block_key(ip)
    ttl = duration_minutes * 60

    # Nếu IP đã bị block thì bỏ qua
    if redis_conn.exists(key):
        logger.info(f"[SKIP] IP {ip} already blocked")
        return

    # Redis TTL
    redis_conn.setex(key, ttl, reason)

    # Database
    BlockedIPModel.block_ip(
        ip_address=ip,
        reason=reason,
        duration_minutes=duration_minutes
    )

    # Notify firewall worker
    redis_conn.publish("iptables_commands", f"BLOCK {ip}")

    logger.warning(f"[BLOCK] {ip} ({reason}) for {duration_minutes} minutes")


def enqueue_unblock(ip: str, reason: str = "expired"):
    """
    Unblock IP:
    - Xóa Redis key (nếu còn)
    - Update DB
    - Publish iptables command
    """
    redis_conn.delete(_redis_block_key(ip))

    BlockedIPModel.unblock_ip(ip)

    redis_conn.publish("iptables_commands", f"UNBLOCK {ip}")

    #in ra thời gian thực hiện unblock bằng date time hiện tại
    logger.info(f"[UNBLOCK] {ip} ({reason}) at {datetime.now()}")
    

# ==============================
# BACKGROUND WORKER
# ==============================

def auto_unblock_expired_ips():
    """
    Poll database để tìm IP đã hết hạn block
    (backup mechanism, an toàn nếu Redis restart)
    """
    logger.info("[WORKER] Auto-unblock worker started")

    while True:
        try:
            expired_ips = BlockedIPModel.auto_unblock_expired()
            if expired_ips is not None:
                for ip in expired_ips:
                    enqueue_unblock(ip['ip_address'], reason="db_expired")

        except Exception as e:
            logger.error(f"[ERROR] auto_unblock_expired_ips: {e}")

        time.sleep(UNBLOCK_POLL_INTERVAL)

def listen_redis_expired_events():
    pubsub = redis_conn.pubsub()
    pubsub.subscribe("__keyevent@0__:expired")

    for msg in pubsub.listen():
        if msg["type"] != "message":
            continue

        key = msg["data"]
        if not key.startswith(BLOCK_KEY_PREFIX):
            continue

        ip = key.replace(BLOCK_KEY_PREFIX, "")

        BlockedIPModel.unblock_ip(ip)
        enqueue_unblock(ip, reason="redis_expired")

        logger.info(f"[UNBLOCK] {ip} (redis_expired) date time: {datetime.now()}")
# ==============================
import threading

def start_workers():
    threading.Thread(
        target=listen_redis_expired_events,
        daemon=True
    ).start()

    threading.Thread(
        target=auto_unblock_expired_ips,
        daemon=True
    ).start()

    logger.info("[SYSTEM] Block worker started")

    while True:
        time.sleep(60)

if __name__ == "__main__":
    #test enqueue_block block ip 1.2.3.4
    # enqueue_block("1.2.3.4", reason="test_block", duration_minutes=2)
    start_workers()

