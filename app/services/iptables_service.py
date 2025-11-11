#!/usr/bin/env python3
# app/services/iptables_service.py
"""
iptables_service.py — service chạy nền (root)
Nghe lệnh từ Redis để BLOCK / UNBLOCK IP.
"""

import redis
import subprocess
import logging
import time
import os
from datetime import datetime

# --- LOGGING CONFIG ---
LOG_DIR = "app/logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "iptables_service.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("iptables_service")

# --- REDIS CONFIG ---
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_CHANNEL = "iptables_commands"
REDIS_SOCKET_TIMEOUT = 60  # tăng timeout để tránh disconnect


def iptables_block(ip: str):
    """Chặn IP bằng iptables (nếu chưa có)."""
    try:
        # Kiểm tra IP đã tồn tại chưa
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if check.returncode == 0:
            logger.warning(f"[SKIP] IP {ip} đã bị chặn từ trước.")
            return

        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        logger.info(f"[BLOCKED] {ip} - Đã thêm vào iptables")
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Lỗi khi block {ip}: {e}")
    except Exception as e:
        logger.error(f"⚠️ Lỗi không xác định khi block {ip}: {e}")


def iptables_unblock(ip: str):
    """Gỡ chặn IP khỏi iptables (nếu có)."""
    try:
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if check.returncode != 0:
            logger.warning(f"[SKIP] IP {ip} chưa bị chặn, bỏ qua.")
            return

        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        logger.info(f"[UNBLOCKED] {ip} - Đã gỡ khỏi iptables")
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Lỗi khi unblock {ip}: {e}")
    except Exception as e:
        logger.error(f"⚠️ Lỗi không xác định khi unblock {ip}: {e}")


def start_redis_listener():
    """Lắng nghe Redis channel để nhận lệnh block/unblock."""
    while True:
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, socket_timeout=REDIS_SOCKET_TIMEOUT)
            pubsub = r.pubsub(ignore_subscribe_messages=True)  # bỏ qua message subscribe ban đầu
            pubsub.subscribe(REDIS_CHANNEL)
            logger.info(f"[REDIS] Đã kết nối Redis channel: {REDIS_CHANNEL}")

            for message in pubsub.listen():
                if message is None:
                    continue
                if message["type"] != "message":
                    continue

                payload = message["data"].decode("utf-8").strip()
                logger.info(f"[REDIS] Nhận lệnh: {payload}")

                parts = payload.split()
                if len(parts) != 2:
                    logger.warning(f"[INVALID] Lệnh Redis không hợp lệ: {payload}")
                    continue

                action, ip = parts
                if action.upper() == "BLOCK":
                    iptables_block(ip)
                elif action.upper() == "UNBLOCK":
                    iptables_unblock(ip)
                else:
                    logger.warning(f"[INVALID] Hành động không hợp lệ: {action}")

        except redis.ConnectionError as e:
            logger.error(f"[REDIS] Mất kết nối Redis: {e}, thử lại sau 5s...")
            time.sleep(5)
        except redis.TimeoutError as e:
            logger.error(f"[REDIS] Timeout khi đọc từ socket: {e}, reconnect sau 5s...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"[ERROR] Lỗi không xác định: {e}, reconnect sau 5s...")
            time.sleep(5)


if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info(f"🚀 Bắt đầu iptables_service tại {datetime.now()}")
    logger.info("=" * 60)
    print("🚀 Bắt đầu iptables_service...")

    start_redis_listener()
    logger.info("iptables_service đã dừng.")