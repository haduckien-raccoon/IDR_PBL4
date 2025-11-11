# import logging
# from logging.handlers import RotatingFileHandler
# import os

# def get_logger(name: str):
#     logger = logging.getLogger(name)
#     if logger.handlers:
#         return logger
#     logger.setLevel(logging.INFO)

#     log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
#     os.makedirs(log_dir, exist_ok=True)
#     log_path = os.path.join(log_dir, "alerts.log")

#     fh = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3)
#     fh.setLevel(logging.INFO)
#     fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
#     fh.setFormatter(fmt)

#     ch = logging.StreamHandler()
#     ch.setLevel(logging.INFO)
#     ch.setFormatter(fmt)

#     logger.addHandler(fh)
#     logger.addHandler(ch)
#     return logger
import logging
import os

def get_logger(name: str):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    # Chỉ log ra terminal
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    logger.addHandler(ch)

    # ✳️ Tắt propagate để không bị ghi nhầm vào root logger hoặc file log khác
    logger.propagate = False

    return logger
