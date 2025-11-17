import os
import time
import threading
import queue
import smtplib
from email.message import EmailMessage
import logging
from typing import Optional, Dict, Any, List

console_logger = logging.getLogger("console")

MAIL_QUEUE_MAXSIZE = 1000
MAIL_MAX_RETRY = 5
MAIL_BACKOFF_BASE = 0.5  # giây

_mail_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=MAIL_QUEUE_MAXSIZE)
_metrics = {"enq": 0, "drop": 0, "sent": 0, "fail": 0}

def enqueue_mail(to_addr: str, subject: str, text: str, html: Optional[str] = None, cc: Optional[List[str]] = None, bcc: Optional[List[str]] = None):
    job = {
        "to": to_addr,
        "subject": subject,
        "text": text,
        "html": html,
        "cc": cc or [],
        "bcc": bcc or [],
        "retry": 0,
    }
    try:
        _mail_q.put_nowait(job)
        _metrics["enq"] += 1
    except queue.Full:
        _metrics["drop"] += 1
        console_logger.warning("Mail queue full, dropping email to %s", to_addr)

def _send_smtp(job: Dict[str, Any]):
    host = os.getenv("SMTP_HOST", "localhost")
    port = int(os.getenv("SMTP_PORT", "25"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    use_tls = os.getenv("SMTP_USE_TLS", "false").lower() in ("1", "true", "yes")
    from_addr = os.getenv("SMTP_FROM", user or "ids@example.com")

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = job["to"]
    if job["cc"]:
        msg["Cc"] = ", ".join(job["cc"])
    msg["Subject"] = job["subject"]
    if job["html"]:
        msg.set_content(job["text"] or "")
        msg.add_alternative(job["html"], subtype="html")
    else:
        msg.set_content(job["text"] or "")

    rcpt = [job["to"]] + job["cc"] + job["bcc"]

    if use_tls:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls()
            if user:
                s.login(user, password)
            s.send_message(msg, from_addr=from_addr, to_addrs=rcpt)
    else:
        with smtplib.SMTP(host, port, timeout=10) as s:
            if user:
                s.login(user, password)
            s.send_message(msg, from_addr=from_addr, to_addrs=rcpt)

def _mail_worker(stop_event: threading.Event):
    console_logger.info("Mail worker started")
    while not stop_event.is_set():
        try:
            job = _mail_q.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            _send_smtp(job)
            _metrics["sent"] += 1
        except Exception as e:
            job["retry"] += 1
            if job["retry"] <= MAIL_MAX_RETRY:
                backoff = MAIL_BACKOFF_BASE * (2 ** (job["retry"] - 1))
                console_logger.warning("Send mail failed (attempt %d/%d): %s. Backoff %.1fs", job["retry"], MAIL_MAX_RETRY, e, backoff)
                # ngủ theo backoff rồi đưa lại vào queue (ưu tiên thấp)
                time.sleep(min(backoff, 8.0))
                try:
                    _mail_q.put_nowait(job)
                except queue.Full:
                    _metrics["drop"] += 1
                    console_logger.error("Mail queue full on retry, dropping email to %s", job["to"])
            else:
                _metrics["fail"] += 1
                console_logger.error("Send mail permanently failed after %d retries to %s: %s", MAIL_MAX_RETRY, job["to"], e)
        finally:
            try:
                _mail_q.task_done()
            except Exception:
                pass

def start_mail_workers(num_workers: int = 1) -> threading.Event:
    stop_event = threading.Event()
    for i in range(max(1, num_workers)):
        t = threading.Thread(target=_mail_worker, args=(stop_event,), daemon=True, name=f"mail-worker-{i}")
        t.start()
    console_logger.info("Started %d mail worker(s)", max(1, num_workers))
    return stop_event

def mail_queue_metrics() -> Dict[str, int]:
    return dict(_metrics)