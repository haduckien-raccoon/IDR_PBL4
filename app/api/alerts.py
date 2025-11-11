# app/api/alerts.py
import os
import base64
import mimetypes
from pathlib import Path
# [THÊM MỚI] Import BaseModel và Field để định nghĩa schema
from typing import List, Optional
from pydantic import BaseModel, Field

from datetime import datetime, timezone

import asyncio
from anyio import to_thread

from sqlalchemy import func, desc
from sqlalchemy.orm import joinedload, Session
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from smtplib import SMTP, SMTP_SSL
from email.message import EmailMessage

from app.core.logging import get_logger
from app.core.config import settings
from app.database import db, get_session
from app.services.analyzer import Analyzer
from app.models import Event, Alert, AttackType, IncidentReport

# WebSocket broadcaster (dùng chung toàn app)
from app.core.ws_broadcaster import manager

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
logger = get_logger(__name__)

# -------------------- helpers --------------------
# (Không thay đổi)
def as_bool(val, default=False):
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    try:
        val = str(val).strip().lower()
        if val in ('y', 'yes', 't', 'true', 'on', '1'):
            return True
        if val in ('n', 'no', 'f', 'false', 'off', '0'):
            return False
        return default
    except Exception:
        return default

def parse_iso_ts(s: Optional[str]):
    if not s:
        return None
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# -------------------- email --------------------
# (Toàn bộ phần email helpers không thay đổi)
def _infer_smtp_from_username(username: str):
    """Map email domain -> sensible SMTP defaults."""
    if not username or '@' not in username:
        return None, None, None
    domain = username.split('@', 1)[1].lower()
    mapping = {
        'gmail.com': ("smtp.gmail.com", 587, True),
        'googlemail.com': ("smtp.gmail.com", 587, True),
        'outlook.com': ("smtp.office3F365.com", 587, True),
        'hotmail.com': ("smtp.office365.com", 587, True),
        'live.com': ("smtp.office365.com", 587, True),
        'yahoo.com': ("smtp.mail.yahoo.com", 587, True),
        'yahoo.com.vn': ("smtp.mail.yahoo.com", 587, True),
    }
    return mapping.get(domain, (None, None, None))

def _build_email_message(payload: dict) -> EmailMessage:
    username = getattr(settings, "SMTP_USERNAME", None) or os.getenv("SMTP_USERNAME")
    mail_from = getattr(settings, "ALERT_FROM", None) or os.getenv("ALERT_FROM") or username
    mail_to = getattr(settings, "ALERT_TO", None) or os.getenv("ALERT_TO")

    subject = f"[IDR Alert] {payload.get('alert_level','info').upper()} - event #{payload.get('event_id')}"
    body_lines = [
        "New Security Alert",
        f"Sent at: {payload.get('sent_at')}",
        f"Alert level: {payload.get('alert_level')}",
        f"Message: {payload.get('alert_message')}",
        "",
        "Event details:",
        f"  Event ID: {payload.get('event_id')}",
        f"  Time: {payload.get('timestamp')}",
        f"  Severity: {payload.get('severity')}",
        f"  Status: {payload.get('status')}",
        f"  Source IP: {payload.get('source_ip')}",
        f"  Destination IP: {payload.get('destination_ip')}",
    ]
    
    # [THÊM MỚI] Thêm mô tả chi tiết (hexdump, v.v.) vào email nếu có
    if payload.get('description'):
        body_lines.append(f"  Description: {payload.get('description')}")


    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.set_content("\n".join(body_lines))
    return msg

def _attach_optional_files(msg: EmailMessage, payload: dict):
    def _attach_bytes(content_bytes: bytes, filename: str):
        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type:
            maintype, subtype = mime_type.split('/', 1)
        else:
            maintype, subtype = 'application', 'octet-stream'
        msg.add_attachment(content_bytes, maintype=maintype, subtype=subtype, filename=filename)

    try:
        b64 = payload.get('captured_file_b64') or payload.get('captured_b64') or payload.get('payload_b64') # [THÊM MỚI] payload_b64
        path = payload.get('captured_file') or payload.get('captured_path')
        if b64:
            try:
                file_bytes = base64.b64decode(b64)
                fname = payload.get('captured_filename') or f"capture_{payload.get('event_id') or 'unknown'}.bin"
                _attach_bytes(file_bytes, fname)
                logger.info(f"Attached captured data from base64 as {fname}")
            except Exception as _e:
                logger.warning(f"Failed to decode base64 captured file: {_e}")
        elif path:
            try:
                p = Path(path)
                if not p.is_absolute():
                    p = Path.cwd() / p
                if p.exists() and p.is_file():
                    _attach_bytes(p.read_bytes(), p.name)
                    logger.info(f"Attached captured file from path: {p}")
                else:
                    logger.warning(f"Captured file path does not exist or is not a file: {p}")
            except Exception as _e:
                logger.warning(f"Failed to attach captured file from path {path}: {_e}")
    except Exception as _e:
        logger.warning(f"Error processing captured file attachment: {_e}")

def _prepare_smtp_config():
    host = getattr(settings, "SMTP_HOST", None) or os.getenv("SMTP_HOST")
    port_raw = getattr(settings, "SMTP_PORT", None) or os.getenv("SMTP_PORT") or "587"
    try:
        port = int(str(port_raw))
    except Exception:
        port = 587
    use_tls_flag = getattr(settings, "SMTP_USE_TLS", None)
    if use_tls_flag is None:
        use_tls_flag = os.getenv("SMTP_USE_TLS", "true")
    use_tls = as_bool(use_tls_flag, True)

    username = getattr(settings, "SMTP_USERNAME", None) or os.getenv("SMTP_USERNAME")
    password = getattr(settings, "SMTP_PASSWORD", None) or os.getenv("SMTP_PASSWORD")
    mail_to = getattr(settings, "ALERT_TO", None) or os.getenv("ALERT_TO")

    if (not host) or (str(host).strip().lower() in {"localhost", "127.0.0.1"}):
        inf_host, inf_port, inf_tls = _infer_smtp_from_username(username)
        if inf_host:
            logger.warning(
                f"SMTP host not set or set to localhost. Inferring provider from username: {username} -> {inf_host}:{inf_port} (TLS={inf_tls})"
            )
            host, port, use_tls = inf_host, inf_port, inf_tls
        else:
            logger.warning(
                "SMTP host is not configured or set to localhost. Set these in your .env: \n"
                "SMTP_HOST=smtp.your-provider.com\nSMTP_PORT=587\nSMTP_USERNAME=you@example.com\nSMTP_PASSWORD=app-password\nSMTP_USE_TLS=true"
            )

    if not host:
        raise RuntimeError("SMTP_HOST is not configured (and could not infer from username). Please set in .env")
    if not mail_to:
        raise RuntimeError("ALERT_TO is empty. Please set ALERT_TO in .env")

    return host, port, use_tls, username, password, mail_to

def _send_email_sync(payload: dict):
    """Hàm sync để chạy trong thread (không block event loop)."""
    msg = _build_email_message(payload)
    _attach_optional_files(msg, payload)

    host, port, use_tls, username, password, mail_to = _prepare_smtp_config()
    recipients: List[str] = [r.strip() for r in str(mail_to).split(',') if r.strip()]

    logger.info(f"SMTP config in use: host={host}, port={port}, use_tls={use_tls}, from={msg['From']}, to={mail_to}")
    logger.debug(f"Attempting SMTP connection to {host}:{port} (TLS: {'implicit' if port == 465 else 'explicit' if use_tls else 'none'})")

    if port == 465:
        with SMTP_SSL(host=host, port=port, timeout=20) as smtp:
            smtp.set_debuglevel(1)
            if username and password:
                logger.debug(f"Authenticating as {username}")
                smtp.login(username, password)
            smtp.send_message(msg, to_addrs=recipients)
    else:
        with SMTP(host=host, port=port, timeout=20) as smtp:
            smtp.set_debuglevel(1)
            smtp.ehlo()
            if port == 587 or use_tls:
                logger.debug("Starting STARTTLS")
                smtp.starttls()
                smtp.ehlo()
            if username and password:
                logger.debug(f"Authenticating as {username}")
                smtp.login(username, password)
            smtp.send_message(msg, to_addrs=recipients)

    logger.info("✅ Alert email sent.")

def map_severity_to_alert_level(sev: str) -> str:
    sev = (sev or "").lower()
    if sev in ("high", "critical"):
        return "critical"
    if sev in ("medium",):
        return "warning"
    return "info"

# -------------------- realtime broadcast --------------------
# (Không thay đổi)
async def emit_alert_realtime(alert_row: Alert, event_row: Event):
    """Phát WS sau khi đã có dữ liệu DB."""
    payload = {
        "type": "alert.new",
        "data": {
            "id": alert_row.alert_id,
            "ts": (event_row.timestamp or datetime.now(timezone.utc)).isoformat(),
            "severity": event_row.severity,
            "src_ip": str(event_row.source_ip) if event_row.source_ip else None,
            "dst_ip": str(event_row.destination_ip) if event_row.destination_ip else None,
            "rule": getattr(event_row, "rule_group_id", None) or "Unknown",
            "brief": alert_row.alert_message or "New alert"
        }
    }
    await manager.broadcast_json(payload)

# -------------------- routes --------------------

# [THÊM MỚI] Pydantic model cho payload từ ids_byte_deep.py
class RawAlertPayload(BaseModel):
    rule_id: str = Field(..., alias="rid")
    message: str
    proto: Optional[str] = "TCP"
    src_ip: str = Field(..., alias="src")
    dst_ip: str = Field(..., alias="dst")
    src_port: Optional[int] = Field(None, alias="sport")
    dst_port: Optional[int] = Field(None, alias="dport")
    variant: Optional[str] = None
    entropy: Optional[float] = None
    hexdump: Optional[str] = None
    payload_b64: Optional[str] = None # Payload gốc (nếu có)
    action: Optional[str] 
    severity: Optional[str] = "medium"

@router.get("")
async def list_alerts(request: Request, session: Session = Depends(get_session)):
    try:
        qp = request.query_params
        severity = qp.get("severity")
        status = qp.get("status")
        alert_level = qp.get("alert_level")
        start_date = parse_iso_ts(qp.get("start_date"))
        end_date = parse_iso_ts(qp.get("end_date"))
        page = max(int(qp.get("page", 1)), 1)
        page_size = min(max(int(qp.get("page_size", 50)), 1), 200)

        q = session.query(Alert).join(Event, Alert.event_id == Event.event_id)

        if alert_level:
            q = q.filter(Alert.alert_level == alert_level)
        if severity:
            q = q.filter(Event.severity == severity)
        if status:
            q = q.filter(Event.status == status)
        if start_date:
            q = q.filter(Event.timestamp >= start_date)
        if end_date:
            q = q.filter(Event.timestamp <= end_date)

        total = q.count()
        rows = (q.options(joinedload(Alert.event))
                 .order_by(desc(Alert.sent_at))
                 .offset((page - 1) * page_size)
                 .limit(page_size)
                 .all())

        def to_dict(a: Alert):
            e = a.event
            return {
                "alert_id": a.alert_id,
                "event_id": a.event_id,
                "alert_message": a.alert_message,
                "alert_level": a.alert_level,
                "sent_at": a.sent_at.isoformat() if a.sent_at else None,
                "is_sent": a.is_sent,
                "timestamp": e.timestamp.isoformat() if e and e.timestamp else None,
                "source_ip": str(e.source_ip) if e and e.source_ip else None,
                "destination_ip": str(e.destination_ip) if e and e.destination_ip else None,
                "severity": e.severity if e else None,
                "status": e.status if e else None,
                "description": e.description if e else None,
            }

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "data": [to_dict(a) for a in rows],
                "meta": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": (total + page_size - 1) // page_size
                }
            }
        )
    except Exception as e:
        logger.error(f"Error listing alerts: {e}")
        return JSONResponse(status_code=500, content={"status":"error","message":"Failed to retrieve alerts"})

@router.get("/{alert_id}")
async def get_alert(alert_id: int, session: Session = Depends(get_session)):
    try:
        a = (session.query(Alert)
             .options(joinedload(Alert.event))
             .filter(Alert.alert_id == alert_id)
             .first())
        if not a:
            return JSONResponse(status_code=404, content={"status":"error","message":"Alert not found"})

        e = a.event
        data = {
            "alert_id": a.alert_id,
            "event_id": a.event_id,
            "alert_message": a.alert_message,
            "alert_level": a.alert_level,
            "sent_at": a.sent_at.isoformat() if a.sent_at else None,
            "is_sent": a.is_sent,
            "timestamp": e.timestamp.isoformat() if e and e.timestamp else None,
            "source_ip": str(e.source_ip) if e and e.source_ip else None,
            "destination_ip": str(e.destination_ip) if e and e.destination_ip else None,
            "severity": e.severity if e else None,
            "status": e.status if e else None,
            "description": e.description if e else None,
        }
        return JSONResponse(status_code=200, content={"status":"success","data":data})
    except Exception as e:
        logger.error(f"Error get alert {alert_id}: {e}")
        return JSONResponse(status_code=500, content={"status":"error","message":"Failed to retrieve alert"})

@router.put("/{alert_id}")
async def update_alert(alert_id: int, request: Request, session: Session = Depends(get_session)):
    try:
        data = await request.json()
        data = data or {}

        a = session.get(Alert, alert_id)
        if not a:
            return JSONResponse(status_code=404, content={"status":"error","message":"Alert not found"})

        if "alert_level" in data:
            if data["alert_level"] not in ("info", "warning", "critical"):
                return JSONResponse(status_code=400, content={"status":"error","message":"Invalid alert_level"})
            a.alert_level = data["alert_level"]

        if "alert_message" in data:
            a.alert_message = str(data["alert_message"])[:4000]

        if "is_sent" in data:
            a.is_sent = bool(data["is_sent"])

        if "event_status" in data:
            e = session.get(Event, a.event_id)
            if e:
                if data["event_status"] not in ("new", "investigating", "resolved"):
                    return JSONResponse(status_code=400, content={"status":"error","message":"Invalid event_status"})
                e.status = data["event_status"]

        if data.get("note"):
            rep = IncidentReport(
                event_id=a.event_id,
                report_details=str(data["note"])[:8000],
                reported_by=None
            )
            session.add(rep)

        return JSONResponse(status_code=200, content={"status":"success","data":{"alert_id": a.alert_id}})
    except Exception as e:
        logger.error(f"Error update alert {alert_id}: {e}")
        return JSONResponse(status_code=500, content={"status":"error","message":"Failed to update alert"})

# [THÊM MỚI] Endpoint để nhận cảnh báo thô từ IDS (ids_byte_deep.py)
@router.post("/raw", status_code=201)
async def create_raw_alert(payload: RawAlertPayload, session: Session = Depends(get_session)):
    """
    Nhận cảnh báo thô trực tiếp từ bộ phân tích (ví dụ: ids_byte_deep.py).
    Endpoint này sẽ tạo Event, Alert và gửi thông báo.
    """
    try:
        logger.info(f"Received raw alert: rule_id={payload.rule_id}, msg='{payload.message}'")

        # 1. Tìm hoặc tạo AttackType
        # Sử dụng message của rule làm attack_name
        attack_name = payload.message or "Unknown IDS Rule"
        category = "Network Signature" # Danh mục cho các rule từ IDS

        attack = (session.query(AttackType)
                  .filter(AttackType.attack_name == attack_name)
                  .first())
        
        #Lấy action trong payload
        action = payload.action or None
        
        if not attack:
            attack_desc = f"Rule ID: {payload.rule_id} (Variant: {payload.variant}, Proto: {payload.proto})"
            attack = AttackType(
                attack_name=attack_name, 
                category=category, 
                description=attack_desc
            )
            session.add(attack)
            session.flush()

        # 2. Tạo Event
        # Vì đây là một rule đã khớp, chúng ta nên đặt severity ít nhất là "medium"
        severity = payload.severity
        
        # Tạo mô tả chi tiết cho Event
        description = (
            f"IDS Rule Matched: '{payload.message}' (ID: {payload.rule_id})\n"
            f"Details: Matched on variant '{payload.variant}' "
            f"for flow {payload.src_ip}:{payload.src_port} -> {payload.dst_ip}:{payload.dst_port} (Proto: {payload.proto}).\n"
            f"Entropy: {payload.entropy or 0.0:.3f}.\n"
        )
        if payload.hexdump:
            description += f"\n--- Hexdump ---\n{payload.hexdump}\n--- End Hexdump ---"

        e = Event(
            source_ip = payload.src_ip or "0.0.0.0",
            destination_ip = payload.dst_ip or "0.0.0.0",
            attack_id = attack.attack_id,
            severity = severity,
            description = description,
            detected_by = "Manual", # Để phân biệt với "AI" -> detected_by = "IDS (raw_packet)",
            status = "new",
        )
        session.add(e)
        session.flush()

        # 3. Tạo Alert
        level = map_severity_to_alert_level(e.severity)
        alert_message = f"IDS Alert: {payload.message}" # Tin nhắn ngắn gọn cho alert
        
        a = Alert(
            event_id = e.event_id,
            alert_message = alert_message,
            alert_level = level,
            is_sent = False
        )
        session.add(a)
        session.flush()

        # 4. Chuẩn bị payload email và gửi
        email_payload = {
            "alert_id": a.alert_id,
            "event_id": e.event_id,
            "alert_message": a.alert_message,
            "alert_level": a.alert_level,
            "sent_at": (a.sent_at or datetime.now(timezone.utc)).isoformat(),
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "severity": severity,
            "status": e.status,
            "source_ip": str(e.source_ip),
            "destination_ip": str(e.destination_ip),
            "description": e.description, # Gửi mô tả đầy đủ
            "payload_b64": payload.payload_b64, # Gửi payload (nếu có)
            "action": action
        }

        email_attempted = False
        try:
            # Gửi email trong thread để không block event loop
            await to_thread.run_sync(_send_email_sync, email_payload)
            a.is_sent = True
            email_attempted = True
            logger.info(f"Email sent for raw alert #{a.alert_id}")
        except Exception as mail_err:
            logger.error(f"Email error for raw alert #{a.alert_id}: {mail_err}")

        # 5. Phát realtime tới WebSocket clients
        try:
            asyncio.create_task(emit_alert_realtime(a, e))
        except RuntimeError:
            await emit_alert_realtime(a, e)

        return {
            "status": "success",
            "data": {
                "alert_id": a.alert_id,
                "event_id": e.event_id,
                "alert_level": a.alert_level,
                "severity": e.severity,
                "status": e.status
            },
            "email_attempted": email_attempted,
            "message": "Raw alert created successfully"
        }

    except Exception as e:
        logger.error(f"Error processing raw alert: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"status":"error","message":"Failed to process raw alert data"})

@router.get("/metrics")
async def alert_metrics(request: Request, session: Session = Depends(get_session)):
    try:
        qp = request.query_params
        start_date = parse_iso_ts(qp.get("start_date"))
        end_date = parse_iso_ts(qp.get("end_date"))

        q = session.query(Alert).join(Event, Alert.event_id == Event.event_id)
        if start_date:
            q = q.filter(Event.timestamp >= start_date)
        if end_date:
            q = q.filter(Event.timestamp <= end_date)

        total_alerts = q.count()

        by_level_q = (session.query(Alert.alert_level, func.count())
                      .join(Event, Alert.event_id == Event.event_id))
        if start_date:
            by_level_q = by_level_q.filter(Event.timestamp >= start_date)
        if end_date:
            by_level_q = by_level_q.filter(Event.timestamp <= end_date)
        by_level = dict(by_level_q.group_by(Alert.alert_level).all())

        by_sev_q = (session.query(Event.severity, func.count())
                    .join(Alert, Alert.event_id == Event.event_id))
        if start_date:
            by_sev_q = by_sev_q.filter(Event.timestamp >= start_date)
        if end_date:
            by_sev_q = by_sev_q.filter(Event.timestamp <= end_date)
        by_sev = dict(by_sev_q.group_by(Event.severity).all())

        by_stat_q = (session.query(Event.status, func.count())
                     .join(Alert, Alert.event_id == Event.event_id))
        if start_date:
            by_stat_q = by_stat_q.filter(Event.timestamp >= start_date)
        if end_date:
            by_stat_q = by_stat_q.filter(Event.timestamp <= end_date)
        by_stat = dict(by_stat_q.group_by(Event.status).all())

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "data": {
                    "total_alerts": total_alerts,
                    "by_alert_level": by_level,
                    "by_severity": by_sev,
                    "by_status": by_stat
                }
            }
        )
    except Exception as e:
        logger.error(f"Error metrics: {e}")
        return JSONResponse(status_code=500, content={"status":"error","message":"Failed to retrieve alert metrics"})