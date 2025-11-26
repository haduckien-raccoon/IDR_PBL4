# api/incident.py
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Optional
import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_session # <--- Sử dụng get_session dependency mới
from app.api.alerts import _send_email_sync
from app.api.alerts import map_severity_to_alert_level

# GIẢ ĐỊNH: Import các model và hàm cần thiết
# (Cần đảm bảo các file model đã được import và định nghĩa Base)
# Giả định app.models đã có các file này:
from app.models.event import Event
from app.models.attack_type import AttackType
# Import model BlockedIPModel từ file blocked_ip.py (dùng mysql.connector)
from app.models.blocked_ip import BlockedIPModel 

router = APIRouter()

# --- Schemas (Pydantic models) cho dữ liệu trả về ---

class AttackTypeSchema(BaseModel):
    attack_id: int
    attack_name: str
    category: str
    
    class Config: # Cho phép Pydantic đọc từ SQLAlchemy object
        from_attributes = True

class EventSchema(BaseModel):
    event_id: int
    timestamp: datetime.datetime
    source_ip: str
    destination_ip: str
    severity: str
    status: str
    description: Optional[str] = None
    attack_type: AttackTypeSchema # Trường đã JOIN

    class Config:
        from_attributes = True

class EventDetailSchema(EventSchema):
    detected_by: str

class QuickStatsSchema(BaseModel):
    incident_today: int
    incident_open: int
    blocked_ip_count: int
    
class IPStatusSchema(BaseModel):
    ip_address: str
    status: str # 'blocked', 'unblocked', 'not_found'


# Hàm tiện ích để lấy dữ liệu Event đã được JOIN với AttackType
# Sửa đổi để chấp nhận các tham số lọc
def get_events_with_attack_type(
    db: Session, 
    event_id: Optional[int] = None, 
    from_date: Optional[datetime.date] = None, 
    to_date: Optional[datetime.date] = None,
    attack_type_id: Optional[int] = None, 
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    
    query = db.query(Event, AttackType.attack_name, AttackType.category).join(AttackType, Event.attack_id == AttackType.attack_id)
    
    # 1. Date Filters
    if from_date:
        query = query.filter(Event.timestamp >= datetime.datetime.combine(from_date, datetime.time.min))
    if to_date:
        query = query.filter(Event.timestamp <= datetime.datetime.combine(to_date, datetime.time.max))

    # 2. Category Filters
    if attack_type_id is not None:
        query = query.filter(Event.attack_id == attack_type_id)
    if severity:
        query = query.filter(Event.severity == severity)
    if status:
        query = query.filter(Event.status == status) # <--- Status Filter
            
    # --- KẾT THÚC LỌC ---
    
    if event_id is not None:
        # ... (logic lấy chi tiết sự kiện giữ nguyên) ...
        event_data = query.filter(Event.event_id == event_id).first()
        # ... (return EventDetailSchema) ...
        if not event_data:
            return None
        event, attack_name, category = event_data
        return EventDetailSchema(
            **event.__dict__,
            attack_type=AttackTypeSchema(
                attack_id=event.attack_id, 
                attack_name=attack_name, 
                category=category
            )
        )
    
    # Lấy danh sách events sau khi lọc
    results = query.order_by(Event.timestamp.desc()).limit(100).all() 
    events_list = []
    for event, attack_name, category in results:
        events_list.append(EventSchema(
            **event.__dict__,
            attack_type=AttackTypeSchema(
                attack_id=event.attack_id, 
                attack_name=attack_name, 
                category=category
            )
        ))
    return events_list


# --- 1. Endpoint lấy Danh sách sự kiện ---
@router.get("/events", response_model=List[EventSchema])
async def list_events(
    db: Session = Depends(get_session),
    from_date: Optional[datetime.date] = Query(None),
    to_date: Optional[datetime.date] = Query(None),
    attack_type_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None) # <--- Add status filter query param
):
    """Retrieves a list of events with filtering support."""
    try:
        events_list = get_events_with_attack_type(
            db, 
            from_date=from_date,
            to_date=to_date,
            attack_type_id=attack_type_id,
            severity=severity,
            status=status
        )
        return events_list
    except Exception as e:
        print(f"[ERROR] list_events: {e}")
        raise HTTPException(status_code=500, detail="Database connection error.")


# --- 2. Endpoint lấy Chi tiết sự kiện ---
@router.get("/events/{event_id}", response_model=EventDetailSchema)
async def get_event_details(event_id: int, db: Session = Depends(get_session)):
    """Retrieves details for a specific event."""
    event_detail = get_events_with_attack_type(db, event_id=event_id)
    if not event_detail:
        raise HTTPException(status_code=404, detail="Event not found")
    return event_detail


# --- 3. Endpoint lấy Thống kê nhanh ---
@router.get("/stats/quick", response_model=QuickStatsSchema)
async def get_quick_stats(db: Session = Depends(get_session)):
    """Retrieves quick statistics for the dashboard overview."""
    
    # 3.1. Sự kiện hôm nay
    today = datetime.datetime.now().date()
    incident_today = db.query(Event).filter(func.date(Event.timestamp) == today).count()
    
    # 3.2. Sự kiện chưa xử lý (status = 'new' hoặc 'investigating')
    incident_open = db.query(Event).filter(
        Event.status.in_(['new', 'investigating'])
    ).count()
    
    # 3.3. IP đã bị chặn (Sử dụng BlockedIPModel dùng mysql.connector)
    try:
        blocked_ips = BlockedIPModel.get_blocked_ips()
        blocked_ip_count = len(blocked_ips)
    except Exception as e:
        print(f"[WARN] Failed to get blocked IPs using BlockedIPModel: {e}")
        blocked_ip_count = 0 
    
    return {
        "incident_today": incident_today,
        "incident_open": incident_open,
        "blocked_ip_count": blocked_ip_count
    }

# --- 4. Endpoint lấy Danh sách Loại tấn công (cho bộ lọc) ---
@router.get("/attack-types", response_model=List[AttackTypeSchema])
async def list_attack_types(db: Session = Depends(get_session)):
    """Retrieves the list of attack types for the filter dropdown."""
    # Truy vấn tất cả các hàng trong bảng AttackType
    attack_types = db.query(AttackType).all() 
    # Chuyển đổi kết quả SQLAlchemy sang Pydantic Schema AttackTypeSchema
    return [AttackTypeSchema.from_orm(a) for a in attack_types] 


# --- 5. Action Endpoint: Update Status (/action/update-status/{event_id}) ---
@router.post("/action/update-status/{event_id}")
async def update_status(event_id: int, data: dict, db: Session = Depends(get_session)):
    """Updates the status of an event (new, investigating, or resolved)."""
    new_status = data.get('status')
    if new_status not in ['new', 'investigating', 'resolved']:
        raise HTTPException(status_code=400, detail="Invalid status provided.")

    event = db.query(Event).filter(Event.event_id == event_id).first()
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
        
    event.status = new_status 
    
    return {"message": f"Event ID {event_id} status updated to {new_status}."}


# --- 6. Action Endpoint: Block IP (/action/block-ip) ---
@router.post("/action/block-ip")
async def block_ip(ip_data: dict):
    """Blocks a specific IP address."""
    ip_address = ip_data.get("ip_address")
    if not ip_address:
        raise HTTPException(status_code=400, detail="Missing ip_address")
        
    reason = ip_data.get("reason", "Manual block from API")
    duration = ip_data.get("duration_minutes", 15)
    
    try:
        BlockedIPModel.block_ip(ip_address, reason, duration)
        return {"message": f"IP {ip_address} blocked successfully for {duration} minutes."}
    except Exception as e:
        print(f"[ERROR] block_ip: {e}")
        raise HTTPException(status_code=500, detail="Failed to execute IP block operation.")


# --- 7. Action Endpoint: Unblock IP (/action/unblock-ip) ---
@router.post("/action/unblock-ip")
async def unblock_ip(ip_data: dict):
    """Unblocks a specific IP address."""
    ip_address = ip_data.get("ip_address")
    if not ip_address:
        raise HTTPException(status_code=400, detail="Missing ip_address")
    
    try:
        BlockedIPModel.unblock_ip(ip_address) # Gọi hàm từ BlockedIPModel
        return {"message": f"IP {ip_address} unblocked successfully."}
    except Exception as e:
        print(f"[ERROR] unblock_ip: {e}")
        raise HTTPException(status_code=500, detail="Failed to execute IP unblock operation.")


# --- 8. Status Endpoint: Get IP Block Status (/ip/status/{ip_address}) ---
@router.get("/ip/status/{ip_address}", response_model=IPStatusSchema)
async def get_ip_status(ip_address: str):
    """Checks the status of an IP address in the ip_blocked table."""
    try:
        # Lấy tất cả IP trong bảng ip_blocked (bao gồm cả unblocked)
        all_ips = BlockedIPModel.get_all() 
        
        # Tìm IP trong danh sách
        ip_record = next((ip for ip in all_ips if ip['ip_address'] == ip_address), None)
        
        if ip_record:
            # Trả về status từ bảng ip_blocked ('blocked' hoặc 'unblocked')
            return IPStatusSchema(ip_address=ip_address, status=ip_record['status'])
        else:
            # IP không có trong bảng
            return IPStatusSchema(ip_address=ip_address, status='not_found')
    except Exception as e:
        print(f"[ERROR] get_ip_status: {e}")
        # Trả về not_found nếu có lỗi kết nối DB của BlockedIPModel
        return IPStatusSchema(ip_address=ip_address, status='not_found')
    
    
# --- 9. ACTION ENDPOINT: Send Email (/action/send-email/{event_id}) ---
@router.post("/action/send-email/{event_id}")
async def send_incident_email(event_id: int, db: Session = Depends(get_session)):
    """Prepares and sends an email notification for a specific event."""
    
    # 1. Lấy chi tiết sự kiện
    event_detail = get_events_with_attack_type(db, event_id=event_id)
    if not event_detail:
        raise HTTPException(status_code=404, detail="Event not found")
        
    # 2. Chuẩn bị Payload Email tương tự như trong alerts.py/create_raw_alert
    try:
        level = map_severity_to_alert_level(event_detail.severity)
        
        email_payload = {
            "alert_id": f"N/A (Manual for Event {event_id})",
            "event_id": event_detail.event_id,
            "alert_message": f"Manual Email for Incident: {event_detail.attack_type.attack_name}",
            "alert_level": level,
            "sent_at": datetime.datetime.now().isoformat(),
            "timestamp": event_detail.timestamp.isoformat(),
            "severity": event_detail.severity,
            "status": event_detail.status,
            "source_ip": event_detail.source_ip,
            "destination_ip": event_detail.destination_ip,
            "description": event_detail.description,
            "payload_b64": "N/A (Event only)", # Không có payload b64 trong Event Model
            "action": "Sent Manually",
        }
        
        # 3. Gửi email
        # Sử dụng to_thread.run_sync để gọi hàm đồng bộ _send_email_sync trong một luồng
        from anyio import to_thread # Cần import to_thread
        await to_thread.run_sync(_send_email_sync, email_payload)
        
        return {"message": f"Email for Event ID {event_id} sent successfully."}

    except RuntimeError as e:
        # Xử lý trường hợp cấu hình SMTP bị thiếu
        raise HTTPException(status_code=503, detail=f"Email sending failed: SMTP not configured or ALERT_TO missing. Detail: {e}")
    except Exception as e:
        print(f"[ERROR] send_incident_email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send email.")