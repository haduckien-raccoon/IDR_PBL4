from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

# Giả định: Bạn đã có hàm get_session trong app.database
# và bạn muốn dùng nó với bí danh get_db
from app.database import get_session as get_db 

# Loại bỏ các imports không cần thiết từ view-ai.py gốc (asyncio, re, aiofiles, ConnectionManager, AlertParser, app)
# vì chúng ta chuyển sang mô hình REST API sử dụng DB Session.

router = APIRouter(prefix="/api/view_ai", tags=["AI_Events_DB"])

# =========================================
# API Routes for AI Events (REST access)
# =========================================

@router.get("/events", response_model=List[Dict[str, Any]])
async def get_ai_events(
    limit: int = Query(100, ge=1, le=500), # Giới hạn 500 events
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    status: Optional[str] = Query(None, description="Filter by event status (new, investigating, resolved)"),
    db: Session = Depends(get_db)
):
    """
    Retrieves a list of recent security events detected ONLY by AI, 
    with optional filtering by severity and status.
    """
    
    # 1. Khởi tạo truy vấn cơ bản, lọc cứng theo detected_by = 'AI'
    sql_base = """
        SELECT 
            e.event_id,
            e.timestamp,
            e.source_ip,
            e.destination_ip,
            e.severity,
            e.description,
            e.detected_by,
            e.status,
            e.attack_id
        FROM events e
        WHERE e.detected_by = 'AI'
    """
    params = {}
    where_clauses = []

    # 2. Xây dựng các điều kiện lọc bổ sung
    
    # Lọc theo Severity
    if severity:
        # Đảm bảo severity nằm trong phạm vi enum
        valid_severity = ['low', 'medium', 'high', 'critical']
        if severity.lower() not in valid_severity:
             raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}. Must be one of {', '.join(valid_severity)}")
        where_clauses.append("e.severity = :severity_val")
        params["severity_val"] = severity.lower()
        
    # Lọc theo Status
    if status:
        # Đảm bảo status nằm trong phạm vi enum
        valid_status = ['new', 'investigating', 'resolved']
        if status.lower() not in valid_status:
             raise HTTPException(status_code=400, detail=f"Invalid status: {status}. Must be one of {', '.join(valid_status)}")
        where_clauses.append("e.status = :status_val")
        params["status_val"] = status.lower()

    # 3. Tổng hợp truy vấn
    if where_clauses:
        sql_base += " AND " + " AND ".join(where_clauses)
        
    # Sắp xếp theo thời gian mới nhất và giới hạn
    sql_query = f"""
        {sql_base}
        ORDER BY e.timestamp DESC
        LIMIT :limit_val
    """
    params["limit_val"] = limit

    try:
        # 4. Thực thi truy vấn
        rows = db.execute(text(sql_query), params).mappings().all()
        
        # 5. Chuyển đổi kết quả sang định dạng JSON/Dict
        results = []
        for r in rows:
            # Chuyển đổi các cột từ SQLAlchemy RowMapping sang dict
            event_dict = dict(r)
            # Chuyển đổi datetime sang ISO format để FastAPI/JSON xử lý
            if event_dict.get("timestamp"):
                event_dict["timestamp"] = event_dict["timestamp"].isoformat()
            
            # Đổi tên cột source_ip/destination_ip thành src/dst cho khớp với frontend
            # (Mặc dù frontend nên dùng source_ip/destination_ip, nhưng ta làm theo event.py)
            event_dict["src"] = event_dict.pop("source_ip", None)
            event_dict["dst"] = event_dict.pop("destination_ip", None)
            
            # Thêm các trường giả lập/tên khác mà frontend view-ai.html mong đợi
            # Lưu ý: 'variant' và 'entropy' không có trong Event model. Ta giả lập/dùng giá trị mặc định.
            event_dict["variant"] = f"AttackType_{event_dict.get('attack_id', 'Unknown')}"
            event_dict["entropy"] = "N/A" # Không có trong Event model
            event_dict["message"] = event_dict.pop("description", "AI Event") # Lấy description làm message
            event_dict["level"] = event_dict.pop("severity").upper() # Severity -> Level (CRITICAL, HIGH, MEDIUM, LOW)
            
            results.append(event_dict)

        return results

    except Exception as e:
        # In lỗi chi tiết trong log server
        print(f"SQL Error retrieving AI events: {e}")
        # Trả về lỗi 500 cho client
        raise HTTPException(status_code=500, detail="Database error retrieving AI events.")


@router.get("/events/{event_id}", response_model=Dict[str, Any])
async def get_event_by_id(event_id: int, db: Session = Depends(get_db)):
    """
    Retrieves details for a specific event by its ID.
    """
    sql_query = """
        SELECT 
            e.event_id,
            e.timestamp,
            e.source_ip,
            e.destination_ip,
            e.severity,
            e.description,
            e.detected_by,
            e.status
        FROM events e
        WHERE e.event_id = :event_id_val
          AND e.detected_by = 'AI'
    """
    
    row = db.execute(text(sql_query), {"event_id_val": event_id}).mappings().first()
    
    if not row:
        raise HTTPException(status_code=404, detail=f"AI Event with ID {event_id} not found.")

    # Chuyển đổi và định dạng lại kết quả tương tự như hàm trên
    found_event = dict(row)
    if found_event.get("timestamp"):
        found_event["timestamp"] = found_event["timestamp"].isoformat()
        
    return JSONResponse(content=found_event)

# WebSocket: Không cần thiết cho việc hiển thị bảng sự kiện từ DB, đã bị loại bỏ.