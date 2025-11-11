# app/api/dashboard.py
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

# Đảm bảo bạn import đúng hàm get_session (get_db là bí danh)
from app.database import get_session as get_db

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

WINDOW_DEFAULT = timedelta(hours=24)

def _since(window: str | None) -> datetime:
    """Helper để tính toán mốc thời gian 'since'."""
    if not window:
        return datetime.now(timezone.utc) - WINDOW_DEFAULT
    
    # Chuyển sang now(timezone.utc) để so sánh
    now = datetime.now(timezone.utc)
    
    if window.endswith("h"):
        return now - timedelta(hours=int(window[:-1] or 24))
    if window.endswith("d"):
        return now - timedelta(days=int(window[:-1] or 1))
    return now - WINDOW_DEFAULT

# [SỬA LỖI] Xóa try...except khỏi hàm _count
# Việc này cho phép lỗi (như connection error) được đưa lên
# hàm get_session để xử lý rollback() đúng cách.
def _count(db: Session, q: str, params: dict) -> int:
    """Helper để chạy SQL count."""
    # KHÔNG DÙNG try...except ở đây.
    return db.execute(text(q), params).scalar() or 0

@router.get("/summary")
def summary(window: str | None = Query(None), db: Session = Depends(get_db)):
    """
    API Summary, truy vấn từ bảng 'events' và 'ai_analysis'.
    (Đã sửa cú pháp SQL sang MySQL - bỏ dấu ngoặc kép)
    """
    since = _since(window)
    params = {"since": since}

    # Critical: Đếm events có severity 'critical' hoặc 'high'
    critical = _count(db, """
        SELECT COUNT(*) FROM events
        WHERE timestamp >= :since
          AND severity IN ('critical', 'high')
    """, params)

    # Blocked: (Ánh xạ lại) Đếm events có status = 'new'
    blocked = _count(db, """
        SELECT COUNT(*) FROM events
        WHERE timestamp >= :since
          AND status = 'new'
    """, params)

    # Anomalies: Đếm events được AI đánh giá là 'Suspicious'
    anomalies = _count(db, """
        SELECT COUNT(DISTINCT e.event_id)
        FROM events e
        JOIN ai_analysis a ON e.event_id = a.event_id
        WHERE e.timestamp >= :since
          AND a.prediction = 'Suspicious'
    """, params)

    # Safe: (Ánh xạ lại) Đếm events được AI đánh giá là 'Benign'
    safe = _count(db, """
        SELECT COUNT(DISTINCT e.event_id)
        FROM events e
        JOIN ai_analysis a ON e.event_id = a.event_id
        WHERE e.timestamp >= :since
          AND a.prediction = 'Benign'
    """, params)

    return {"critical": critical, "blocked": blocked, "anomalies": anomalies, "safe": safe}

@router.get("/timeline")
def timeline(limit: int = 10, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """
    Lấy các sự kiện mới nhất, JOIN với 'attack_types' để lấy tên.
    (Đã sửa cú pháp SQL sang MySQL - bỏ dấu ngoặc kép)
    """
    def time_ago(ts):
        """Helper tính 'time_ago'."""
        if not ts: return "just now"
        # Đảm bảo ts là timezone-aware (UTC) nếu nó chưa có
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
            
        delta = datetime.now(timezone.utc) - ts
        s = int(delta.total_seconds())
        if s < 60:  return f"{s}s ago"
        m = s // 60
        if m < 60:  return f"{m}m ago"
        h = m // 60
        if h < 24:  return f"{h}h ago"
        d = h // 24
        return f"{d}d ago"

    try:
        rows = db.execute(text("""
            SELECT 
                t.attack_name AS name,
                e.status,
                e.timestamp AS created_at
            FROM events e
            JOIN attack_types t ON e.attack_id = t.attack_id
            ORDER BY e.timestamp DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()
        
        return [
            {"name": r["name"], "status": r["status"], "time_ago": time_ago(r["created_at"])} 
            for r in rows
        ]
    except Exception as e:
        print(f"SQL Error in timeline: {e}")
        return []

@router.get("/top-ips")
def top_ips(limit: int = 10, db: Session = Depends(get_db)):
    """
    Lấy Top IP tấn công từ 'events.source_ip'.
    (Đã sửa cú pháp SQL sang MySQL - dùng CAST AS CHAR)
    """
    try:
        # Sửa: Dùng CAST(source_ip AS CHAR) thay vì source_ip::text
        rows = db.execute(text("""
            SELECT 
                COALESCE(CAST(source_ip AS CHAR), 'unknown') AS ip,
                COUNT(*) AS cnt
            FROM events
            GROUP BY ip
            ORDER BY cnt DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()
        
        # Trả về country="" để frontend không bị lỗi
        return [{"ip": r["ip"], "country": ""} for r in rows]
    except Exception as e:
        print(f"SQL Error in top_ips: {e}")
        return []

@router.get("/attack-types")
def attack_types(window: str | None = Query(None), db: Session = Depends(get_db)):
    """
    Thống kê loại tấn công.
    (Đã sửa cú pháp SQL sang MySQL - bỏ dấu ngoặc kép)
    """
    since = _since(window)
    try:
        rows = db.execute(text("""
            SELECT 
                COALESCE(t.category, 'Other') AS cat, 
                COUNT(e.event_id) AS cnt
            FROM events e
            JOIN attack_types t ON e.attack_id = t.attack_id
            WHERE e.timestamp >= :since
            GROUP BY cat
            ORDER BY cnt DESC
        """), {"since": since}).mappings().all()
        
        labels = [r["cat"] for r in rows]
        counts = [r["cnt"] for r in rows]
    except Exception as e:
        print(f"SQL Error in attack_types: {e}")
        labels, counts = [], []
        
    return {"labels": labels, "counts": counts}

# Sửa lại hàm traffic trong app/api/dashboard.py

@router.get("/traffic")
def traffic(window: str | None = Query(None), db: Session = Depends(get_db)):
    """
    Thống kê traffic.
    (Đã SỬA LỖI strftime: Chuyển định dạng %H:%M sang SQL
     và Python chỉ đọc chuỗi đã định dạng)
    """
    since = _since(window)
    try:
        # Yêu cầu MySQL 8.0+
        sql = """
            WITH RECURSIVE hours (h_full) AS (
              -- 1. Dùng h_full (datetime) để tính toán
              SELECT DATE_FORMAT(:since, '%Y-%m-%d %H:00:00')
              UNION ALL
              SELECT h_full + INTERVAL 1 HOUR
              FROM hours
              WHERE h_full + INTERVAL 1 HOUR <= UTC_TIMESTAMP()
            ),
            agg AS (
              SELECT 
                  DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') AS h_full,
                  COUNT(*) AS blocked_events
              FROM events
              WHERE timestamp >= :since
              GROUP BY 1
            )
            SELECT 
                -- 2. Định dạng đầu ra h_label (string) sang %H:%i (MySQL cho HH:MM)
                DATE_FORMAT(hours.h_full, '%H:%i') AS h_label, 
                0 AS allowed,
                COALESCE(agg.blocked_events, 0) AS blocked
            FROM hours 
            LEFT JOIN agg ON hours.h_full = agg.h_full
            WHERE hours.h_full <= UTC_TIMESTAMP()
            ORDER BY hours.h_full
        """
        rows = db.execute(text(sql), {"since": since}).mappings().all()
        
        # 3. SỬA LỖI: Python bây giờ chỉ cần đọc chuỗi 'h_label'
        #    Không cần gọi .strftime() nữa.
        labels  = [r["h_label"] for r in rows]
        allowed = [int(r["allowed"]) for r in rows]
        blocked = [int(r["blocked"]) for r in rows]
    except Exception as e:
        print(f"SQL Error in traffic: {e}")
        labels, allowed, blocked = [], [], []
        
    return {"labels": labels, "allowed": allowed, "blocked": blocked}