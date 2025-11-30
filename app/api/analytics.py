# app/api/analytics.py
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database import get_session as get_db

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

def get_date_range(mode: str, start_date: Optional[str], end_date: Optional[str]):
    """Helper xác định khoảng thời gian start/end"""
    now = datetime.now(timezone.utc)
    
    if mode == "custom" and start_date and end_date:
        # Parse chuỗi YYYY-MM-DD
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) # Hết ngày cuối
        return start, end
        
    if mode == "7d":
        return now - timedelta(days=7), now
    if mode == "90d":
        return now - timedelta(days=90), now
    
    # Mặc định 30 ngày
    return now - timedelta(days=30), now

@router.get("/trend")
def attack_trend(
    mode: str = "30d", 
    from_date: str = None, 
    to_date: str = None, 
    db: Session = Depends(get_db)
):
    """Thống kê số lượng tấn công theo ngày"""
    start, end = get_date_range(mode, from_date, to_date)
    params = {"start": start, "end": end}
    
    try:
        # Group theo ngày (MySQL: DATE_FORMAT)
        sql = """
            SELECT DATE_FORMAT(timestamp, '%Y-%m-%d') as day_label, COUNT(*) as cnt
            FROM events
            WHERE timestamp BETWEEN :start AND :end
            GROUP BY day_label
            ORDER BY day_label ASC
        """
        rows = db.execute(text(sql), params).mappings().all()
        return {
            "labels": [r["day_label"] for r in rows],
            "data": [r["cnt"] for r in rows]
        }
    except Exception as e:
        print(f"Error analytics trend: {e}")
        return {"labels": [], "data": []}

@router.get("/severity")
def severity_dist(
    mode: str = "30d", 
    from_date: str = None, 
    to_date: str = None, 
    db: Session = Depends(get_db)
):
    """Phân bố mức độ nghiêm trọng"""
    start, end = get_date_range(mode, from_date, to_date)
    try:
        sql = """
            SELECT severity, COUNT(*) as cnt
            FROM events
            WHERE timestamp BETWEEN :start AND :end
            GROUP BY severity
        """
        rows = db.execute(text(sql), {"start": start, "end": end}).mappings().all()
        
        # Chuẩn hóa dữ liệu về chữ thường để frontend dễ map màu
        data = {r["severity"].lower(): r["cnt"] for r in rows}
        return data # vd: {"critical": 5, "low": 100}
    except Exception:
        return {}

@router.get("/top-countries")
def top_countries(
    mode: str = "30d", 
    from_date: str = None, 
    to_date: str = None, 
    db: Session = Depends(get_db)
):
    """Top quốc gia (Nếu chưa có cột country, ta group theo IP tạm)"""
    start, end = get_date_range(mode, from_date, to_date)
    try:
        # Nếu bạn chưa có cột country, dùng source_ip. 
        # Nếu đã có, đổi 'source_ip' thành 'country'
        sql = """
            SELECT source_ip as label, COUNT(*) as cnt
            FROM events
            WHERE timestamp BETWEEN :start AND :end
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 5
        """
        rows = db.execute(text(sql), {"start": start, "end": end}).mappings().all()
        return {
            "labels": [r["label"] for r in rows],
            "data": [r["cnt"] for r in rows]
        }
    except Exception:
        return {"labels": [], "data": []}

@router.get("/heatmap")
def heatmap_data(
    mode: str = "30d", 
    from_date: str = None, 
    to_date: str = None, 
    db: Session = Depends(get_db)
):
    """Dữ liệu cho Heatmap: Ngày trong tuần (0-6) x Giờ trong ngày (0-23)"""
    start, end = get_date_range(mode, from_date, to_date)
    try:
        # MySQL: WEEKDAY() trả về 0=Mon, 6=Sun. HOUR() trả về 0-23
        sql = """
            SELECT WEEKDAY(timestamp) as wday, HOUR(timestamp) as hour, COUNT(*) as cnt
            FROM events
            WHERE timestamp BETWEEN :start AND :end
            GROUP BY wday, hour
        """
        rows = db.execute(text(sql), {"start": start, "end": end}).mappings().all()
        
        # Trả về mảng objects để JS xử lý
        return [{"day": r["wday"], "hour": r["hour"], "value": r["cnt"]} for r in rows]
    except Exception:
        return []