# app/api/ws.py
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

# Nếu bạn có broadcaster/manager sẵn, import và dùng cho kênh /ws
try:
    from app.core.ws_broadcaster import manager  # phải có methods: connect(), disconnect()
except Exception:
    manager = None  # fallback

router = APIRouter()

# 1) Kênh WS tổng quát (dùng manager nếu có)
@router.websocket("/ws")
async def ws_root(ws: WebSocket):
    if manager:
        await manager.connect(ws)  # manager.connect nên tự ws.accept()
        try:
            while True:
                # chờ client gửi gì đó để giữ kết nối (hoặc bạn có thể sleep + heartbeat)
                await ws.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(ws)
    else:
        # Fallback: accept và gửi heartbeat 10s/lần
        await ws.accept()
        try:
            while True:
                await asyncio.sleep(10)
                await ws.send_json({"name": "Heartbeat", "status": "monitoring", "time_ago": "just now"})
        except WebSocketDisconnect:
            pass

# 2) Kênh tương thích với frontend cũ (tránh 403 vì sai path)
@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    # mở tự do cho test
    await ws.accept()
    try:
        while True:
            await asyncio.sleep(10)
            await ws.send_json({"name": "Heartbeat", "status": "monitoring", "time_ago": "just now"})
    except WebSocketDisconnect:
        pass

# 3) Kênh public (không auth) — bạn đang dùng trong template
@router.websocket("/ws/alerts-public")
async def ws_alerts_public(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            await asyncio.sleep(15)
            await ws.send_json({
                "name": "Heartbeat",
                "status": "monitoring",
                "time_ago": "just now"
            })
    except WebSocketDisconnect:
        pass
