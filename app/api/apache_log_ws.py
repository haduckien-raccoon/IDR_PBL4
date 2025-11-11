#!/usr/bin/env python3
import asyncio
import paramiko
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, APIRouter
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

# --- SSH Config ---
HOST = "10.10.16.231"  
PORT = 22
USER = "ASUS"
PASSWORD = "120605"
KEY_FILE = None 


LOG_FILE = r"D:\Program Files\xampp\apache\logs\error.log"

app = FastAPI()
router = APIRouter(prefix="/api/log-server", tags=["rules"])
templates = Jinja2Templates(directory="app/templates")



@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse("logs.html", {"request": request})

@router.websocket("/ws/logs")
async def websocket_logs(ws: WebSocket):
    await ws.accept()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(HOST, port=PORT, username=USER, password=PASSWORD)
        transport = client.get_transport()
        if not transport:
            await ws.send_text("❌ SSH transport error.")
            await ws.close()
            return

        # ✅ Dùng PowerShell đọc log realtime
        command = (
            f"powershell -NoProfile -ExecutionPolicy Bypass "
            f"-Command \"Get-Content -Path '{LOG_FILE}' -Wait -Tail 100\""
        )

        channel = transport.open_session()
        channel.exec_command(command)

        await ws.send_text(f"✅ Connected to {HOST}, streaming {LOG_FILE} ...")

        while True:
            if channel.recv_ready():
                data = channel.recv(4096).decode(errors="ignore")
                if data.strip():
                    await ws.send_text(data)
            await asyncio.sleep(0.5)

    except Exception as e:
        await ws.send_text(f"⚠️ Error: {e}")
    finally:
        try:
            channel.close()
        except:
            pass
        client.close()
        await ws.close()
