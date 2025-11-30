# app/api/ssh_terminal.py

import asyncio
import paramiko
from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect

router = APIRouter(prefix="/ssh", tags=["SSH"])

@router.websocket("/terminal")
async def ssh_terminal(websocket: WebSocket):
    await websocket.accept()
    
    # 1. Lấy thông tin từ Query Params (URL gửi lên từ JS)
    params = websocket.query_params
    ssh_host = params.get("host")
    ssh_port = int(params.get("port", 22))
    ssh_user = params.get("user")
    ssh_password = params.get("password")

    # Kiểm tra dữ liệu đầu vào
    if not ssh_host or not ssh_user or not ssh_password:
        await websocket.send_text("\r\n\x1b[31mError: Missing connection parameters (host, user, password).\x1b[0m\r\n")
        await websocket.close()
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 2. Kết nối SSH với thông tin động
        await websocket.send_text(f"Connecting to {ssh_host}...\r\n") # Log nhẹ ra màn hình
        
        ssh.connect(
            ssh_host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10 # Set timeout tránh treo
        )

        # ... (Phần còn lại giữ nguyên như cũ) ...
        chan = ssh.invoke_shell(term='xterm')
        
        async def reader():
            try:
                while True:
                    data = await asyncio.to_thread(chan.recv, 1024)
                    if not data:
                        break
                    await websocket.send_text(data.decode("utf-8", errors="ignore"))
            except Exception:
                pass

        reader_task = asyncio.create_task(reader())

        try:
            while True:
                msg = await websocket.receive_text()
                await asyncio.to_thread(chan.send, msg)
        except WebSocketDisconnect:
            pass
        finally:
            reader_task.cancel()
            ssh.close()

    except Exception as e:
        await websocket.send_text(f"\r\n\x1b[31m*** SSH connection failed: {e} ***\x1b[0m\r\n")
        await websocket.close()