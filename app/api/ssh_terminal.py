# app/api/ssh_terminal.py

import asyncio
import paramiko
from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect

router = APIRouter(prefix="/ssh", tags=["SSH"])

# TODO: sau này bạn có thể lấy những thông tin này từ DB / .env
SSH_HOST = "192.168.1.8"   # máy chủ cần bảo vệ
SSH_PORT = 22
SSH_USER = "hieu"        # user trên server đó
SSH_PASSWORD = "120605"  # tạm thời hard-code để demo


@router.websocket("/terminal")
async def ssh_terminal(websocket: WebSocket):
    """
    WebSocket bridge giữa trình duyệt và SSH server.
    """
    await websocket.accept()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 1. Kết nối SSH tới server cần bảo vệ
        ssh.connect(
            SSH_HOST,
            port=SSH_PORT,
            username=SSH_USER,
            password=SSH_PASSWORD,
            look_for_keys=False,
            allow_agent=False,
        )

        # 2. Mở shell tương tác
        chan = ssh.invoke_shell(term='xterm')
        # chan là blocking; ta dùng asyncio.to_thread để đọc/ghi không chặn event loop

        async def reader():
            """Đọc output từ SSH và gửi về browser."""
            try:
                while True:
                    # chạy recv trong thread riêng
                    data = await asyncio.to_thread(chan.recv, 1024)
                    if not data:
                        await asyncio.sleep(0.05)
                        continue
                    # gửi text về client
                    await websocket.send_text(data.decode("utf-8", errors="ignore"))
            except Exception:
                # SSH đóng / WebSocket đóng -> thoát
                pass

        reader_task = asyncio.create_task(reader())

        # 3. Nhận input từ browser và gửi vào SSH
        try:
            while True:
                msg = await websocket.receive_text()
                # gửi từng phím/lệnh vào shell SSH
                await asyncio.to_thread(chan.send, msg)
        except WebSocketDisconnect:
            pass
        finally:
            reader_task.cancel()
            try:
                chan.close()
            except Exception:
                pass
            ssh.close()

    except Exception as e:
        # Nếu không SSH được thì báo lỗi lên terminal
        await websocket.send_text(f"\r\n*** SSH connection error: {e} ***\r\n")
        await websocket.close()
