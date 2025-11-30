import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

# Router cho toàn bộ chức năng xem log
router = APIRouter(prefix="/logs", tags=["Logs"])

# Giữ tối đa bao nhiêu bản ghi gần nhất trong bộ nhớ
MAX_RECENT = 5000

# History cho 2 loại log (dùng cho client mới connect vào WS)
traffic_recent: List[Dict[str, Any]] = []
alerts_recent: List[Dict[str, Any]] = []


# ============================================================
# Quản lý kết nối WebSocket
# ============================================================
class ConnectionManager:
    def __init__(self) -> None:
        self.connections: Dict[str, List[WebSocket]] = {
            "traffic": [],
            "alerts": [],
        }

    async def connect(self, ws: WebSocket, type_: str) -> None:
        await ws.accept()
        self.connections[type_].append(ws)

    def disconnect(self, ws: WebSocket, type_: str) -> None:
        if ws in self.connections[type_]:
            self.connections[type_].remove(ws)

    async def broadcast(self, type_: str, data: str) -> None:
        """Gửi dữ liệu JSON string tới tất cả client của 1 loại."""
        for ws in list(self.connections[type_]):
            try:
                await ws.send_text(data)
            except Exception:
                # nếu lỗi (client đóng), loại khỏi danh sách
                self.disconnect(ws, type_)


manager = ConnectionManager()


# ============================================================
# Parser cho traffic.log
# ============================================================
class TrafficParser:
    """
    Ví dụ dòng header:
    2025-11-11 15:41:25,771 [TRAFFIC] TRAFFIC proto=TCP 91.189.91.81:80->10.10.30.195:37284 entropy=4.726 bytes=1448
    """

    RE_HEADER = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+'
        r'\[(?P<level>[A-Z]+)\]\s+TRAFFIC\s+'
        r'proto=(?P<proto>\w+)\s+'
        r'(?P<src>[0-9a-fA-F\.:]+:[0-9]+)->(?P<dst>[0-9a-fA-F\.:]+:[0-9]+)\s+'
        r'entropy=(?P<entropy>[0-9\.]+)\s+bytes=(?P<bytes>\d+)'
    )
    RE_HEX = re.compile(r'^[0-9a-fA-F]{8}\s+([0-9a-fA-F]{2}\s+){1,}.*$')

    @classmethod
    def parse_header(cls, line: str) -> Optional[Dict[str, Any]]:
        m = cls.RE_HEADER.match(line.strip())
        if not m:
            return None

        proto_raw = m.group("proto")
        if proto_raw == "6":
            proto = "TCP"
        elif proto_raw == "17":
            proto = "UDP"
        else:
            proto = proto_raw

        return {
            "timestamp": m.group("ts"),
            "level": m.group("level"),
            "proto": proto,
            "src": m.group("src"),
            "dst": m.group("dst"),
            "entropy": m.group("entropy"),
            "bytes": m.group("bytes"),
        }

    @staticmethod
    def is_hexdump_header(line: str) -> bool:
        return line.strip().lower().startswith("hexdump:")

    @classmethod
    def is_hex_line(cls, line: str) -> bool:
        return bool(cls.RE_HEX.match(line))


# ============================================================
# Parser cho ai_alerts.log
# ============================================================
class AlertParser:
    """
    Parser linh hoạt cho alert log.

    Ví dụ (xấp xỉ):
    2025-10-14 16:27:20,842 [ALERT] ALERT [SQLI_C-OBFUSCATION-001] ... proto=TCP 1.2.3.4:80->5.6.7.8:443 variant=SQLI_C entropy=4.53 bytes=123
    """

    RE_HEADER = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+'
        r'\[(?P<level>[A-Z]+)\]\s+'
        r'(?P<rest>.*)$'
    )
    RE_HEX = re.compile(r'^[0-9a-fA-F]{8}\s+([0-9a-fA-F]{2}\s+){1,}.*$')

    @classmethod
    def parse_header(cls, line: str) -> Optional[Dict[str, Any]]:
        m = cls.RE_HEADER.match(line.strip())
        if not m:
            return None

        rest = m.group("rest")

        alert_id = None
        message = rest
        proto = None
        src = None
        dst = None
        variant = None
        entropy = None

        # RULE ID trong []
        m_id = re.search(r'\[(?P<id>[^\]]+)\]', rest)
        if m_id:
            alert_id = m_id.group("id")

        # proto=...
        m_proto = re.search(r'\bproto=(\w+)', rest)
        if m_proto:
            proto = m_proto.group(1)

        # src->dst
        m_flow = re.search(r'([0-9a-fA-F\.:]+:[0-9]+)->([0-9a-fA-F\.:]+:[0-9]+)', rest)
        if m_flow:
            src, dst = m_flow.group(1), m_flow.group(2)

        # variant=...
        m_var = re.search(r'\bvariant=([^\s]+)', rest)
        if m_var:
            variant = m_var.group(1)

        # entropy=...
        m_ent = re.search(r'\bentropy=([0-9\.]+)', rest)
        if m_ent:
            entropy = m_ent.group(1)

        # làm gọn message: bỏ RULE ID và các cặp key=value phổ biến
        tmp = rest
        if m_id:
            tmp = tmp.replace(f"[{m_id.group(1)}]", "").strip()
        tmp = re.sub(r'\b(proto|variant|entropy|bytes|sid|gid|rev)=[^\s]+', "", tmp)
        tmp = re.sub(r'\s+', " ", tmp).strip()
        if tmp:
            message = tmp

        if proto == "6":
            proto_fmt = "TCP"
        elif proto == "17":
            proto_fmt = "UDP"
        else:
            proto_fmt = proto or "-"

        return {
            "timestamp": m.group("ts"),
            "level": m.group("level"),
            "alert_id": alert_id or "-",
            "message": message,
            "proto": proto_fmt,
            "src": src or "-",
            "dst": dst or "-",
            "variant": variant or "-",
            "entropy": entropy or "-",
        }

    @staticmethod
    def is_hexdump_header(line: str) -> bool:
        return line.strip().lower().startswith("hexdump:")

    @classmethod
    def is_hex_line(cls, line: str) -> bool:
        return bool(cls.RE_HEX.match(line))


# ============================================================
# LogTailer: đọc file giống `tail -f`
# ============================================================
class LogTailer:
    def __init__(
        self,
        filepath: Path,
        parser,
        type_: str,
        history_list: List[Dict[str, Any]],
        recent_cap: int = MAX_RECENT,
    ) -> None:
        self.filepath = filepath
        self.parser = parser
        self.type_ = type_
        self.history_list = history_list
        self.recent_cap = recent_cap

    async def load_recent_logs(self, count: int = 10000) -> List[Dict[str, Any]]:
        """
        Đọc phần cuối file (tương đương `tail -n`) rồi parse thành
        các block header + hexdump.
        """
        if not self.filepath.exists():
            return []

        to_read = 8192
        data = b""

        try:
            async with aiofiles.open(self.filepath, "rb") as f:
                await f.seek(0, os.SEEK_END)
                file_size = await f.tell()
                pos = file_size

                while pos > 0 and data.count(b"\n") <= count * 3:
                    read_size = min(to_read, pos)
                    pos -= read_size
                    await f.seek(pos)
                    chunk = await f.read(read_size)
                    data = chunk + data
                    if pos == 0:
                        break
        except FileNotFoundError:
            return []

        lines = data.decode("utf-8", errors="replace").splitlines()

        logs: List[Dict[str, Any]] = []
        buffer_header: Optional[Dict[str, Any]] = None
        hexdump_lines: List[str] = []
        in_hexdump = False

        for line in lines[-count * 3 :]:
            header = self.parser.parse_header(line)
            if header:
                if buffer_header:
                    logs.append(
                        {
                            "header": buffer_header,
                            "body": "\n".join(hexdump_lines) if hexdump_lines else "",
                        }
                    )
                buffer_header = header
                hexdump_lines = []
                in_hexdump = False
                continue

            if self.parser.is_hexdump_header(line):
                in_hexdump = True
                continue

            if in_hexdump and self.parser.is_hex_line(line):
                hexdump_lines.append(line)
                continue

        if buffer_header:
            logs.append(
                {
                    "header": buffer_header,
                    "body": "\n".join(hexdump_lines) if hexdump_lines else "",
                }
            )

        return logs

    async def start(self) -> None:
        """
        Tail realtime giống `tail -f`.
        """
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        if not self.filepath.exists():
            self.filepath.touch()

        async with aiofiles.open(
            self.filepath, "r", encoding="utf-8", errors="replace"
        ) as f:
            # nhảy tới cuối file
            await f.seek(0, os.SEEK_END)
            last_pos = await f.tell()

            header: Optional[Dict[str, Any]] = None
            hexbuf: List[str] = []
            inhex = False

            while True:
                try:
                    # phát hiện file bị truncate/rotate
                    try:
                        curr_size = os.path.getsize(self.filepath)
                    except FileNotFoundError:
                        curr_size = 0
                    if curr_size < last_pos:
                        await f.seek(0)
                        last_pos = 0

                    line = await f.readline()
                    if not line:
                        await asyncio.sleep(0.2)
                        continue

                    last_pos = await f.tell()
                    line = line.rstrip("\n")

                    new_header = self.parser.parse_header(line)
                    if new_header:
                        if header:
                            await self._flush(header, hexbuf)
                        header = new_header
                        hexbuf = []
                        inhex = False
                        continue

                    if header is None:
                        # bỏ qua cho tới khi gặp header đầu tiên
                        continue

                    if self.parser.is_hexdump_header(line):
                        inhex = True
                        continue

                    if inhex and self.parser.is_hex_line(line):
                        hexbuf.append(line)
                        continue

                    if not line.strip():
                        if header:
                            await self._flush(header, hexbuf)
                        header = None
                        hexbuf = []
                        inhex = False
                        continue
                except Exception:
                    # không để tailer chết vì lỗi bất ngờ
                    await asyncio.sleep(0.2)

    async def _flush(self, header: Dict[str, Any], hexdump: List[str]) -> None:
        obj = dict(header)
        obj["body"] = "\n".join(hexdump) if hexdump else ""

        # broadcast qua WS
        await manager.broadcast(self.type_, json.dumps(obj))

        # cập nhật history
        self.history_list.append(obj)
        if len(self.history_list) > self.recent_cap:
            # giữ lại recent_cap phần tử cuối
            del self.history_list[: len(self.history_list) - self.recent_cap]


# ============================================================
# WebSocket endpoints
# ============================================================
@router.websocket("/ws/traffic")
async def ws_traffic(ws: WebSocket):
    await manager.connect(ws, "traffic")
    try:
        # gửi history cho client mới
        for obj in traffic_recent:
            await ws.send_text(json.dumps(obj))

        # giữ kết nối mở; client không cần gửi gì
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws, "traffic")


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await manager.connect(ws, "alerts")
    try:
        for obj in alerts_recent:
            await ws.send_text(json.dumps(obj))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws, "alerts")


# ============================================================
# HTTP endpoints trả HTML
# ============================================================
@router.get("/traffic")
async def traffic_page():
    html_path = Path(__file__).parent.parent / "templates" / "packets.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@router.get("/alerts")
async def alerts_page():
    html_path = Path(__file__).parent.parent / "templates" / "alerts.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


# ============================================================
# Hàm khởi động tailer (sẽ được gọi từ main.lifespan)
# ============================================================
async def start_log_tailers() -> None:
    """
    Được gọi một lần khi ứng dụng khởi động (từ main.lifespan).

    - Tiền xử lý: đọc history hiện có trong file log.
    - Tạo background task tail realtime cho traffic.log và ai_alerts.log.
    """
    base = Path(__file__).parent.parent / "logs"

    traffic_tailer = LogTailer(
        base / "traffic.log",
        TrafficParser,
        "traffic",
        traffic_recent,
        recent_cap=MAX_RECENT,
    )
    alert_tailer = LogTailer(
        base / "ai_alerts.log",
        AlertParser,
        "alerts",
        alerts_recent,
        recent_cap=MAX_RECENT,
    )

    # nạp sẵn lịch sử
    traffic_recent[:] = [
        {**entry["header"], "body": entry.get("body", "")}
        for entry in await traffic_tailer.load_recent_logs(MAX_RECENT)
    ]
    alerts_recent[:] = [
        {**entry["header"], "body": entry.get("body", "")}
        for entry in await alert_tailer.load_recent_logs(MAX_RECENT)
    ]

    # khởi động tailer background
    asyncio.create_task(traffic_tailer.start())
    asyncio.create_task(alert_tailer.start())
