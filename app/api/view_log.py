import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List

import aiofiles
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, APIRouter
from fastapi.responses import HTMLResponse

app = FastAPI()

router = APIRouter(prefix="/api/logs", tags=["Logs"])

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"


# =========================================
# Connection Manager
# =========================================
class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {"traffic": [], "alerts": []}

    async def connect(self, ws: WebSocket, type_: str):
        await ws.accept()
        self.connections[type_].append(ws)

    def disconnect(self, ws: WebSocket, type_: str):
        if ws in self.connections[type_]:
            self.connections[type_].remove(ws)

    async def broadcast(self, type_: str, data: str):
        for ws in list(self.connections[type_]):
            try:
                await ws.send_text(data)
            except Exception:
                self.disconnect(ws, type_)


manager = ConnectionManager()


# =========================================
# Parsers
# =========================================
class TrafficParser:
    RE_HEADER = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+\[(?P<level>[A-Z]+)\]\s+TRAFFIC\s+'
        r'proto=(?P<proto>\w+)\s+(?P<src>[0-9a-fA-F\.:]+:[0-9]+)->(?P<dst>[0-9a-fA-F\.:]+:[0-9]+)\s+'
        r'entropy=(?P<entropy>[0-9.]+)\s+bytes=(?P<bytes>\d+)'
    )
    RE_HEX = re.compile(r'^[0-9a-fA-F]{8}\s+([0-9a-fA-F]{2}\s+){1,}.*$')

    @classmethod
    def parse_header(cls, line: str):
        m = cls.RE_HEADER.match(line.strip())
        if not m:
            return None
        return {
            "timestamp": m.group("ts"),
            "level": m.group("level"),
            # "proto": m.group("proto"),
            "proto": "TCP" if m.group("proto") == "6" else "UDP" if m.group("proto") == "17" else m.group("proto"),
            "src": m.group("src"),
            "dst": m.group("dst"),
            "entropy": m.group("entropy"),
            "bytes": m.group("bytes"),
        }

    @classmethod
    def is_hexdump_header(cls, line: str):
        return line.strip().lower().startswith("hexdump:")

    @classmethod
    def is_hex_line(cls, line: str):
        return bool(cls.RE_HEX.match(line))


class AlertParser:
    RE_HEADER = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+\[(?P<level>[A-Z]+)\]\s+ALERT\s+\[(?P<id>[^\]]+)\]\s+(?P<msg>.+?)\s*\|\s*proto=(?P<proto>\w+)\s+(?P<src>[0-9a-fA-F\.:]+:[0-9]+)->(?P<dst>[0-9a-fA-F\.:]+:[0-9]+)\s+variant=(?P<variant>\S+)\s+entropy=(?P<entropy>[0-9.]+)'
    )
    RE_HEX = re.compile(r'^[0-9a-fA-F]{8}\s+([0-9a-fA-F]{2}\s+){1,}.*$')

    @classmethod
    def parse_header(cls, line: str):
        m = cls.RE_HEADER.match(line.strip())
        if not m:
            return None
        return {
            "timestamp": m.group("ts"),
            "level": m.group("level"),
            "alert_id": m.group("id"),
            "message": m.group("msg"),
            # "proto": m.group("proto"),
            #fix lai sao cho 6 la TCP va 17 la UDP
            "proto": "TCP" if m.group("proto") == "6" else "UDP" if m.group("proto") == "17" else m.group("proto"),
            "src": m.group("src"),
            "dst": m.group("dst"),
            "variant": m.group("variant"),
            "entropy": m.group("entropy"),
        }

    @classmethod
    def is_hexdump_header(cls, line: str):
        return line.strip().lower().startswith("hexdump:")

    @classmethod
    def is_hex_line(cls, line: str):
        return bool(cls.RE_HEX.match(line))


# =========================================
# Log Tailer
# =========================================
class LogTailer:
    def __init__(self, filepath: Path, manager: ConnectionManager, parser, type_: str):
        self.filepath = filepath
        self.manager = manager
        self.parser = parser
        self.type_ = type_

    async def load_recent_logs(self, count=1000):
        if not self.filepath.exists():
            return []

        async with aiofiles.open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = await f.readlines()

        logs = []
        buffer_header = None
        hexdump_lines = []
        in_hexdump = False

        for line in reversed(lines):
            line = line.rstrip("\n")
            parsed = self.parser.parse_header(line)
            if parsed:
                if buffer_header:
                    logs.append(
                        {"header": buffer_header, "body": "\n".join(reversed(hexdump_lines))}
                    )
                buffer_header = parsed
                hexdump_lines = []
                in_hexdump = False
                continue

            if buffer_header:
                if self.parser.is_hex_line(line):
                    hexdump_lines.append(line)
                    in_hexdump = True
                    continue
                if self.parser.is_hexdump_header(line):
                    in_hexdump = True
                    continue

        if buffer_header:
            logs.append({"header": buffer_header, "body": "\n".join(reversed(hexdump_lines))})

        return list(reversed(logs[-count:]))

    async def start(self):
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        if not self.filepath.exists():
            self.filepath.touch()

        async with aiofiles.open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            await f.seek(0, 2)
            buffer_header = None
            hexdump_lines = []
            in_hexdump = False

            while True:
                line = await f.readline()
                if not line:
                    await asyncio.sleep(0.3)
                    continue
                line = line.rstrip("\n")

                parsed = self.parser.parse_header(line)
                if parsed:
                    if buffer_header:
                        await self._flush(buffer_header, hexdump_lines)
                    buffer_header = parsed
                    hexdump_lines = []
                    in_hexdump = False
                    continue

                if buffer_header and self.parser.is_hexdump_header(line):
                    in_hexdump = True
                    continue

                if in_hexdump and self.parser.is_hex_line(line):
                    hexdump_lines.append(line)
                    continue

                if buffer_header and not line.strip():
                    await self._flush(buffer_header, hexdump_lines)
                    buffer_header = None
                    hexdump_lines = []
                    in_hexdump = False

    async def _flush(self, header: Dict[str, Any], hexdump: List[str]):
        obj = dict(header)
        if hexdump:
            obj["body"] = "\n".join(hexdump)
        await self.manager.broadcast(self.type_, json.dumps(obj))


# =========================================
# WebSocket Routes
# =========================================
@router.websocket("/ws/traffic")
async def ws_traffic(ws: WebSocket):
    await manager.connect(ws, "traffic")
    try:
        for obj in getattr(app.state, "traffic_recent", []):
            await ws.send_text(json.dumps(obj))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws, "traffic")


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await manager.connect(ws, "alerts")
    try:
        for obj in getattr(app.state, "alerts_recent", []):
            await ws.send_text(json.dumps(obj))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws, "alerts")


# =========================================
# HTML Routes
# =========================================
@router.get("/traffic")
async def traffic_page():
    #print path
    print(Path(__file__).parent.parent / "templates" / "packets.html")
    html = Path(__file__).parent.parent / "templates" / "packets.html"
    return HTMLResponse(html.read_text())


@router.get("/alerts")
async def alerts_page():
    html = Path(__file__).parent.parent / "templates" / "alerts.html"
    return HTMLResponse(html.read_text())

# @router.get("/alerts_ai")
# async def alerts_ai_page():
#     html = Path(__file__).parent.parent / "templates" / "alerts_ai.html"
#     return HTMLResponse(html.read_text())
# =========================================
# Startup event
# =========================================
@router.on_event("startup")
async def startup_event():
    base = Path(__file__).parent.parent / "logs"

    traffic_tailer = LogTailer(base / "traffic.log", manager, TrafficParser, "traffic")
    alert_tailer = LogTailer(base / "alerts.log", manager, AlertParser, "alerts")

    asyncio.create_task(traffic_tailer.start())
    asyncio.create_task(alert_tailer.start())

    app.state.traffic_recent = [
        {**entry["header"], "body": entry.get("body", "")}
        for entry in await traffic_tailer.load_recent_logs(1000)
    ]
    app.state.alerts_recent = [
        {**entry["header"], "body": entry.get("body", "")}
        for entry in await alert_tailer.load_recent_logs(1000)
    ]


# =========================================
# Run standalone
# =========================================
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("app.api.view_log:app", host="0.0.0.0", port=8000, reload=True)
