import asyncio
import json
import re
import os
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

# how many recent entries to keep in memory for new WS clients
MAX_RECENT = 1000


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
    def __init__(self, filepath: Path, manager: ConnectionManager, parser, type_: str, recent_cap: int = MAX_RECENT):
        self.filepath = filepath
        self.manager = manager
        self.parser = parser
        self.type_ = type_
        self.recent_cap = recent_cap

    async def load_recent_logs(self, count: int = 1000) -> List[Dict[str, Any]]:
        """
        Efficiently read the last `count` lines from the file (like `tail -n count`),
        then parse them into blocks (header + optional hexdump).
        Returns list of {'header': ..., 'body': '...'} in chronological order.
        """
        if not self.filepath.exists():
            return []

        # read last bytes until we have enough lines
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
        except Exception:
            # fallback to simple readlines (safer but slower)
            async with aiofiles.open(self.filepath, "r", encoding="utf-8", errors="replace") as ftext:
                lines = await ftext.readlines()
            text_lines = [ln.rstrip("\n") for ln in lines]
        else:
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = data.decode(errors="replace")
            text_lines = text.splitlines()

        # take last `count` lines
        tail_lines = text_lines[-count:]

        # parse lines into blocks
        logs: List[Dict[str, Any]] = []
        buffer_header = None
        hexdump_lines: List[str] = []
        in_hexdump = False

        for line in tail_lines:
            parsed = self.parser.parse_header(line)
            if parsed:
                # if there is a previous header buffered, push it
                if buffer_header:
                    logs.append({"header": buffer_header, "body": "\n".join(hexdump_lines) if hexdump_lines else ""})
                buffer_header = parsed
                hexdump_lines = []
                in_hexdump = False
                continue

            if buffer_header:
                if self.parser.is_hexdump_header(line):
                    in_hexdump = True
                    continue
                if in_hexdump and self.parser.is_hex_line(line):
                    hexdump_lines.append(line)
                    continue
                # non-hex, non-header: ignore (could be other messages)

        # push last buffered
        if buffer_header:
            logs.append({"header": buffer_header, "body": "\n".join(hexdump_lines) if hexdump_lines else ""})

        return logs

    async def start(self):
        """
        Start tailing the file like `tail -f`.
        - jump to EOF on start
        - poll quickly for new lines (small sleep)
        - detect truncate/rotate and seek to start
        - parse headers and hexdump blocks, flush immediately on header or blank line
        - broadcast via WebSocket manager and maintain app.state.<type>_recent
        """
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        if not self.filepath.exists():
            self.filepath.touch()

        async with aiofiles.open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            # move to end (like tail -f)
            await f.seek(0, os.SEEK_END)
            last_pos = await f.tell()

            header = None
            hexbuf: List[str] = []
            inhex = False

            while True:
                try:
                    # handle truncate/rotate: if file shrank, seek to start
                    try:
                        curr_size = os.path.getsize(self.filepath)
                    except FileNotFoundError:
                        curr_size = 0
                    if curr_size < last_pos:
                        # file rotated/truncated
                        await f.seek(0)
                        last_pos = 0

                    await f.seek(last_pos)
                    line = await f.readline()
                    if not line:
                        # no new data
                        await asyncio.sleep(0.05)  # 50ms poll for near-realtime
                        continue

                    last_pos = await f.tell()
                    line = line.rstrip("\n")

                    parsed = self.parser.parse_header(line)
                    if parsed:
                        # new header -> flush previous block immediately
                        if header:
                            await self._flush(header, hexbuf)
                        header = parsed
                        hexbuf = []
                        inhex = False
                        continue

                    # detect hexdump header
                    if header and self.parser.is_hexdump_header(line):
                        inhex = True
                        continue

                    # accumulate hex lines
                    if inhex and self.parser.is_hex_line(line):
                        hexbuf.append(line)
                        continue

                    # blank line ends block -> flush
                    if header and not line.strip():
                        await self._flush(header, hexbuf)
                        header = None
                        hexbuf = []
                        inhex = False
                        continue

                    # if any other non-header lines appear while not in hex mode, ignore
                except Exception:
                    # don't crash the tailer; sleep briefly and continue
                    await asyncio.sleep(0.2)

    async def _flush(self, header: Dict[str, Any], hexdump: List[str]):
        obj = dict(header)
        if hexdump:
            obj["body"] = "\n".join(hexdump)
        else:
            obj["body"] = obj.get("body", "")

        # Broadcast to connected clients
        try:
            await self.manager.broadcast(self.type_, json.dumps(obj))
        except Exception:
            pass

        # maintain recent list in app.state so new WS clients can receive history
        key = f"{self.type_}_recent"
        recent = getattr(app.state, key, None)
        if recent is None:
            recent = []
        # append and keep cap
        recent.append(obj)
        if len(recent) > self.recent_cap:
            recent = recent[-self.recent_cap :]
        setattr(app.state, key, recent)


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
            # receive to keep connection alive; ignore client messages
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
    html = Path(__file__).parent.parent / "templates" / "packets.html"
    return HTMLResponse(html.read_text())


@router.get("/alerts")
async def alerts_page():
    html = Path(__file__).parent.parent / "templates" / "alerts.html"
    return HTMLResponse(html.read_text())


# register router
app.include_router(router)


# =========================================
# Startup event
# =========================================
@router.on_event("startup")
async def startup_event():
    base = Path(__file__).parent.parent / "logs"

    traffic_tailer = LogTailer(base / "traffic.log", manager, TrafficParser, "traffic", recent_cap=MAX_RECENT)
    alert_tailer = LogTailer(base / "alerts.log", manager, AlertParser, "alerts", recent_cap=MAX_RECENT)

    # start background tailers
    asyncio.create_task(traffic_tailer.start())
    asyncio.create_task(alert_tailer.start())

    # preload recent entries (keep them chronological)
    app.state.traffic_recent = [
        {**entry["header"], "body": entry.get("body", "")}
        for entry in await traffic_tailer.load_recent_logs(MAX_RECENT)
    ]
    app.state.alerts_recent = [
        {**entry["header"], "body": entry.get("body", "")}
        for entry in await alert_tailer.load_recent_logs(MAX_RECENT)
    ]


# =========================================
# Run standalone (for local dev)
# =========================================
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("app.api.view_log:app", host="0.0.0.0", port=8000, reload=True)
