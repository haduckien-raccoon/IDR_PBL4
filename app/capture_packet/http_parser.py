# #haduckien@Raccoon2005:/media/haduckien/E/Studying/HK5/PBL4/idr_project$ sudo /media/haduckien/E/Tool/miniconda3/bin/conda run -n base --no-capture-output python app/capture_packet/http_parser.py --iface lo --filter "tcp dst port 80"
# http_parser.py
from __future__ import annotations
import logging
import re
from urllib.parse import unquote_plus
from typing import Dict, Optional, Any
from app.capture_packet.reassembly_module import TCPReassembler

# =============================
# Logging
# =============================
console_logger = logging.getLogger("http_parser")
console_logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch.setFormatter(formatter)
console_logger.addHandler(ch)

# =============================
# HTTP Parser
# =============================
class HTTPParseResult:
    def __init__(self):
        self.method: Optional[str] = None
        self.uri: Optional[str] = None
        self.headers: Dict[str, str] = {}
        self.body: bytes = b""
        self.regions: Dict[str, bytes] = {}

        # Snort/Suricata-style fields
        self.http_method: Optional[str] = None
        self.http_version: Optional[str] = None
        self.http_host: Optional[str] = None
        self.http_user_agent: Optional[str] = None

class HTTPParser:
    CRLF = b"\r\n"
    HEADER_RE = re.compile(rb"^(?P<name>[^:]+):[ \t]*(?P<value>.+)$")

    def parse(self, data: bytes, client_side: bool = True) -> HTTPParseResult:
        result = HTTPParseResult()
        try:
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                return result

            header_block = data[:header_end]
            body_block = data[header_end + 4:]
            lines = header_block.split(self.CRLF)
            if not lines:
                return result

            # ---- first line ----
            first = lines[0].decode("latin1", errors="ignore")
            parts = first.split()
            if client_side:
                if len(parts) >= 2:
                    result.method = parts[0].upper()
                    result.http_method = result.method
                    result.uri = unquote_plus(parts[1])
                    if len(parts) >= 3:
                        result.http_version = parts[2]
            else:
                if len(parts) >= 1:
                    result.http_version = parts[0]

            # ---- headers ----
            current_name = None
            current_value = ""
            for l in lines[1:]:
                if l.startswith(b" ") or l.startswith(b"\t"):
                    if current_name:
                        current_value += " " + l.strip().decode("latin1")
                    continue

                if current_name:
                    result.headers[current_name] = current_value.strip()

                m = self.HEADER_RE.match(l)
                if m:
                    current_name = m.group("name").decode("latin1").lower()
                    current_value = m.group("value").decode("latin1", errors="ignore")
                else:
                    current_name = None
                    current_value = ""

            if current_name:
                result.headers[current_name] = current_value.strip()

            # ---- body ----
            if result.headers.get("transfer-encoding") == "chunked":
                result.body = body_block
            else:
                clen = int(result.headers.get("content-length", "0") or "0")
                result.body = body_block[:clen]

            # ---- Snort/Suricata regions ----
            if result.uri:
                result.regions["http_uri"] = result.uri.encode("latin1")
            if result.method:
                result.regions["http_method"] = result.method.encode("latin1")
            if result.http_version:
                result.regions["http_version"] = result.http_version.encode("latin1")

            header_bytes = b"".join([f"{k}: {v}\r\n".encode("latin1") for k, v in result.headers.items()])
            result.regions["http_header"] = header_bytes
            if client_side:
                result.regions["http_client_body"] = result.body
            else:
                result.regions["http_server_body"] = result.body

            # Optional fields
            result.http_host = result.headers.get("host")
            result.http_user_agent = result.headers.get("user-agent")
            if result.http_host:
                result.regions["http_host"] = result.http_host.encode("latin1")
            if result.http_user_agent:
                result.regions["http_user_agent"] = result.http_user_agent.encode("latin1")

            cookie_header = result.headers.get("cookie")
            if cookie_header:
                result.regions["http_cookie"] = cookie_header.encode("latin1")
            status = result.headers.get("status")
            if status:
                result.regions["http_status"] = status.encode("latin1")

        except Exception:
            pass

        return result