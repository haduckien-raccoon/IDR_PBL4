# http_parser.py
from __future__ import annotations
import sys
import os
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
import argparse
import threading
import queue
import time
import logging
import re
import binascii
import math
import base64
from collections import Counter
from pathlib import Path
import json
import hashlib
from urllib.parse import unquote_plus
from typing import Dict, Any, Tuple, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
from typing import Deque, Tuple, Dict, Any, List, Optional
from collections import deque
import sys
import threading
import re
from typing import Dict, Optional, Tuple
from urllib.parse import unquote_plus

from scapy.all import sniff, IP, TCP, Raw
from app.capture_packet.flowtracker_module import FlowTracker
from app.capture_packet.reassembly_module import TCPReassembler   # <--- thêm dòng này

# =============================
# HTTP PARSER (giống Snort)
# =============================

class HTTPParseResult:
    def __init__(self):
        self.method: Optional[str] = None
        self.uri: Optional[str] = None
        self.headers: Dict[str, str] = {}
        self.body: bytes = b""
        self.regions: Dict[str, bytes] = {}

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
            body_block = data[header_end+4:]

            lines = header_block.split(self.CRLF)
            if not lines:
                return result

            # ---- first line ----
            first = lines[0].decode("latin1", errors="ignore")
            parts = first.split()

            if client_side:   # HTTP request
                if len(parts) >= 2:
                    result.method = parts[0].upper()
                    result.uri = unquote_plus(parts[1])
            else:
                result.method = parts[0]  # status only

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

            # ---- Snort regions ----
            if result.uri:
                result.regions["http_uri"] = result.uri.encode("latin1")

            header_bytes = b"".join([f"{k}: {v}\r\n".encode("latin1") for k, v in result.headers.items()])
            result.regions["http_header"] = header_bytes

            if client_side:
                result.regions["http_client_body"] = result.body
            else:
                result.regions["http_server_body"] = result.body

            # ---- HTTP Cookie region ----
            cookie_header = result.headers.get("cookie")
            if cookie_header:
                # Snort lưu cookies tách riêng
                result.regions["http_cookie"] = cookie_header.encode("latin1")

        except Exception:
            pass

        return result


# =============================
# SNIFF + REASSEMBLY
# =============================

# tcp_reasm = TCPReassembler()
# parser = HTTPParser()

# def process_packet(pkt):

#     res = tcp_reasm.feed(pkt)   # *** SỬ DỤNG REASSEMBLY ***
#     if not res:
#         return

#     payload, key = res
#     src_ip, dst_ip, sport, dport = key

#     print("\n========== FULL HTTP STREAM ===========")
#     print(payload)
#     print("=======================================\n")

#     # Xác định chiều client/server
#     client_side = (dport == 80)

#     http = parser.parse(payload, client_side=client_side)

#     print(http)


# def main():
#     print("[*] Sniffing + TCP Reassembly (port 80) ...")
#     sniff(filter="tcp port 80", prn=process_packet, iface="lo")

# if __name__ == "__main__":
#     main()

#haduckien@Raccoon2005:/media/haduckien/E/Studying/HK5/PBL4/idr_project$ sudo /media/haduckien/E/Tool/miniconda3/bin/conda run -n base --no-capture-output python app/capture_packet/http_parser.py --iface lo --filter "tcp dst port 80"