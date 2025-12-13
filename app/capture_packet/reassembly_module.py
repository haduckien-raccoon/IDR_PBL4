# # tcp_reasm_rfc.py
# # RFC 793 + RFC 815 aware TCP reassembly
# import sys
# import time
# import threading
# from typing import Dict, Any, Tuple, List, Optional, Deque
# from collections import deque
# from app.capture_packet.flowtracker_module import FlowTracker

# BUFID = Tuple[str, str, int, int]  # (src_ip, dst_ip, sport, dport)


# class Segment:
#     """Represents a TCP segment for a given ACK block."""
#     def __init__(self, seq: int, payload: bytes, index: Optional[int] = None):
#         self.seq = seq
#         self.payload = bytearray(payload)
#         self.len = len(payload)
#         self.indexes: List[int] = [index] if index is not None else []


# class FlowState:
#     """Represents all segments and hole list for a given flow/ACK."""
#     def __init__(self, isn: int):
#         self.isn = isn
#         self.holes: List[Tuple[int, int]] = [(isn, sys.maxsize)]  # initial hole open-ended
#         self.segments: List[Segment] = []


# class TCPReassembly:
#     """RFC 793 + RFC 815 aware TCP reassembly engine."""
#     def __init__(self):
#         self._buffer: Dict[BUFID, Dict[int, FlowState]] = {}
#         self._datagrams: List[Dict[str, Any]] = []
#         self.flow_tracker = FlowTracker()

#         # Memory / timeout controls
#         self.memcap = 200 * 1024 * 1024  # 200MB total reassembly memcap
#         self.idle_timeout = 120          # seconds
#         self.max_holes_per_flow = 64
#         self.max_flow_raw_bytes = 2 * 1024 * 1024  # 2MB per ACK block

#         # Track last_seen per flow
#         self._last_seen: Dict[BUFID, float] = {}

#     # ---------------- Memory & timeout management ----------------
#     def memory_usage(self) -> int:
#         total = 0
#         for flow_dict in self._buffer.values():
#             for state in flow_dict.values():
#                 for seg in state.segments:
#                     total += len(seg.payload)
#         return total

#     def cleanup_timeouts(self):
#         now = time.time()
#         # Remove idle flows
#         for bufid in list(self._buffer.keys()):
#             last = self._last_seen.get(bufid, now)
#             if now - last > self.idle_timeout:
#                 self._submit_and_delete(bufid, reason='idle_timeout')

#         # Enforce memory cap
#         mem = self.memory_usage()
#         if mem > self.memcap:
#             items = sorted(
#                 ((bufid, self._last_seen.get(bufid, 0)) for bufid in self._buffer.keys()),
#                 key=lambda x: x[1]
#             )
#             for bufid, _ in items:
#                 if mem <= self.memcap:
#                     break
#                 self._submit_and_delete(bufid, reason='memcap_flush')
#                 mem = self.memory_usage()

#     # ---------------- Segment insertion ----------------
#     def _insert_segment(self, flow: FlowState, seq: int, payload: bytes, index: Optional[int] = None):
#         new_seg = Segment(seq, payload, index)
#         merged: List[Segment] = []
#         inserted = False
#         for seg in flow.segments:
#             if seq + len(payload) <= seg.seq:
#                 if not inserted:
#                     merged.append(new_seg)
#                     inserted = True
#                 merged.append(seg)
#             elif seq >= seg.seq + seg.len:
#                 merged.append(seg)
#             else:
#                 # overlap: keep existing, fill missing bytes
#                 start = min(seg.seq, seq)
#                 end = max(seg.seq + seg.len, seq + len(payload))
#                 combined = bytearray(end - start)
#                 # copy existing
#                 for i in range(seg.len):
#                     combined[seg.seq - start + i] = seg.payload[i]
#                 # copy new
#                 for i in range(len(payload)):
#                     offset = seq - start + i
#                     if combined[offset] == 0:
#                         combined[offset] = payload[i]
#                 seg.seq = start
#                 seg.payload = combined
#                 seg.len = len(combined)
#                 seg.indexes.extend(new_seg.indexes)
#                 merged.append(seg)
#                 inserted = True
#         if not inserted:
#             merged.append(new_seg)
#         flow.segments = merged
#         self._update_holes(flow, seq, len(payload))

#     # ---------------- Hole list update ----------------
#     def _update_holes(self, flow: FlowState, seq: int, length: int):
#         first = seq
#         last = seq + length
#         new_holes = []
#         for start, end in flow.holes:
#             if last <= start or first >= end:
#                 new_holes.append((start, end))
#                 continue
#             if first > start:
#                 new_holes.append((start, first))
#             if last < end:
#                 new_holes.append((last, end))
#         flow.holes = new_holes[:self.max_holes_per_flow]

#     # ---------------- Assemble payload ----------------
#     def _assemble_payload(self, flow: FlowState) -> Tuple[bytes, List[int]]:
#         segments_sorted = sorted(flow.segments, key=lambda s: s.seq)
#         data = bytearray()
#         indexes: List[int] = []
#         for s in segments_sorted:
#             offset = s.seq - flow.isn
#             if offset > len(data):
#                 data.extend(b'\x00' * (offset - len(data)))
#             end = offset + len(s.payload)
#             if end > len(data):
#                 data.extend(b'\x00' * (end - len(data)))
#             data[offset:end] = s.payload
#             indexes.extend(s.indexes)
#         return bytes(data), indexes

#     # ---------------- Packet processing ----------------
#     def process_packet(self, pkt, index: Optional[int] = None):
#         if not pkt.haslayer('IP') or not pkt.haslayer('TCP'):
#             return
#         ip = pkt['IP']
#         tcp = pkt['TCP']
#         payload = bytes(tcp.payload)
#         BUFID_KEY = (str(ip.src), str(ip.dst), int(tcp.sport), int(tcp.dport))
#         DSN = int(tcp.seq)
#         ACK = int(tcp.ack)
#         SYN = bool(tcp.flags & 0x02)
#         FIN = bool(tcp.flags & 0x01)
#         RST = bool(tcp.flags & 0x04)
#         LAST = DSN + len(payload)

#         self.flow_tracker.update(BUFID_KEY, tcp, ip)
#         self._last_seen[BUFID_KEY] = time.time()

#         if SYN and BUFID_KEY in self._buffer:
#             self._submit_and_delete(BUFID_KEY, reason='syn_reset')

#         if BUFID_KEY not in self._buffer:
#             self._buffer[BUFID_KEY] = {}

#         flow_dict = self._buffer[BUFID_KEY]
#         if ACK not in flow_dict:
#             flow_dict[ACK] = FlowState(DSN)
#         flow_state = flow_dict[ACK]

#         if payload:
#             self._insert_segment(flow_state, DSN, payload, index)
#             if len(flow_state.segments) > 1024 or len(flow_state.segments) * len(payload) > self.max_flow_raw_bytes:
#                 self._submit_and_delete(BUFID_KEY, reason='segment_limit_exceeded')

#         if FIN or RST:
#             self._submit_and_delete(BUFID_KEY, reason='fin_or_rst')

#     # ---------------- Submit datagrams ----------------
#     def _submit_and_delete(self, bufid: BUFID, reason: str = 'flush'):
#         if bufid not in self._buffer:
#             return
#         flow_dict = self._buffer.pop(bufid)
#         flow_info = self.flow_tracker.get_flow_safe(bufid, pkt=None)
#         for ack, state in flow_dict.items():
#             payload, indexes = self._assemble_payload(state)
#             datagram = {
#                 'flow': flow_info,
#                 'NotImplemented': bool(state.holes),
#                 'id': {
#                     'src': (bufid[0], bufid[2]),
#                     'dst': (bufid[1], bufid[3]),
#                     'ack': ack,
#                 },
#                 'index': tuple(indexes),
#                 'payload': payload,
#                 'packets': None,
#                 'flush_reason': reason,
#             }
#             self._datagrams.append(datagram)

#         # cleanup flow if teardown
#         f = self.flow_tracker.get_flow(bufid)
#         if f and f.get('state') == 'teardown':
#             self.flow_tracker.delete_flow(bufid)

#         if bufid in self._last_seen:
#             del self._last_seen[bufid]

#     # ---------------- Public API ----------------
#     def get_datagrams(self) -> List[Dict[str, Any]]:
#         return list(self._datagrams)

#     def clear_datagrams(self):
#         self._datagrams.clear()

#     def flush_all(self):
#         for bufid in list(self._buffer.keys()):
#             self._submit_and_delete(bufid, reason='manual_flush')

#     def get_buffer_snapshot(self) -> Dict:
#         snap = {}
#         for bufid, flow_dict in self._buffer.items():
#             snap[bufid] = {
#                 ack: {'holes': state.holes, 'segments': [(s.seq, s.len) for s in state.segments]}
#                 for ack, state in flow_dict.items()
#             }
#         return snap


# # ---------------- Wrapper ----------------
# class TCPReassembler:
#     """Thread-safe wrapper exposing feed(ip_pkt) returning (payload, key) or None"""
#     def __init__(self, timeout: int = 120):
#         self.reasm = TCPReassembly()
#         self.lock = threading.Lock()
#         self._outq: Deque[Tuple[bytes, Tuple[str, str, int, int]]] = deque()
#         self.timeout = timeout

#     def feed(self, ip_pkt) -> Optional[Tuple[bytes, Tuple[str, str, int, int]]]:
#         try:
#             self.reasm.cleanup_timeouts()
#         except Exception:
#             pass

#         with self.lock:
#             if self._outq:
#                 return self._outq.popleft()

#             try:
#                 self.reasm.process_packet(ip_pkt)
#             except Exception:
#                 pass

#             datagrams = self.reasm.get_datagrams()
#             if not datagrams:
#                 return None

#             for d in datagrams:
#                 payload = d.get('payload', b'')
#                 idinfo = d.get('id', {})
#                 src = idinfo.get('src', (None, None))
#                 dst = idinfo.get('dst', (None, None))
#                 key = (str(src[0]), str(dst[0]), int(src[1]), int(dst[1]))
#                 self._outq.append((payload, key))

#             self.reasm.clear_datagrams()
#             if self._outq:
#                 return self._outq.popleft()
#             return None

#     def _cleanup(self):
#         try:
#             self.reasm.flow_tracker.prune_stale()
#         except Exception:
#             pass

# # def debug_feed(tcp_reasm: TCPReassembler, pkt):
# #     if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
# #         print("Not an IP/TCP packet")
# #         return

# #     ip = pkt[IP]
# #     tcp = pkt[TCP]

# #     flags = []
# #     if tcp.flags & 0x02: flags.append("SYN")
# #     if tcp.flags & 0x10: flags.append("ACK")
# #     if tcp.flags & 0x01: flags.append("FIN")
# #     if tcp.flags & 0x04: flags.append("RST")
# #     if tcp.flags & 0x08: flags.append("PSH")
# #     if tcp.flags & 0x20: flags.append("URG")
# #     if tcp.flags & 0x40: flags.append("ECE")
# #     if tcp.flags & 0x80: flags.append("CWR")

# #     BUFID_KEY = (ip.src, ip.dst, tcp.sport, tcp.dport)
# #     flow_info = tcp_reasm.reasm.flow_tracker.get_flow_safe(BUFID_KEY, pkt=(ip,tcp))
# #     buffer_snap = tcp_reasm.reasm.get_buffer_snapshot()

# #     print(f"\n--- PACKET ---")
# #     print(f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}  flags: {','.join(flags)}  len={len(tcp.payload)}")
# #     print(f"Flow state: {flow_info.get('state')}  direction: {flow_info.get('direction')}")
# #     print(f"Buffer snapshot (holes + segments): {buffer_snap.get(BUFID_KEY)}")

# #     # Feed into reassembler
# #     result = tcp_reasm.feed(pkt)
# #     if result:
# #         payload, key = result
# #         print(f"DATAGRAM produced! length={len(payload)}  key={key}")
# #         print(f"Payload preview (hex, first 64 bytes): {payload[:64].hex()} ...")
# #     else:
# #         print("No datagram produced yet (buffering)")

# # if __name__ == "__main__":
# #     tcp_reasm = TCPReassembler(timeout=60)

# #     print("Sniffing 100 TCP packets on localhost for debug (port 80)...")
# #     pkts = sniff(count=100, filter="tcp port 80", iface="lo")
# #     for i, pkt in enumerate(pkts):
# #         print(f"\n=== Packet {i+1} ===")
# #         debug_feed(tcp_reasm, pkt)

# #     print("\n--- FINAL DATAGRAMS ---")
# #     datagrams = tcp_reasm.reasm.get_datagrams()
# #     for i, d in enumerate(datagrams):
# #         print(f"Datagram {i}: src={d['id']['src']} dst={d['id']['dst']} ack={d['id']['ack']} len={len(d['payload'])} holes={d['NotImplemented']}")
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
from scapy.all import sniff, IP, TCP, UDP, Raw
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
from app.capture_packet.flowtracker_module import FlowTracker

console_logger = logging.getLogger("console")
BUFID = Tuple[str, str, int, int]  # (src_ip, dst_ip, src_port, dst_port)
console_logger = logging.getLogger("console")

# ================= SEGMENT =================
class Segment:
    __slots__ = ("seq", "data")
    def __init__(self, seq: int, data: bytes):
        self.seq = seq
        self.data = data
    @property
    def end(self):
        return self.seq + len(self.data)

# ================= DIRECTION BUFFER =================
class DirectionBuffer:
    def __init__(self, isn: int):
        self.isn = isn
        self.segments: List[Segment] = []      # ordered, non-overlap
        self.holes: List[Tuple[int, int]] = [(isn, sys.maxsize)]
        self.last_seen = time.time()

    def insert(self, seq: int, payload: bytes):
        if not payload:
            return
        new = Segment(seq, payload)
        result: List[Segment] = []

        for s in self.segments:
            # no overlap
            if new is None or new.end <= s.seq or new.seq >= s.end:
                result.append(s)
                continue

            # overlap -> FIRST SEEN WINS
            if new.seq < s.seq:
                left = new.data[: s.seq - new.seq]
                if left:
                    result.append(Segment(new.seq, left))
            if new.end > s.end:
                new = Segment(s.end, new.data[s.end - new.seq :])
            else:
                new = None
            result.append(s)

        if new:
            result.append(new)

        # sort + merge adjacent
        result.sort(key=lambda x: x.seq)
        merged: List[Segment] = []
        for s in result:
            if not merged or merged[-1].end < s.seq:
                merged.append(s)
            elif merged[-1].end == s.seq:
                merged[-1] = Segment(merged[-1].seq, merged[-1].data + s.data)

        self.segments = merged
        self._update_holes(seq, seq + len(payload))
        self.last_seen = time.time()

    def _update_holes(self, start: int, end: int):
        new_holes = []
        for hs, he in self.holes:
            if end <= hs or start >= he:
                new_holes.append((hs, he))
            else:
                if start > hs:
                    new_holes.append((hs, start))
                if end < he:
                    new_holes.append((end, he))
        self.holes = new_holes

    def assemble(self) -> bytes:
        data = bytearray()
        for s in self.segments:
            data.extend(s.data)
        return bytes(data)

# ================= FLOW BUFFER =================
class FlowBuffer:
    def __init__(self):
        self.dirs: Dict[BUFID, DirectionBuffer] = {}
        self.last_seen = time.time()

# ================= TCP REASSEMBLY =================
class TCPReassembly:
    def __init__(self):
        self.flows: Dict[BUFID, FlowBuffer] = {}
        self._datagrams: Deque[Dict[str, Any]] = deque()
        self.flow_tracker = FlowTracker()
        self.idle_timeout = 120
        self.lock = threading.Lock()

    def process_packet(self, pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip, tcp = pkt[IP], pkt[TCP]
        payload = bytes(tcp.payload)
        seq = int(tcp.seq)
        syn = tcp.flags & 0x02
        fin = tcp.flags & 0x01
        rst = tcp.flags & 0x04

        bufid: BUFID = (str(ip.src), str(ip.dst), int(tcp.sport), int(tcp.dport))
        self.flow_tracker.update(bufid, tcp, ip)

        with self.lock:
            flow = self.flows.setdefault(bufid, FlowBuffer())
            flow.last_seen = time.time()

            if bufid not in flow.dirs:
                isn = seq + (1 if syn else 0)
                flow.dirs[bufid] = DirectionBuffer(isn)

            dbuf = flow.dirs[bufid]
            dbuf.insert(seq, payload)

            if fin or rst:
                self._flush_flow(bufid, reason="fin_or_rst")

    def _flush_flow(self, bufid: BUFID, reason: str):
        flow = self.flows.get(bufid)
        if not flow:
            return
        for dbuf in flow.dirs.values():
            payload = dbuf.assemble()
            self._datagrams.append({
                "payload": payload,
                "id": {
                    "src": (bufid[0], bufid[2]),
                    "dst": (bufid[1], bufid[3]),
                },
                "flow": self.flow_tracker.get_flow_safe(bufid, None),
                "flush_reason": reason,
                "incomplete": len(dbuf.holes) > 0,
            })
        self.flows.pop(bufid, None)

    def cleanup_timeouts(self):
        now = time.time()
        with self.lock:
            for bufid in list(self.flows.keys()):
                if now - self.flows[bufid].last_seen > self.idle_timeout:
                    self._flush_flow(bufid, reason="idle_timeout")

    def get_datagrams(self) -> List[Dict[str, Any]]:
        return list(self._datagrams)

    def clear_datagrams(self):
        self._datagrams.clear()

# ================= WRAPPER =================
class TCPReassembler:
    def __init__(self, timeout: int = 120):
        self.reasm = TCPReassembly()
        self._outq: Deque[Tuple[bytes, BUFID]] = deque()
        self.lock = threading.Lock()

    def feed(self, ip_pkt) -> Optional[Tuple[bytes, BUFID]]:
        try:
            self.reasm.cleanup_timeouts()
        except Exception:
            pass

        with self.lock:
            if self._outq:
                return self._outq.popleft()

            self.reasm.process_packet(ip_pkt)
            dgs = self.reasm.get_datagrams()
            if not dgs:
                return None

            for d in dgs:
                payload = d["payload"]
                src = d["id"]["src"]
                dst = d["id"]["dst"]
                key = (str(src[0]), str(dst[0]), int(src[1]), int(dst[1]))
                self._outq.append((payload, key))

            self.reasm.clear_datagrams()
            return self._outq.popleft() if self._outq else None
        
    def _cleanup(self):
        try:
            self.reasm.flow_tracker.prune_stale()
        except Exception:
            pass
