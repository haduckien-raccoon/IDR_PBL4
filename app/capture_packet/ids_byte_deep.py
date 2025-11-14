#!/usr/bin/env python3
"""
ids_byte_deep.py - simple Snort-like byte-level IDS
"""

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
from typing import Deque
from collections import deque
import sys
import threading


from app.workers.blocker import enqueue_block
# ----------------- Config paths -----------------
BASE_DIR = Path("app")
LOG_DIR = BASE_DIR / "logs"
RULES_PATH = Path("app/capture_packet/rules.json")
API_ALERT_ENDPOINT = "http://127.0.0.1:8000/api/alerts/raw"
TRAFFIC_LOG = LOG_DIR / "traffic.log"
ALERTS_LOG = LOG_DIR / "alerts.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)

# ----------------- Logging setup -----------------
traffic_logger = logging.getLogger("traffic")
alerts_logger = logging.getLogger("alerts")
console_logger = logging.getLogger("console")
rules_logger = logging.getLogger("rules")  # new logger for rule changes

for lg in (traffic_logger, alerts_logger, console_logger, rules_logger):
    lg.setLevel(logging.DEBUG)

# console handler
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fmt_console = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch.setFormatter(fmt_console)
console_logger.addHandler(ch)

# traffic file handler
fh_traffic = logging.FileHandler(str(TRAFFIC_LOG), encoding="utf-8")
fh_traffic.setLevel(logging.INFO)
fh_traffic.setFormatter(logging.Formatter("%(asctime)s [TRAFFIC] %(message)s"))
traffic_logger.addHandler(fh_traffic)

# alerts file handler
fh_alerts = logging.FileHandler(str(ALERTS_LOG), encoding="utf-8")
fh_alerts.setLevel(logging.INFO)
fh_alerts.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s"))
alerts_logger.addHandler(fh_alerts)

# ----------------- Utilities -----------------
def hexdump(src: bytes, length: int = 16) -> str:
    lines = []
    for i in range(0, len(src), length):
        sub = src[i:i+length]
        hx = ' '.join(f"{b:02x}" for b in sub)
        txt = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in sub)
        lines.append(f"{i:08x}  {hx:<{length*3}}  {txt}")
    return "\n".join(lines)

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    l = len(data)
    ent = 0.0
    for v in counts.values():
        p = v / l
        ent -= p * math.log2(p)
    return ent

def rule_id(r: Dict[str, Any]) -> str:
    return r.get("id") or r.get("uuid") or "<no-id>"

# ----------------- Rules loading & compilation -----------------
def load_rules(path: Path) -> List[Dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        console_logger.warning("Rules file not found: %s", path)
        return []
    except Exception as e:
        console_logger.error("Failed to load rules.json: %s", e)
        return []

    rules = []
    for r in raw:
        rr = dict(r)
        rr["proto"] = (rr.get("proto") or "ANY").upper()
        for p in ("dst_port", "src_port"):
            try:
                rr[p] = int(rr[p]) if rr.get(p) is not None else None
            except Exception:
                rr[p] = None
        if rr.get("pattern_bytes") and isinstance(rr["pattern_bytes"], str):
            rr["pattern_bytes"] = rr["pattern_bytes"].encode("latin1")
        if rr.get("pattern_regex_bytes") and isinstance(rr["pattern_regex_bytes"], str):
            rr["pattern_regex_bytes"] = rr["pattern_regex_bytes"]
        if rr.get("pattern_hex") and not rr.get("pattern_bytes"):
            try:
                rr["pattern_bytes"] = binascii.unhexlify(rr["pattern_hex"])
            except Exception:
                rr["pattern_bytes"] = None
        rules.append(rr)
    console_logger.info("Loaded %d rules", len(rules))
    return rules

def compile_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled = []
    for r in raw_rules:
        ent: Dict[str, Any] = {"rule": r}
        ent["pattern_bytes"] = r.get("pattern_bytes") if isinstance(r.get("pattern_bytes"), (bytes, bytearray)) else b""
        pr = r.get("pattern_regex_bytes")
        if pr:
            try:
                ent["pattern_regex_compiled"] = re.compile(pr, flags=re.DOTALL | re.IGNORECASE)
            except Exception as e:
                console_logger.warning("Regex compile failed for %s: %s", rule_id(r), e)
                ent["pattern_regex_compiled"] = None
        else:
            ent["pattern_regex_compiled"] = None
        compiled.append(ent)
    return compiled

# ----------------- Aho automaton (optional) -----------------
try:
    import ahocorasick  # type: ignore
    AHO_AVAILABLE = True
except ImportError:
    AHO_AVAILABLE = False

def build_aho(raw_rules: List[Dict[str, Any]]) -> Optional[Any]:
    if not AHO_AVAILABLE:
        return None
    try:
        aho = ahocorasick.Automaton()
        idx = 0
        for r in raw_rules:
            if r.get("use_aho") and r.get("pattern_bytes"):
                pat = r["pattern_bytes"]
                try:
                    key = pat.decode("latin1")
                except Exception:
                    key = str(pat)
                aho.add_word(key, (idx, rule_id(r), r.get("message")))
                idx += 1
        if idx > 0:
            aho.make_automaton()
            console_logger.info("AHO automaton built with %d patterns", idx)
            return aho
    except Exception as e:
        console_logger.warning("Failed building AHO: %s", e)
    return None

# ----------------- Payload decoding helpers -----------------
def try_base64_decode(s: str) -> Optional[str]:
    candidate = "".join(s.strip().split())
    if len(candidate) < 8:
        return None
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', candidate):
        return None
    try:
        raw = base64.b64decode(candidate, validate=True)
        return raw.decode('latin1', errors='ignore')
    except Exception:
        return None

def generate_decodes(payload: bytes, enable_decode: bool) -> List[Tuple[str,str]]:
    variants: List[Tuple[str,str]] = []
    try:
        raw_text = payload.decode('latin1', errors='ignore')
    except Exception:
        raw_text = ""
    variants.append(("raw", raw_text))
    if not enable_decode:
        return variants
    try:
        url = unquote_plus(raw_text)
    except Exception:
        url = raw_text
    if url != raw_text:
        variants.append(("url", url))
    b64_raw = try_base64_decode(raw_text)
    if b64_raw:
        variants.append(("b64", b64_raw))
        u = unquote_plus(b64_raw)
        if u != b64_raw:
            variants.append(("b64->url", u))
    b64_url = try_base64_decode(url)
    if b64_url and b64_url != b64_raw:
        variants.append(("url->b64", b64_url))
    form_decoded = unquote_plus(raw_text)
    if form_decoded != raw_text and ("form", form_decoded) not in variants:
        variants.append(("form", form_decoded))
    try:
        variants.append(("raw_lower", raw_text.lower()))
    except Exception:
        pass
    return variants

BUFID = Tuple[str, str, int, int]  # (src_ip, dst_ip, src_port, dst_port)

class TCPReassembly:
    def __init__(self):
        # buffer[BUFID] = {
        #   'hdl': [ {'first': int_seq, 'last': int_seq}, ... ],
        #   ack_num (int): {
        #       'ind': [indexes],
        #       'isn': int,    # initial sequence number for this ack-buffer
        #       'len': int,    # current length of raw
        #       'raw': bytearray,
        #   }, ...
        # }
        self._buffer: Dict[BUFID, Dict] = {}
        # produced datagrams (list of dict)
        self._datagrams: List[Dict[str, Any]] = []

    # ---------- public helpers ----------
    def process_packet(self, pkt, index: Optional[int] = None):
        """Process a Scapy packet for reassembly. Call this for each captured packet."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        if tcp.dport != 80:
            return
        
        payload = bytes(tcp.payload)
        has_payload = len(payload) > 0

        BUFID = (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))
        DSN = int(tcp.seq)
        ACK = int(tcp.ack)
        SYN = bool(tcp.flags & 0x02)
        FIN = bool(tcp.flags & 0x01)
        RST = bool(tcp.flags & 0x04)
        FIRST = DSN
        LAST = DSN + len(payload)

        # If SYN and an existing buffer exists => flush previous and delete
        if SYN and BUFID in self._buffer:
            self._submit_and_delete(BUFID, reason='syn_reset')

        # If buffer not exist, create new one
        if BUFID not in self._buffer:
            # Create HDL such that after first received fragment, missing region starts at DSN+len(payload)
            # We initialize HDL as wide open; we'll update after inserting fragment
            self._buffer[BUFID] = {
                'hdl': [],  # will set when first fragment arrives
            }

        # If no payload, still record ACK entry (to keep indices) and flush on FIN/RST if present
        if not has_payload:
            # ensure an ACK entry exists
            if ACK not in self._buffer[BUFID]:
                self._buffer[BUFID][ACK] = {
                    'ind': [index] if index is not None else [],
                    'isn': DSN,
                    'len': 0,
                    'raw': bytearray(),
                }
            else:
                if index is not None:
                    self._buffer[BUFID][ACK]['ind'].append(index)
            if FIN or RST:
                self._submit_and_delete(BUFID, reason='fin_or_rst_no_payload')
            return

        # Insert payload into ACK-specific block
        if ACK not in self._buffer[BUFID]:
            # create new block; set ISN to DSN and raw to payload
            self._buffer[BUFID][ACK] = {
                'ind': [index] if index is not None else [],
                'isn': DSN,
                'len': len(payload),
                'raw': bytearray(payload),
            }
            # If we just created first block in this session, initialize HDL to indicate missing after this fragment
            if not self._buffer[BUFID].get('hdl'):
                # Hole starts at LAST (next wanted seq) and is unbounded to the right
                self._buffer[BUFID]['hdl'] = [{'first': LAST, 'last': sys.maxsize}]
        else:
            # append index
            if index is not None:
                self._buffer[BUFID][ACK]['ind'].append(index)

            # merge fragment into existing raw
            block = self._buffer[BUFID][ACK]
            ISN = block['isn']
            RAW = block['raw']

            if DSN >= ISN:
                # fragment starts at or after ISN
                offset = DSN - ISN
                needed = offset + len(payload)
                if offset >= len(RAW):
                    # append gap (zeros) then payload
                    gap = offset - len(RAW)
                    if gap > 0:
                        RAW.extend(b'\x00' * gap)
                    RAW.extend(payload)
                else:
                    # overlapping or replacing bytes
                    endpos = offset + len(payload)
                    if endpos > len(RAW):
                        # extend to fit
                        RAW[offset:endpos] = payload
                    else:
                        RAW[offset:endpos] = payload
            else:
                # fragment starts before ISN -> need to prepend or overlap-left
                # compute overlap / gap relative to ISN
                delta = ISN - DSN  # bytes that fragment extends left of ISN
                if delta >= len(payload):
                    # fragment entirely before current RAW with gap
                    gap = delta - len(payload)
                    RAW = bytearray(payload + (b'\x00' * gap) + RAW)
                    block['isn'] = DSN
                else:
                    # partial overlap: prefix from payload that is before ISN, then remainder overlaps existing RAW
                    prefix = payload[:delta]
                    overlap = payload[delta:]
                    RAW = bytearray(prefix + RAW)
                    # now write overlap into RAW starting at position len(prefix)
                    pos = len(prefix)
                    need = pos + len(overlap)
                    if need > len(RAW):
                        RAW.extend(b'\x00' * (need - len(RAW)))
                    RAW[pos:pos + len(overlap)] = overlap
                    block['isn'] = DSN
            block['raw'] = RAW
            block['len'] = len(block['raw'])

        # Update HDL using RFC-815 like logic: holes described in absolute seq numbers
        HDL = self._buffer[BUFID].get('hdl', [])
        # If HDL empty, we can set a fresh hole starting after this block (LAST) if not set
        if not HDL:
            HDL = [{'first': LAST, 'last': sys.maxsize}]
            self._buffer[BUFID]['hdl'] = HDL

        # Find a hole that overlaps with [FIRST, LAST)
        for idx, hole in enumerate(list(HDL)):
            # If fragment entirely after this hole -> continue
            if FIRST > hole['last']:
                continue
            # If fragment entirely before this hole -> continue
            if LAST < hole['first']:
                continue
            # Overlap: remove current hole
            try:
                HDL.pop(idx)
            except Exception:
                # safe fallback: rebuild without this hole
                HDL = [h for h in HDL if h is not hole]
            # left leftover
            if FIRST > hole['first']:
                left = {'first': hole['first'], 'last': FIRST - 1}
                HDL.insert(idx, left)
                idx += 1
            # right leftover (only create if fragment does not finalize and not FIN/RST)
            if (LAST < hole['last']) and (not FIN) and (not RST):
                right = {'first': LAST + 1, 'last': hole['last']}
                HDL.insert(idx, right)
            break
        # store HDL back
        self._buffer[BUFID]['hdl'] = HDL

        # If FIN or RST present, flush session
        if FIN or RST:
            self._submit_and_delete(BUFID, reason='fin_or_rst')

    def _submit_and_delete(self, bufid: BUFID, reason: str = 'flush'):
        """Build datagrams from buffer[bufid] and remove the buffer."""
        if bufid not in self._buffer:
            return
        buf = self._buffer[bufid]
        HDL = buf.get('hdl', [])
        # iterate all ack-keys in buf (ints)
        for key, block in list(buf.items()):
            if key == 'hdl':
                continue
            if not isinstance(key, int):
                continue
            raw = block.get('raw', None)
            if not raw:
                continue
            payload_bytes = bytes(raw)
            datagram = {
                'NotImplemented': (len(HDL) != 0),  # True if holes remain
                'id': {
                    'src': (bufid[0], bufid[2]),
                    'dst': (bufid[1], bufid[3]),
                    'ack': key,
                },
                'index': tuple(block.get('ind', [])),
                'payload': payload_bytes,
                'packets': None,
                'flush_reason': reason,
            }
            self._datagrams.append(datagram)
        # finally delete buffer
        try:
            del self._buffer[bufid]
        except KeyError:
            pass

    def get_datagrams(self) -> List[Dict[str, Any]]:
        """Return list of produced datagrams (and keep them)."""
        return list(self._datagrams)

    def clear_datagrams(self):
        """Clear stored datagrams."""
        self._datagrams.clear()

    def flush_all(self):
        """Flush all active buffers (force produce datagrams) and clear buffers."""
        bufids = list(self._buffer.keys())
        for b in bufids:
            self._submit_and_delete(b, reason='manual_flush')

    def get_buffer_snapshot(self) -> Dict:
        """Debug helper: snapshot of current buffers and HDL."""
        snap = {}
        for k, v in self._buffer.items():
            snap[k] = {
                'hdl': v.get('hdl'),
                'acks': [x for x in v.keys() if isinstance(x, int)],
            }
        return snap

# ---------- Wrapper to expose feed(ip_pkt) API ----------
class TCPReassembler:
    """
    Wrapper around TCPReassembly that exposes `feed(ip_pkt)` returning either
    (assembled_bytes, (src, dst, sport, dport)) or None.
    It buffers multiple produced datagrams internally and returns one per call.
    """
    def __init__(self, timeout: int = 120):
        self.reasm = TCPReassembly()
        self.lock = threading.Lock()
        self._outq: Deque[Tuple[bytes, Tuple[str,str,int,int]]] = deque()
        # optional timeout attribute kept for compatibility with old class
        self.timeout = timeout

    def feed(self, ip_pkt) -> Optional[Tuple[bytes, Tuple[str,str,int,int]]]:
        # return any queued assembled datagram first
        with self.lock:
            if self._outq:
                return self._outq.popleft()

            # process incoming packet via standard reassembly
            try:
                self.reasm.process_packet(ip_pkt)
            except Exception:
                # avoid blowing up worker loop on unexpected pkt shapes
                # log if needed, but keep behavior silent here
                pass

            datagrams = self.reasm.get_datagrams()
            if not datagrams:
                return None

            # push all datagrams into outq (as (payload, key)), then clear
            for d in datagrams:
                payload = d.get('payload', b'')
                # datagram id: 'src': (ip, port), 'dst': (ip, port)
                idinfo = d.get('id', {})
                src = idinfo.get('src', (None, None))
                dst = idinfo.get('dst', (None, None))
                try:
                    key = (str(src[0]), str(dst[0]), int(src[1]), int(dst[1]) if dst[1] is not None else None)
                except Exception:
                    # fallback to values from packet if id formatting unexpected
                    try:
                        t = ip_pkt[TCP]
                        key = (str(ip_pkt[IP].src), str(ip_pkt[IP].dst), int(t.sport), int(t.dport))
                    except Exception:
                        key = (None, None, None, None)
                self._outq.append((payload, key))

            # clear datagrams stored in TCPReassembly to avoid duplication
            self.reasm.clear_datagrams()

            if self._outq:
                return self._outq.popleft()
            return None

    def _cleanup(self):
        # kept for API parity; reassembly uses internal cleanup via sys.maxsize holes,
        # you can implement timed connection culling here if needed.
        pass

def dict_diff(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Tuple[Any, Any]]:
    """
    Return a dict of fields that changed with (old_value, new_value).
    Only top-level fields compared (sufficient for your rule shape).
    """
    diffs: Dict[str, Tuple[Any, Any]] = {}
    all_keys = set(old.keys()) | set(new.keys())
    for k in all_keys:
        o = old.get(k)
        n = new.get(k)
        if o != n:
            diffs[k] = (o, n)
    return diffs

# ----------------- IDS Engine -----------------
class IDS:
    def __init__(self, rules_path: Path, enable_decode: bool = True, payload_bytes: int = 4096):
        self._last_rules_event_time = 0
        self.rules_raw = load_rules(rules_path)
        self.compiled = compile_rules(self.rules_raw)
        self.aho = build_aho(self.rules_raw)
        self.enable_decode = enable_decode
        self.payload_bytes = int(payload_bytes)
        # self.defr = IPDefragmenter()
        self.reasm = TCPReassembler()
        self.last_alerts: Dict[str,float] = {}
        self.alert_throttle = 2.0
        self.logged_payloads = set()
        self.rules: Dict[str, Dict[str, Any]] = {rule_id(r): r for r in self.rules_raw}
        self.logged_payloads_cleanup_interval = 60
        self._last_cleanup = time.time()
        self.rules_path = rules_path
        self._start_rules_watcher()

    def log_traffic(self, meta: Dict[str, Any], payload: bytes):
        """
        Log traffic in the same style as alerts: include entropy and a hexdump
        (hexdump limited to first 2048 bytes to avoid huge logs).
        """
        try:
            key = (meta.get('src'), meta.get('dst'), meta.get('sport'), meta.get('dport'), meta.get('proto'), hashlib.sha1(payload).hexdigest())
            if key in self.logged_payloads:
                return  # skip duplicate
            self.logged_payloads.add(key)

            now = time.time()
            if now - self._last_cleanup > self.logged_payloads_cleanup_interval:
                self.logged_payloads.clear()
                self._last_cleanup = now
            ent = entropy(payload)
            hd = hexdump(payload[:2048])
            src = f"{meta.get('src')}:{meta.get('sport') or ''}"
            dst = f"{meta.get('dst')}:{meta.get('dport') or ''}"
            s = f"TRAFFIC proto={meta.get('proto')} {src}->{dst} entropy={ent:.3f} bytes={len(payload)}\nhexdump:\n{hd}\n"
            traffic_logger.info(s)
            console_logger.debug("TRAFFIC %s %s -> %s len=%d", meta.get('proto'), src, dst, len(payload))
        except Exception:
            console_logger.exception("log_traffic error")

    def log_alert(self, meta: Dict[str, Any], payload: bytes, rid: str, message: str, matched_variant: str, action: str, severity: str):
        try:
            key = (meta.get('src'), meta.get('dst'), meta.get('sport'), meta.get('dport'), meta.get('proto'), hashlib.sha1(payload).hexdigest())
            print(key)
            if key in self.logged_payloads:
                return  # skip duplicate
            self.logged_payloads.add(key)

            now = time.time()
            if now - self._last_cleanup > self.logged_payloads_cleanup_interval:
                self.logged_payloads.clear()
                self._last_cleanup = now
            ent = entropy(payload)
            hd = hexdump(payload[:2048])
            src = f"{meta.get('src')}:{meta.get('sport') or ''}"
            dst = f"{meta.get('dst')}:{meta.get('dport') or ''}"
            s = f"ALERT [{rid}] {message} | proto={meta.get('proto')} {src}->{dst} variant={matched_variant} entropy={ent:.3f}\nhexdump:\n{hd}\n"
            alerts_logger.info(s)
            console_logger.info("ALERT %s %s -> %s (%s)", rid, src, dst, message)
            severity = meta.get('severity', 'medium')
            #Gửi cảnh báo đến api:
            try:
                api_payload ={
                    "rid": rid,
                    "message": message,
                    "src": meta.get('src'),
                    "dst": meta.get('dst'),
                    "sport": meta.get('sport'),
                    "dport": meta.get('dport'),
                    "proto": meta.get('proto'),
                    "variant": matched_variant,
                    "entropy": ent,
                    "hexdump": hd,
                    "action": action,
                    "payload": base64.b64encode(payload).decode('ascii'),
                    "severity": severity
                }

                response = requests.post(API_ALERT_ENDPOINT, json=api_payload, timeout=5)
                if response.status_code == 201:
                    console_logger.info("Alert sent to API successfully: %s", response.json())
                else:
                    console_logger.error("Failed to send alert to API: %s - %s", response.status_code, response.text)
            except requests.exceptions.RequestException as e:
                console_logger.error("Error sending alert to API: %s", e)
                # Handle specific request exceptions if needed
            except Exception as e:
                console_logger.exception("Unexpected error sending alert to API: %s", e)
        except Exception:
            console_logger.exception("log_alert error")
    def should_throttle(self, sig: str) -> bool:
        now = time.time()
        last = self.last_alerts.get(sig)
        if last and (now - last) < self.alert_throttle:
            return True
        self.last_alerts[sig] = now
        return False
    
    def reload_rules(self):
        console_logger.info("Reloading rules from %s", self.rules_path)
        try:
            new_raw = load_rules(self.rules_path)
            new_compiled = compile_rules(new_raw)
            new_aho = build_aho(new_raw)
            self.rules_raw = new_raw
            self.compiled = new_compiled
            self.aho = new_aho
            console_logger.info("Rules reloaded: %d rules", len(self.rules_raw))
        except Exception as e:
            console_logger.error("Failed to reload rules: %s", e)
    def reload_rules_incremental(self):
        """
        Incremental reload of rules.json based on UUID.
        Detailed logging of added/updated/removed rules.
        """
        rules_logger.info("Starting incremental reload from %s", self.rules_path)
        try:
            new_raw = load_rules(self.rules_path)
            # ensure compile_single_rule exists in file (you have it)
            if not hasattr(self, "rules_map"):
                # First time initialization
                self.rules_map = {}
                self.compiled_map = {}
                for r in new_raw:
                    rid = r.get("uuid") or rule_id(r)
                    try:
                        compiled_entry = compile_single_rule(r)
                    except Exception as e:
                        rules_logger.error("Compile error for new rule %s: %s", rid, e)
                        compiled_entry = {"rule": r, "pattern_bytes": b"", "pattern_regex_compiled": None}
                    self.rules_map[rid] = r
                    self.compiled_map[rid] = compiled_entry
                    rules_logger.info("Initial load rule %s summary: group=%s message=%s", rid, r.get("group_id"), r.get("message"))
                self.rules_raw = new_raw
                self.compiled = list(self.compiled_map.values())
                self.aho = build_aho(new_raw)
                rules_logger.info("Initialized rules map: %d rules", len(new_raw))
                return

            old_uuids = set(self.rules_map.keys())
            new_uuids = set()
            added = []
            removed = []
            updated = []

            # Process new / updated
            for r in new_raw:
                rid = r.get("uuid") or rule_id(r)
                new_uuids.add(rid)
                old_rule = self.rules_map.get(rid)
                if old_rule is None:
                    # new rule
                    try:
                        compiled_entry = compile_single_rule(r)
                    except Exception as e:
                        rules_logger.error("Compile error for added rule %s: %s", rid, e)
                        compiled_entry = {"rule": r, "pattern_bytes": b"", "pattern_regex_compiled": None}
                    self.rules_map[rid] = r
                    self.compiled_map[rid] = compiled_entry
                    added.append(rid)
                    rules_logger.info("Added rule %s summary: group=%s message=%s", rid, r.get("group_id"), r.get("message"))
                else:
                    if r != old_rule:
                        # updated rule
                        diffs = dict_diff(old_rule, r)
                        try:
                            compiled_entry = compile_single_rule(r)
                        except Exception as e:
                            rules_logger.error("Compile error for updated rule %s: %s", rid, e)
                            compiled_entry = {"rule": r, "pattern_bytes": b"", "pattern_regex_compiled": None}
                        self.rules_map[rid] = r
                        self.compiled_map[rid] = compiled_entry
                        updated.append((rid, diffs))
                        rules_logger.info("Updated rule %s summary: group=%s message=%s changed_fields=%s",
                                        rid, r.get("group_id"), r.get("message"), ", ".join(diffs.keys()))
                        # log detail of changed fields
                        for k, (ov, nv) in diffs.items():
                            rules_logger.info("  - %s: %r -> %r", k, ov, nv)

            # Removed
            for rid in list(old_uuids):
                if rid not in new_uuids:
                    removed.append(rid)
                    # capture some info from old rule for human-readable log
                    oldr = self.rules_map.get(rid)
                    rules_logger.info("Removed rule %s summary: group=%s message=%s", rid, (oldr.get("group_id") if oldr else None), (oldr.get("message") if oldr else None))
                    # actually remove
                    self.rules_map.pop(rid, None)
                    self.compiled_map.pop(rid, None)

            # Finalize compiled list and Aho
            self.compiled = list(self.compiled_map.values())
            self.rules_raw = new_raw
            self.aho = build_aho(new_raw)

            # summary
            rules_logger.info("Incremental reload finished: total=%d added=%d updated=%d removed=%d",
                            len(self.rules_raw), len(added), len(updated), len(removed))
            # also echo to console
            console_logger.info("Rules reload: +%d ~%d -%d (total=%d)", len(added), len(updated), len(removed), len(self.rules_raw))
            if not (added or updated or removed):
                rules_logger.info("No rule changes detected.")

        except Exception as e:
            rules_logger.exception("Failed incremental reload: %s", e)

    def _start_rules_watcher(self):
        class Handler(FileSystemEventHandler):
            def __init__(self, ids: "IDS"):
                self.ids = ids

            def _should_handle(self, path: str) -> bool:
                try:
                    return os.path.abspath(path) == os.path.abspath(self.ids.rules_path)
                except Exception:
                    return False

            def _debounce(self):
                # simple debounce to avoid duplicate events (editors often generate multiple)
                now = time.time()
                last = getattr(self.ids, "_last_rules_event_time", 0)
                if now - last < 1.0:
                    return False
                self.ids._last_rules_event_time = int(time.time())
                return True

            def on_modified(self, event):
                if event.is_directory:
                    return
                if self._should_handle(event.src_path) and self._debounce():
                    rules_logger.info("Detected modified event for %s", event.src_path)
                    self.ids.reload_rules_incremental()

            def on_created(self, event):
                if event.is_directory:
                    return
                if self._should_handle(event.src_path) and self._debounce():
                    rules_logger.info("Detected created event for %s", event.src_path)
                    self.ids.reload_rules_incremental()

            def on_moved(self, event):
                # editors often save via tmp file + rename -> catch moved
                if event.is_directory:
                    return
                # check both dest and src
                dest = getattr(event, "dest_path", None) or getattr(event, "dest_path", "")
                if self._should_handle(dest) and self._debounce():
                    rules_logger.info("Detected moved event dest=%s src=%s", dest, getattr(event, "src_path", ""))
                    self.ids.reload_rules_incremental()
                elif self._should_handle(getattr(event, "src_path", "")) and self._debounce():
                    rules_logger.info("Detected moved event src=%s", getattr(event, "src_path", ""))
                    self.ids.reload_rules_incremental()

        observer = Observer()
        event_handler = Handler(self)
        folder = os.path.dirname(os.path.abspath(self.rules_path))
        observer.schedule(event_handler, path=folder or ".", recursive=False)
        observer.daemon = True
        observer.start()
        rules_logger.info("Started file watcher for %s", self.rules_path)
        
    def match_payload(self, payload: bytes, meta: Dict[str, Any]):
        p = payload[: self.payload_bytes]
        variants = generate_decodes(p, self.enable_decode)
        hits: List[Tuple[str,str,str]] = []

        if self.aho:
            try:
                s_raw = p.decode('latin1', errors='ignore')
                for end_index, (idx, rid, message) in self.aho.iter(s_raw):
                    hits.append((rid, message, "AHO_raw"))
            except Exception:
                console_logger.debug("AHO error", exc_info=True)

        for entry in self.compiled:
            r = entry["rule"]
            rule_proto = (r.get("proto") or "ANY").upper()
            if rule_proto != "ANY" and str(meta.get("proto") or "").upper() != rule_proto:
                continue

            dst_port_rule = r.get("dst_port")
            dst_port_meta = meta.get("dport")
            if dst_port_rule is not None and dst_port_meta is not None and dst_port_rule != dst_port_meta:
                continue

            src_port_rule = r.get("src_port")
            src_port_meta = meta.get("sport")
            if src_port_rule is not None and src_port_meta is not None and src_port_rule != src_port_meta:
                continue

            pb = entry.get("pattern_bytes")
            if pb and pb in p:
                hits.append((rule_id(r), r.get("message"), "BYTES_raw"))
                continue

            regex = entry.get("pattern_regex_compiled")
            if regex:
                for label, txt in variants:
                    if regex.search(txt):
                        hits.append((rule_id(r), r.get("message"), f"REGEX_{label}"))
                        break

        # Nếu match rule, log vào ALERTS, không log vào TRAFFIC
        if hits:
            for rid, message, variant in hits:
                h = hashlib.sha1(f"{rid}|{meta.get('src')}|{meta.get('dst')}|{variant}|{len(p)}".encode()).hexdigest()[:12]
                if self.should_throttle(h):
                    console_logger.debug("throttled alert %s", h)
                    continue
                try:
                    #lấy thêm action trong rules chứa alerts để biết mức độ nghiêm trọng của alert
                    if rid in self.rules:
                        meta["action"] = self.rules[rid].get("action", "unknown")
                        meta["severity"] = self.rules[rid].get("severity", "medium")
                    else:
                        meta["action"] = "unknown"
                        meta["severity"] = "medium"
                    action = meta["action"]
                    severity = meta["severity"]
                    self.log_alert(meta, p, rid, message, variant, action, severity)
#fix:
                    if action.lower() == "block" and str(meta.get("src")) != "127.0.0.1":
                        src_ip = meta.get("src")
                        if src_ip:
                            try:
                                enqueue_block(src_ip, reason=f"IDS rule {rid} triggered block action")
                                console_logger.info("Enqueued block for %s", src_ip)
                            except Exception:
                                console_logger.exception("enqueue_block error")
                except Exception:
                    console_logger.exception("log_alert error")
        else:
            # Nếu không match rule, mới log traffic
            try:
                self.log_traffic(meta, payload)
            except Exception:
                console_logger.exception("log_traffic error")

def compile_single_rule(r: Dict[str, Any]) -> Dict[str, Any]:
    ent: Dict[str, Any] = {"rule": r}
    ent["pattern_bytes"] = r.get("pattern_bytes") if isinstance(r.get("pattern_bytes"), (bytes, bytearray)) else b""
    pr = r.get("pattern_regex_bytes")
    if pr:
        try:
            ent["pattern_regex_compiled"] = re.compile(pr, flags=re.DOTALL | re.IGNORECASE)
        except Exception as e:
            console_logger.warning("Regex compile failed for %s: %s", r.get("uuid"), e)
            ent["pattern_regex_compiled"] = None
    else:
        ent["pattern_regex_compiled"] = None
    return ent

# ----------------- Packet queue & worker -----------------
pkt_queue: "queue.Queue[Any]" = queue.Queue(maxsize=20000)

def enqueue(pkt):
    try:
        pkt_queue.put_nowait(pkt)
    except queue.Full:
        console_logger.warning("Queue full, dropping packet")

def worker_loop(ids: IDS, stop_event: threading.Event):
    allowed_ports = {80}
    while not stop_event.is_set():
        try:
            pkt = pkt_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            if IP not in pkt:
                continue
            ip_pkt = pkt[IP]
            # fragment
            # res = ids.defr.push(ip_pkt)
            # if res:
            #     if res.get("dport") in allowed_ports:
            #         ids.match_payload(res["assembled_bytes"], res)
            # TCP
            if TCP in ip_pkt:
                out = ids.reasm.feed(ip_pkt)
                if out:
                    assembled_bytes, conn_key = out
                    src, dst, sport, dport = conn_key
                    if dport not in allowed_ports:
                        continue
                    meta = {"src": src, "dst": dst,
                            "sport": sport, "dport": dport, "proto": "TCP"}
                    ids.match_payload(assembled_bytes, meta)
                else:
                    t = ip_pkt[TCP]
                    raw_payload = bytes(t.payload) if Raw in t and bytes(t.payload) else b""
                    if raw_payload and t.dport in allowed_ports:
                        meta = {"src": ip_pkt.src, "dst": ip_pkt.dst,
                                "sport": t.sport, "dport": t.dport, "proto": "TCP"}
                        ids.match_payload(raw_payload, meta)
        except Exception:
            console_logger.exception("Worker loop exception")
        finally:
            try:
                pkt_queue.task_done()
            except Exception:
                pass

# ----------------- Main CLI -----------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--filter", default="")
    p.add_argument("--payload-bytes", type=int, default=8192)
    p.add_argument("--no-decode", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    if args.verbose:
        ch.setLevel(logging.DEBUG)
        console_logger.setLevel(logging.DEBUG)
    ids = IDS(RULES_PATH, enable_decode=not args.no_decode, payload_bytes=args.payload_bytes)
    stop_event = threading.Event()
    th = threading.Thread(target=worker_loop, args=(ids, stop_event), daemon=True)
    th.start()
    console_logger.info("Starting sniffer - iface=%s filter=%s payload_bytes=%d decode=%s",
                        args.iface, args.filter, args.payload_bytes, not args.no_decode)
    try:
        sniff(iface=args.iface, filter=args.filter, prn=enqueue, store=False)
    except KeyboardInterrupt:
        console_logger.info("Stopping...")
    finally:
        stop_event.set()
        th.join()

if __name__ == "__main__":
    main()
