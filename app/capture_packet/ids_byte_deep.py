#!/usr/bin/env python3
"""
ids_byte_deep.py - simple Snort-like byte-level IDS
"""

from __future__ import annotations
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
import os
import requests

# ----------------- Config paths -----------------
BASE_DIR = Path("app")
LOG_DIR = BASE_DIR / "logs"
RULES_PATH = Path("app/capture_packet/rules.json")
API_ALERT_ENDPOINT = "http://127.0.0.1:8000/api/alerts/raw"
TRAFFIC_LOG = LOG_DIR / "traffic.log"
ALERTS_LOG = LOG_DIR / "alerts.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)

# # ----------------- Logging setup -----------------
# traffic_logger = logging.getLogger("traffic")
# alerts_logger = logging.getLogger("alerts")
# console_logger = logging.getLogger("console")

# for lg in (traffic_logger, alerts_logger, console_logger):
#     lg.setLevel(logging.DEBUG)

# # console handler
# ch = logging.StreamHandler()
# ch.setLevel(logging.INFO)
# fmt_console = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
# ch.setFormatter(fmt_console)
# console_logger.addHandler(ch)

# # traffic file handler
# fh_traffic = logging.FileHandler(str(TRAFFIC_LOG), encoding="utf-8")
# fh_traffic.setLevel(logging.INFO)
# fh_traffic.setFormatter(logging.Formatter("%(asctime)s [TRAFFIC] %(message)s"))
# traffic_logger.addHandler(fh_traffic)

# # alerts file handler
# fh_alerts = logging.FileHandler(str(ALERTS_LOG), encoding="utf-8")
# fh_alerts.setLevel(logging.INFO)
# fh_alerts.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s"))
# alerts_logger.addHandler(fh_alerts)
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

# ----------------- IP Defragmenter -----------------
class IPDefragmenter:
    def __init__(self, timeout: int = 30):
        self.buckets: Dict[Tuple, Dict[str, Any]] = {}
        self.timeout = timeout
        self.lock = threading.Lock()

    def push(self, ip_pkt) -> Optional[Dict[str, Any]]:
        if getattr(ip_pkt, "flags", 0) == 0 and getattr(ip_pkt, "frag", 0) == 0:
            proto_val = ip_pkt.proto
            if proto_val == 6:
                proto_name = "TCP"
            elif proto_val == 17:
                proto_name = "UDP"
            else:
                proto_name = str(proto_val)
            return {"assembled_bytes": bytes(ip_pkt.payload),
                    "src": ip_pkt.src, "dst": ip_pkt.dst,
                    "proto": proto_name,
                    "sport": getattr(ip_pkt.payload, "sport", None),
                    "dport": getattr(ip_pkt.payload, "dport", None)}
        key = (ip_pkt.src, ip_pkt.dst, ip_pkt.id, ip_pkt.proto)
        with self.lock:
            b = self.buckets.get(key)
            if b is None:
                b = {"frags": {}, "seen_last": False, "t": time.time(), "l4meta": None}
                self.buckets[key] = b
            offset = ip_pkt.frag * 8
            b["frags"][offset] = bytes(ip_pkt.payload)
            if ip_pkt.frag == 0:
                try:
                    l4 = ip_pkt.payload
                    b["l4meta"] = {"sport": getattr(l4, "sport", None),
                                   "dport": getattr(l4, "dport", None),
                                   "proto": ip_pkt.proto}
                except Exception:
                    b["l4meta"] = None
            if (ip_pkt.flags & 1) == 0:
                b["seen_last"] = True
            if b["seen_last"]:
                offsets = sorted(b["frags"].keys())
                if offsets and offsets[0] == 0:
                    parts = []
                    expected = 0
                    for off in offsets:
                        if off != expected:
                            return None
                        parts.append(b["frags"][off])
                        expected += len(b["frags"][off])
                    assembled_payload = b"".join(parts)
                    l4meta = b.get("l4meta")
                    del self.buckets[key]
                    return {"assembled_bytes": assembled_payload,
                            "src": ip_pkt.src, "dst": ip_pkt.dst,
                            "proto": ip_pkt.proto,
                            "sport": l4meta.get("sport") if l4meta else None,
                            "dport": l4meta.get("dport") if l4meta else None}
            self._cleanup()
            return None

    def _cleanup(self):
        now = time.time()
        for k in list(self.buckets.keys()):
            if now - self.buckets[k]["t"] > self.timeout:
                del self.buckets[k]

# ----------------- TCP Reassembler -----------------
class TCPReassembler:
    def __init__(self, timeout: int = 120):
        self.conns: Dict[Tuple[str,str,int,int], Dict[str, Any]] = {}
        self.timeout = timeout
        self.lock = threading.Lock()

    def feed(self, ip_pkt) -> Optional[Tuple[bytes, Tuple[str,str,int,int]]]:
        if TCP not in ip_pkt:
            return None
        t = ip_pkt[TCP]
        key = (ip_pkt[IP].src, ip_pkt[IP].dst, t.sport, t.dport)
        seq = int(t.seq)
        data = bytes(t.payload) if Raw in t and bytes(t.payload) else b""
        with self.lock:
            st = self.conns.get(key)
            if st is None:
                st = {"segments": {}, "next_seq": None, "t": time.time()}
                self.conns[key] = st
            if data:
                st["segments"][seq] = data
            if st["next_seq"] is None and st["segments"]:
                st["next_seq"] = min(st["segments"].keys())
            out = []
            while st["next_seq"] in st["segments"]:
                out.append(st["segments"].pop(st["next_seq"]))
                st["next_seq"] += len(out[-1])
            st["t"] = time.time()
            self._cleanup()
            if out:
                return b"".join(out), key
            return None

    def _cleanup(self):
        now = time.time()
        for k in list(self.conns.keys()):
            if now - self.conns[k]["t"] > self.timeout:
                del self.conns[k]

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
        self.defr = IPDefragmenter()
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

    def log_alert(self, meta: Dict[str, Any], payload: bytes, rid: str, message: str, matched_variant: str, action: str):
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
                    "severity": meta.get('severity', 'medium'),
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
                    else:
                        meta["action"] = "unknown"
                    action = meta["action"]
                    self.log_alert(meta, p, rid, message, variant, action)
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
            res = ids.defr.push(ip_pkt)
            if res:
                if res.get("dport") in allowed_ports:
                    ids.match_payload(res["assembled_bytes"], res)
            # TCP
            if TCP in ip_pkt:
                out = ids.reasm.feed(ip_pkt)
                if out:
                    assembled_bytes, conn_key = out
                    meta = {"src": conn_key[0], "dst": conn_key[1],
                            "sport": conn_key[2], "dport": conn_key[3], "proto": "TCP"}
                    ids.match_payload(assembled_bytes, meta)
                else:
                    t = ip_pkt[TCP]
                    raw_payload = bytes(t.payload) if Raw in t and bytes(t.payload) else b""
                    if raw_payload:
                        meta = {"src": ip_pkt.src, "dst": ip_pkt.dst,
                                "sport": t.sport, "dport": t.dport, "proto": "TCP"}
                        ids.match_payload(raw_payload, meta)
            elif UDP in ip_pkt:
                u = ip_pkt[UDP]
                raw_payload = bytes(u.payload) if Raw in u and bytes(u.payload) else b""
                if raw_payload:
                    meta = {"src": ip_pkt.src, "dst": ip_pkt.dst,
                            "sport": u.sport, "dport": u.dport, "proto": "UDP"}
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
