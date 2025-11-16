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
from app.capture_packet.http_parser import HTTPParser, HTTPParseResult
import pcre2 

# ----------------- IDS Engine -----------------
from app.capture_packet.reassembly_module import TCPReassembler
from app.capture_packet.utils_module import (
    load_rules,
    compile_rules,
    build_aho,
    generate_decodes,
    entropy,
    hexdump,
    rule_id,
    dict_diff,
)

# ----------------- Config paths -----------------
BASE_DIR = Path("app")
LOG_DIR = BASE_DIR / "logs"
RULES_PATH = Path("app/capture_packet/rules_fix.json")
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

# def compile_single_rule(r: Dict[str, Any]) -> Dict[str, Any]:
#     ent: Dict[str, Any] = {"rule": r}
#     ent["pattern_bytes"] = r.get("pattern_bytes") if isinstance(r.get("pattern_bytes"), (bytes, bytearray)) else b""
#     pr = r.get("pattern_regex_bytes")
#     if pr:
#         try:
#             ent["pattern_regex_compiled"] = re.compile(pr, flags=re.DOTALL | re.IGNORECASE)
#         except Exception as e:
#             console_logger.warning("Regex compile failed for %s: %s", r.get("uuid"), e)
#             ent["pattern_regex_compiled"] = None
#     else:
#         ent["pattern_regex_compiled"] = None
#     return ent
#fix:

def compile_single_rule(r: Dict[str, Any]) -> Dict[str, Any]:
    ent: Dict[str, Any] = {"rule": r}
    compiled_contents = []
    for c in r.get("content", []):
        if isinstance(c, str):
            content_dict = {"pattern": c, "nocase": False, "fast_pattern": False}
        else:
            content_dict = {
                "pattern": c.get("pattern") or c.get("value") or "",
                "nocase": bool(c.get("nocase")),
                "fast_pattern": bool(c.get("fast_pattern", False)),
            }
        pattern_bytes = content_dict["pattern"].encode("latin1", "ignore")
        compiled_contents.append({
            "raw": content_dict,
            "pattern_bytes": pattern_bytes,
            "fast_pattern": content_dict["fast_pattern"]
        })
    ent["contents"] = compiled_contents

    pcre_pattern = r.get("pcre")
    if pcre_pattern:
        try:
            flags = pcre2.DOTALL
            if any(c.get("nocase", False) for c in r.get("content", [])):
                flags |= pcre2.IGNORECASE
            ent["pcre_compiled"] = pcre2.compile(pcre_pattern.encode("latin1"), flags=flags)
        except Exception:
            ent["pcre_compiled"] = None
    else:
        ent["pcre_compiled"] = None
    return ent


class IDS:
    def __init__(self, rules_path: Path, enable_decode: bool = False, payload_bytes: int = 4096):
        self._last_rules_event_time = 0
        self.rules_path = rules_path
        self.rules_raw = load_rules(rules_path)
        # compile rules into byte-level structures
        self.compiled = compile_rules(self.rules_raw)
        # build aho from compiled rules (fast patterns)
        self.aho, self.aho_map = build_aho(self.compiled)
        self.enable_decode = enable_decode  # default False for Snort-like pipeline
        self.payload_bytes = int(payload_bytes)
        self.reasm = TCPReassembler()
        self.last_alerts: Dict[str, float] = {}
        self.alert_throttle = 2.0
        self.logged_payloads = set()
        self.logged_payloads_cleanup_interval = 60
        self._last_cleanup = time.time()
        self.rules: Dict[str, Dict[str, Any]] = {rule_id(r): r for r in self.rules_raw}
        self.rules_map = { (r.get("uuid") or rule_id(r)): r for r in self.rules_raw }
        self.compiled_map = {}  # filled by incremental loader if used
        self._start_rules_watcher()
        # http parser instance
        self.http_parser = HTTPParser()

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
            new_aho, _ = build_aho(new_compiled)
            self.rules_raw = new_raw
            self.compiled = new_compiled
            self.aho = new_aho
            self.rules = {rule_id(r): r for r in new_raw}
            console_logger.info("Rules reloaded: %d rules", len(self.rules_raw))
        except Exception as e:
            console_logger.error("Failed to reload rules: %s", e)
    def reload_rules_incremental(self):
        """
        Incremental reload: use compile_single_rule for changed rules.
        """
        rules_logger.info("Starting incremental reload from %s", self.rules_path)
        try:
            new_raw = load_rules(self.rules_path)
            new_map = {}
            new_compiled_map = {}

            # load/compile all into maps
            for r in new_raw:
                rid = r.get("uuid") or rule_id(r)
                new_map[rid] = r
                try:
                    new_compiled_map[rid] = compile_single_rule(r)
                except Exception as e:
                    rules_logger.error("Compile single rule failed %s: %s", rid, e)
                    new_compiled_map[rid] = {"rule": r, "contents": [], "pcre_compiled": None}

            # determine added/updated/removed
            old_ids = set(self.rules_map.keys()) if hasattr(self, "rules_map") else set()
            new_ids = set(new_map.keys())
            added = new_ids - old_ids
            removed = old_ids - new_ids
            updated = set(i for i in new_ids & old_ids if new_map[i] != self.rules_map.get(i))

            # apply
            self.rules_map = new_map
            # rebuild compiled list from compiled_map values
            self.compiled_map = new_compiled_map
            self.compiled = list(new_compiled_map.values())
            # rebuild aho
            self.aho, _ = build_aho(self.compiled)
            self.rules_raw = new_raw

            rules_logger.info("Incremental reload done: total=%d added=%d updated=%d removed=%d",
                              len(self.rules_raw), len(added), len(updated), len(removed))
            console_logger.info("Rules reload: +%d ~%d -%d (total=%d)", len(added), len(updated), len(removed), len(self.rules_raw))
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
        """
        Full Snort-like payload matching pipeline
        1. Build multi-buffer from HTTP fields (uses HTTPParseResult.regions)
        2. Fast pattern Aho-Corasick (latin1 mapping) — supports two build styles:
        - self.aho is dict[str, Automaton] (per-buffer automata)
        - self.aho is Automaton and self.aho_map maps key->list[(rule_idx, content_idx)]
        3. Full content match with offset/depth/distance/within
        4. PCRE match on decoded variants if required
        5. Alert logging + optional block
        """

        # --- 0. truncate payload if needed ---
        p = payload[: self.payload_bytes]

        # --- 1. build buffers (multi-buffer like Snort) ---
        buffers: Dict[str, bytes] = {"raw": p}

        try:
            parsed: HTTPParseResult = self.http_parser.parse(p, client_side=True)

            # Merge regions from parser (Snort-style). parsed.regions is Dict[str, bytes].
            # Only accept bytes values (type-safe).
            for region_name, region_value in parsed.regions.items():
                if isinstance(region_value, (bytes, bytearray)):
                    buffers[region_name] = bytes(region_value)

            # NOTE:
            # --- DO NOT call undefined some_mapping.update(...) here ---
            # We don't need to update any external mapping at this point.
            # Buffers are ready and type-safe: Dict[str, bytes].
        except Exception:
            console_logger.debug("HTTP parse error", exc_info=True)

        # --- prepare hits list ---
        hits: List[Tuple[str, str, str]] = []

        # --- 2. Fast pattern Aho-Corasick (bytes -> latin1) ---
        if self.aho:
            try:
                # Case A: self.aho is a dict of automata per region (e.g., {"raw": automaton, "http_uri": automaton, ...})
                if isinstance(self.aho, dict):
                    for buf_name, buf_bytes in buffers.items():
                        aho_automaton = self.aho.get(buf_name)
                        if not aho_automaton:
                            continue
                        s = buf_bytes.decode("latin1", "ignore")
                        for end_index, val in aho_automaton.iter(s):
                            # if automaton stores value as (rule_idx, content_idx) directly adjust accordingly
                            # we assume val is the pattern key or stored payload; map to rule indices if needed
                            # Best-effort: accept either (rule_idx, content_idx) or key -> lookup in aho_map
                            if isinstance(val, tuple) and len(val) == 2 and isinstance(val[0], int):
                                rule_idx, content_idx = val
                                r = self.compiled[rule_idx]["rule"]
                                hits.append((rule_id(r), r.get("message"), f"AHO_{buf_name}"))
                            else:
                                # val is likely the key string -> use self.aho_map if present
                                key = val
                                if getattr(self, "aho_map", None):
                                    for rule_idx, _ in self.aho_map.get(key, []):
                                        r = self.compiled[rule_idx]["rule"]
                                        hits.append((rule_id(r), r.get("message"), f"AHO_{buf_name}"))
                                else:
                                    # fallback: can't map -> still record the key match as generic
                                    hits.append((f"AHO_KEY:{key}", f"AHO matched key {key}", f"AHO_{buf_name}"))
                else:
                    # Case B: self.aho is a single Automaton and self.aho_map maps key->list[(rule_idx, content_idx)]
                    automaton = self.aho
                    aho_map = getattr(self, "aho_map", {}) or {}
                    for buf_name, buf_bytes in buffers.items():
                        s = buf_bytes.decode("latin1", "ignore")
                        for end_index, val in automaton.iter(s):
                            # val is the key string (that's how build_aho added words)
                            key = val
                            for rule_idx, _ in aho_map.get(key, []):
                                r = self.compiled[rule_idx]["rule"]
                                hits.append((rule_id(r), r.get("message"), f"AHO_{buf_name}"))
            except Exception:
                console_logger.debug("AHO error", exc_info=True)

        # --- 3. Full content + match-position with offset/depth/distance/within ---
        for entry in self.compiled:
            r = entry["rule"]

            # --- 3a. early proto/port filtering ---
            rule_proto = (r.get("proto") or "ANY").upper()
            if rule_proto != "ANY" and str(meta.get("proto") or "").upper() != rule_proto:
                continue

            if r.get("dst_port") is not None and meta.get("dport") is not None:
                if r["dst_port"] != meta["dport"]:
                    continue
            if r.get("src_port") is not None and meta.get("sport") is not None:
                if r["src_port"] != meta["sport"]:
                    continue

            # --- 3b. Full content match ---
            contents = entry.get("contents", [])
            last_end = 0
            rule_matched = True

            for idx, c in enumerate(contents):
                # choose buffer per content (multi-buffer)
                buf_name = c["raw"].get("field", "raw")
                buf = buffers.get(buf_name, buffers["raw"])

                pat = c["pattern_bytes"]
                nocase = c["raw"].get("nocase", False)

                # choose haystack according to nocase
                hs = buf.lower() if nocase else buf
                needle = pat.lower() if nocase else pat

                # --- content #1: offset + depth ---
                if idx == 0:
                    start = c["raw"].get("offset", 0) or 0
                    start = max(0, start)
                    depth = c["raw"].get("depth", None)
                    end = start + depth if (depth is not None and depth >= 0) else len(buf)
                # --- content 2+: distance + within ---
                else:
                    distance = c["raw"].get("distance", 0) or 0
                    start = last_end + distance
                    within = c["raw"].get("within", None)
                    end = last_end + within if (within is not None and within >= 0) else len(buf)

                start = max(0, int(start))
                end = min(len(buf), int(end))
                if start > end:
                    rule_matched = False
                    break

                pos = hs.find(needle, start, end)
                if pos < 0:
                    rule_matched = False
                    break

                last_end = pos + len(needle)

            if not rule_matched:
                continue

            # --- 3c. PCRE matching (Snort-like) ---
            pcre = entry.get("pcre_compiled")
            if pcre:
                variants = generate_decodes(buf, enable_decode=self.enable_decode)
                matched_pcre = False
                for label, txt in variants:
                    # convert bytes -> latin1 string 1:1
                    if isinstance(txt, bytes):
                        txt = txt.decode("latin1", "ignore")
                    try:
                        if pcre.match(txt) or pcre.search(txt):
                            matched_pcre = True
                            break
                    except Exception:
                        continue
                if not matched_pcre:
                    continue

            # --- 3d. Matched rule ---
            hits.append((rule_id(r), r.get("message"), f"FULL_{buf_name}"))

        # --- 4. Log alerts or traffic ---
        if hits:
            for rid, message, variant in hits:
                h = hashlib.sha1(f"{rid}|{meta.get('src')}|{meta.get('dst')}|{variant}|{len(p)}".encode()).hexdigest()[:12]
                if self.should_throttle(h):
                    console_logger.debug("throttled alert %s", h)
                    continue
                try:
                    # add action + severity
                    if rid in self.rules:
                        meta["action"] = self.rules[rid].get("action", "unknown")
                        meta["severity"] = self.rules[rid].get("severity", "medium")
                    else:
                        meta["action"] = "unknown"
                        meta["severity"] = "medium"
                    action = meta["action"]
                    severity = meta["severity"]
                    self.log_alert(meta, p, rid, message, variant, action, severity)

                    # Block if requested
                    # if action.lower() == "block" and str(meta.get("src")) != "127.0.0.1":
                    #     src_ip = meta.get("src")
                    #     if src_ip:
                    #         try:
                    #             enqueue_block(src_ip, reason=f"IDS rule {rid} triggered block action")
                    #             console_logger.info("Enqueued block for %s", src_ip)
                    #         except Exception:
                    #             console_logger.exception("enqueue_block error")
                except Exception:
                    console_logger.exception("log_alert error")
        else:
            try:
                self.log_traffic(meta, payload)
            except Exception:
                console_logger.exception("log_traffic error")

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
                print(out)
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

# ----------------- Old simple match_payload (byte + regex only) -----------------
        
#     def match_payload(self, payload: bytes, meta: Dict[str, Any]):
#         p = payload[: self.payload_bytes]
#         variants = generate_decodes(p, self.enable_decode)
#         hits: List[Tuple[str,str,str]] = []

#         if self.aho:
#             try:
#                 s_raw = p.decode('latin1', errors='ignore')
#                 for end_index, (idx, rid, message) in self.aho.iter(s_raw):
#                     hits.append((rid, message, "AHO_raw"))
#             except Exception:
#                 console_logger.debug("AHO error", exc_info=True)

#         for entry in self.compiled:
#             r = entry["rule"]
#             rule_proto = (r.get("proto") or "ANY").upper()
#             if rule_proto != "ANY" and str(meta.get("proto") or "").upper() != rule_proto:
#                 continue

#             dst_port_rule = r.get("dst_port")
#             dst_port_meta = meta.get("dport")
#             if dst_port_rule is not None and dst_port_meta is not None and dst_port_rule != dst_port_meta:
#                 continue

#             src_port_rule = r.get("src_port")
#             src_port_meta = meta.get("sport")
#             if src_port_rule is not None and src_port_meta is not None and src_port_rule != src_port_meta:
#                 continue

#             pb = entry.get("pattern_bytes")
#             if pb and pb in p:
#                 hits.append((rule_id(r), r.get("message"), "BYTES_raw"))
#                 continue

#             regex = entry.get("pattern_regex_compiled")
#             if regex:
#                 for label, txt in variants:
#                     if regex.search(txt):
#                         hits.append((rule_id(r), r.get("message"), f"REGEX_{label}"))
#                         break

#         # Nếu match rule, log vào ALERTS, không log vào TRAFFIC
#         if hits:
#             for rid, message, variant in hits:
#                 h = hashlib.sha1(f"{rid}|{meta.get('src')}|{meta.get('dst')}|{variant}|{len(p)}".encode()).hexdigest()[:12]
#                 if self.should_throttle(h):
#                     console_logger.debug("throttled alert %s", h)
#                     continue
#                 try:
#                     #lấy thêm action trong rules chứa alerts để biết mức độ nghiêm trọng của alert
#                     if rid in self.rules:
#                         meta["action"] = self.rules[rid].get("action", "unknown")
#                         meta["severity"] = self.rules[rid].get("severity", "medium")
#                     else:
#                         meta["action"] = "unknown"
#                         meta["severity"] = "medium"
#                     action = meta["action"]
#                     severity = meta["severity"]
#                     self.log_alert(meta, p, rid, message, variant, action, severity)
# #fix:
#                     if action.lower() == "block" and str(meta.get("src")) != "127.0.0.1":
#                         src_ip = meta.get("src")
#                         if src_ip:
#                             try:
#                                 enqueue_block(src_ip, reason=f"IDS rule {rid} triggered block action")
#                                 console_logger.info("Enqueued block for %s", src_ip)
#                             except Exception:
#                                 console_logger.exception("enqueue_block error")
#                 except Exception:
#                     console_logger.exception("log_alert error")
#         else:
#             # Nếu không match rule, mới log traffic
#             try:
#                 self.log_traffic(meta, payload)
#             except Exception:
#                 console_logger.exception("log_traffic error")