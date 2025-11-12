#!/usr/bin/env python3
"""
ids_optimized.py - Optimized Snort-like IDS with reduced false positives
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
from collections import Counter, defaultdict
from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP
from pathlib import Path
import json
import hashlib
from urllib.parse import unquote_plus, urlparse
from typing import Dict, Any, Tuple, List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests

from app.workers.blocker import enqueue_block

# ----------------- Config paths -----------------
BASE_DIR = Path("app")
LOG_DIR = BASE_DIR / "logs"
RULES_PATH = Path("app/capture_packet/rules.json")
API_ALERT_ENDPOINT = "http://127.0.0.1:8000/api/alerts/raw"
TRAFFIC_LOG = LOG_DIR / "traffic.log"
ALERTS_LOG = LOG_DIR / "alerts.log"
FALSE_POSITIVE_LOG = LOG_DIR / "false_positive.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)

# ----------------- Logging setup -----------------
traffic_logger = logging.getLogger("traffic")
alerts_logger = logging.getLogger("alerts")
console_logger = logging.getLogger("console")
rules_logger = logging.getLogger("rules")
fp_logger = logging.getLogger("false_positive")

for lg in (traffic_logger, alerts_logger, console_logger, rules_logger, fp_logger):
    lg.setLevel(logging.DEBUG)

# console handler
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fmt_console = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch.setFormatter(fmt_console)
console_logger.addHandler(ch)

# file handlers
fh_traffic = logging.FileHandler(str(TRAFFIC_LOG), encoding="utf-8")
fh_traffic.setLevel(logging.INFO)
fh_traffic.setFormatter(logging.Formatter("%(asctime)s [TRAFFIC] %(message)s"))
traffic_logger.addHandler(fh_traffic)

fh_alerts = logging.FileHandler(str(ALERTS_LOG), encoding="utf-8")
fh_alerts.setLevel(logging.INFO)
fh_alerts.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s"))
alerts_logger.addHandler(fh_alerts)

fh_fp = logging.FileHandler(str(FALSE_POSITIVE_LOG), encoding="utf-8")
fh_fp.setLevel(logging.INFO)
fh_fp.setFormatter(logging.Formatter("%(asctime)s [FP] %(message)s"))
fp_logger.addHandler(fh_fp)

# ----------------- False Positive Reduction -----------------
class FalsePositiveReducer:
    """Advanced false positive reduction techniques"""
    
    def __init__(self):
        self.whitelist_ips = self._load_whitelist_ips()
        self.whitelist_domains = self._load_whitelist_domains()
        self.normal_traffic_patterns = defaultdict(int)
        self.fp_threshold = 5  # Minimum hits to consider normal
        self.learning_mode = True  # First 30 minutes in learning mode
        self.learning_start = time.time()
        self.learning_duration = 1800  # 30 minutes
        
    def _load_whitelist_ips(self) -> Set[str]:
        """Load whitelist IPs from file"""
        whitelist_file = Path("app/capture_packet/whitelist_ips.txt")
        if whitelist_file.exists():
            return set(whitelist_file.read_text().splitlines())
        return set()
    
    def _load_whitelist_domains(self) -> Set[str]:
        """Load whitelist domains from file"""
        whitelist_file = Path("app/capture_packet/whitelist_domains.txt")
        if whitelist_file.exists():
            return set(whitelist_file.read_text().splitlines())
        return set()
    
    def is_whitelisted(self, meta: Dict[str, Any]) -> bool:
        """Check if IP/domain is whitelisted"""
        src_ip = meta.get('src', '')
        dst_ip = meta.get('dst', '')
        
        # Check IP whitelist
        if src_ip in self.whitelist_ips or dst_ip in self.whitelist_ips:
            return True
            
        return False
    
    def update_normal_traffic(self, payload: bytes, meta: Dict[str, Any]):
        """Update normal traffic patterns during learning phase"""
        if not self.learning_mode:
            return
            
        key = f"{meta.get('src')}:{meta.get('sport')}-{meta.get('dst')}:{meta.get('dport')}"
        self.normal_traffic_patterns[key] += 1
        
        # Check if learning period is over
        if time.time() - self.learning_start > self.learning_duration:
            self.learning_mode = False
            console_logger.info("Learning mode completed. Normal traffic patterns established.")
    
    def is_normal_traffic(self, payload: bytes, meta: Dict[str, Any]) -> bool:
        """Check if traffic matches normal patterns"""
        if self.learning_mode:
            return False
            
        key = f"{meta.get('src')}:{meta.get('sport')}-{meta.get('dst')}:{meta.get('dport')}"
        return self.normal_traffic_patterns.get(key, 0) > self.fp_threshold

# ----------------- Advanced Rule Matching -----------------
class AdvancedRuleMatcher:
    """Enhanced rule matching with context awareness"""
    
    def __init__(self):
        self.protocol_context = {
            'http': self._analyze_http_context,
            'dns': self._analyze_dns_context, 
            'ftp': self._analyze_ftp_context,
            'smtp': self._analyze_smtp_context
        }
        
    def _analyze_http_context(self, payload: bytes, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP context for better rule matching"""
        context = {'is_http': False, 'method': '', 'path': '', 'headers': {}}
        
        try:
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            if lines and any(method in lines[0] for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']):
                context['is_http'] = True
                context['method'] = lines[0].split(' ')[0] if ' ' in lines[0] else ''
                context['path'] = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else ''
                
                # Parse headers
                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        context['headers'][key.lower()] = value
                    elif line == '':
                        break
        except:
            pass
            
        return context
    
    def _analyze_dns_context(self, payload: bytes, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze DNS context"""
        context = {'is_dns': False, 'query_type': ''}
        # Basic DNS detection (port 53)
        if meta.get('dport') == 53 or meta.get('sport') == 53:
            context['is_dns'] = True
        return context
    
    def _analyze_ftp_context(self, payload: bytes, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze FTP context"""
        context = {'is_ftp': False, 'command': ''}
        # FTP typically uses port 21
        if meta.get('dport') == 21 or meta.get('sport') == 21:
            context['is_ftp'] = True
            try:
                text = payload.decode('utf-8', errors='ignore').strip()
                if text:
                    context['command'] = text.split(' ')[0]
            except:
                pass
        return context
    
    def _analyze_smtp_context(self, payload: bytes, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SMTP context"""
        context = {'is_smtp': False, 'command': ''}
        # SMTP typically uses port 25
        if meta.get('dport') == 25 or meta.get('sport') == 25:
            context['is_smtp'] = True
            try:
                text = payload.decode('utf-8', errors='ignore').strip()
                if text:
                    context['command'] = text.split(' ')[0]
            except:
                pass
        return context
    
    def get_protocol_context(self, payload: bytes, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Get protocol-specific context for the payload"""
        port = meta.get('dport') or meta.get('sport')
        
        if port in [80, 443, 8080, 8000]:
            return self.protocol_context['http'](payload, meta)
        elif port == 53:
            return self.protocol_context['dns'](payload, meta)
        elif port == 21:
            return self.protocol_context['ftp'](payload, meta)
        elif port == 25:
            return self.protocol_context['smtp'](payload, meta)
            
        return {'is_unknown': True}

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
        
        # Enhanced port handling with ranges
        for p in ("dst_port", "src_port"):
            if rr.get(p) is not None:
                if isinstance(rr[p], str) and ':' in rr[p]:
                    # Handle port ranges (e.g., "80:90")
                    try:
                        start, end = map(int, rr[p].split(':'))
                        rr[p] = (start, end)
                    except:
                        rr[p] = None
                else:
                    try:
                        rr[p] = int(rr[p])
                    except:
                        rr[p] = None
        
        # Enhanced pattern compilation
        if rr.get("pattern_bytes") and isinstance(rr["pattern_bytes"], str):
            rr["pattern_bytes"] = rr["pattern_bytes"].encode("latin1")
            
        if rr.get("pattern_hex") and not rr.get("pattern_bytes"):
            try:
                rr["pattern_bytes"] = binascii.unhexlify(rr["pattern_hex"].replace(' ', ''))
            except Exception:
                rr["pattern_bytes"] = None
                
        # Add confidence score if not present
        if "confidence" not in rr:
            rr["confidence"] = rr.get("severity", "medium")
                
        rules.append(rr)
        
    console_logger.info("Loaded %d rules", len(rules))
    return rules

def compile_single_rule(r: Dict[str, Any]) -> Dict[str, Any]:
    ent: Dict[str, Any] = {"rule": r}
    ent["pattern_bytes"] = r.get("pattern_bytes") if isinstance(r.get("pattern_bytes"), (bytes, bytearray)) else b""
    
    pr = r.get("pattern_regex_bytes")
    if pr:
        try:
            flags = re.DOTALL
            if r.get("case_insensitive", True):
                flags |= re.IGNORECASE
            ent["pattern_regex_compiled"] = re.compile(pr, flags=flags)
        except Exception as e:
            console_logger.warning("Regex compile failed for %s: %s", rule_id(r), e)
            ent["pattern_regex_compiled"] = None
    else:
        ent["pattern_regex_compiled"] = None
        
    return ent

def compile_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled = []
    for r in raw_rules:
        compiled.append(compile_single_rule(r))
    return compiled

# ----------------- Aho automaton -----------------
# ----------------- Aho automaton (ahocorapy) -----------------
from ahocorapy.keywordtree import KeywordTree
from typing import List, Dict, Any, Optional

def build_aho(raw_rules: List[Dict[str, Any]], console_logger=None) -> Optional[KeywordTree]:
    """
    Xây dựng Aho-Corasick automaton từ danh sách rule.
    Sử dụng ahocorapy (pure Python) cho Python >=3.13.
    """
    try:
        A = KeywordTree(case_insensitive=False)
    except Exception as e:
        if console_logger:
            console_logger.warning("Không thể khởi tạo KeywordTree: %s", e)
        return None

    added = 0
    for idx, r in enumerate(raw_rules):
        try:
            if not r.get("use_aho") or not r.get("pattern_bytes"):
                continue

            pat = r["pattern_bytes"]
            # pattern có thể là bytes hoặc str
            if isinstance(pat, bytes):
                key = pat.decode("latin1", errors="ignore")
            else:
                key = str(pat)

            data = {
                "idx": idx,
                "uuid": r.get("uuid") or r.get("id") or f"rule_{idx}",
                "message": r.get("message", ""),
                "severity": r.get("severity", "medium")
            }

            A.add(key, data)
            added += 1

        except Exception as e:
            if console_logger:
                console_logger.warning("Bỏ qua rule lỗi (%s): %s", r.get("uuid", "unknown"), e)

    if added == 0:
        if console_logger:
            console_logger.warning("Không có rule nào được thêm vào AHO automaton.")
        return None

    try:
        A.finalize()
        if console_logger:
            console_logger.info("✅ AHO automaton đã xây dựng thành công với %d patterns", added)
        return A
    except Exception as e:
        if console_logger:
            console_logger.error("❌ Lỗi khi hoàn tất automaton: %s", e)
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

# ----------------- Enhanced Defragmenter -----------------
class EnhancedIPDefragmenter:
    def __init__(self, timeout: int = 30):
        self.buckets: Dict[Tuple, Dict[str, Any]] = {}
        self.timeout = timeout
        self.lock = threading.Lock()

    def push(self, ip_pkt) -> Optional[Dict[str, Any]]:
        if getattr(ip_pkt, "flags", 0) == 0 and getattr(ip_pkt, "frag", 0) == 0:
            # Not fragmented
            proto_val = ip_pkt.proto
            if proto_val == 6:
                proto_name = "TCP"
            elif proto_val == 17:
                proto_name = "UDP"
            elif proto_val == 1:
                proto_name = "ICMP"
            else:
                proto_name = str(proto_val)
                
            return {
                "assembled_bytes": bytes(ip_pkt.payload),
                "src": ip_pkt.src, "dst": ip_pkt.dst,
                "proto": proto_name,
                "sport": getattr(ip_pkt.payload, "sport", None),
                "dport": getattr(ip_pkt.payload, "dport", None)
            }
            
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
                    b["l4meta"] = {
                        "sport": getattr(l4, "sport", None),
                        "dport": getattr(l4, "dport", None),
                        "proto": ip_pkt.proto
                    }
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
                    
                    proto_name = "TCP" if l4meta and l4meta.get("proto") == 6 else \
                                "UDP" if l4meta and l4meta.get("proto") == 17 else \
                                "ICMP" if l4meta and l4meta.get("proto") == 1 else str(l4meta.get("proto") if l4meta else "UNKNOWN")
                    
                    return {
                        "assembled_bytes": assembled_payload,
                        "src": ip_pkt.src, "dst": ip_pkt.dst,
                        "proto": proto_name,
                        "sport": l4meta.get("sport") if l4meta else None,
                        "dport": l4meta.get("dport") if l4meta else None
                    }
                    
            self._cleanup()
            return None

    def _cleanup(self):
        now = time.time()
        expired = []
        for k, v in self.buckets.items():
            if now - v["t"] > self.timeout:
                expired.append(k)
        for k in expired:
            del self.buckets[k]

# ----------------- Enhanced TCP Reassembler -----------------
class EnhancedTCPReassembler:
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
        expired = []
        for k, v in self.conns.items():
            if now - v["t"] > self.timeout:
                expired.append(k)
        for k in expired:
            del self.conns[k]

# ----------------- Enhanced IDS Engine -----------------
class EnhancedIDS:
    def __init__(self, rules_path: Path, enable_decode: bool = True, payload_bytes: int = 4096):
        self._last_rules_event_time = 0
        self.rules_path = rules_path
        self.enable_decode = enable_decode
        self.payload_bytes = int(payload_bytes)
        
        # Enhanced components
        self.fp_reducer = FalsePositiveReducer()
        self.rule_matcher = AdvancedRuleMatcher()
        self.defr = EnhancedIPDefragmenter()
        self.reasm = EnhancedTCPReassembler()
        
        # Alert management
        self.last_alerts: Dict[str, float] = {}
        self.alert_throttle = 2.0
        self.confidence_threshold = 0.7
        
        # State tracking
        self.logged_payloads: Set[Tuple] = set()
        self.logged_payloads_cleanup_interval = 60
        self._last_cleanup = time.time()
        
        # Load initial rules
        self.reload_rules()
        self._start_rules_watcher()

    def reload_rules(self):
        """Reload rules with enhanced compilation"""
        console_logger.info("Reloading rules from %s", self.rules_path)
        try:
            new_raw = load_rules(self.rules_path)
            new_compiled = compile_rules(new_raw)
            new_aho = build_aho(new_raw)
            
            self.rules_raw = new_raw
            self.compiled = new_compiled
            self.aho = new_aho
            self.rules_map = {rule_id(r): r for r in self.rules_raw}
            
            console_logger.info("Rules reloaded: %d rules", len(self.rules_raw))
        except Exception as e:
            console_logger.error("Failed to reload rules: %s", e)

    def calculate_confidence_score(self, rule: Dict[str, Any], context: Dict[str, Any], 
                                 matched_variant: str) -> float:
        """Calculate confidence score for a rule match"""
        base_score = 0.5
        
        # Rule confidence
        if rule.get("confidence") == "high":
            base_score += 0.3
        elif rule.get("confidence") == "medium":
            base_score += 0.2
        elif rule.get("confidence") == "low":
            base_score += 0.1
            
        # Protocol context match
        if context.get('is_http') and rule.get('proto') == 'TCP' and (rule.get('dst_port') == 80 or rule.get('dst_port') == 443):
            base_score += 0.2
            
        # Matching method
        if matched_variant.startswith("BYTES"):
            base_score += 0.1
        elif matched_variant.startswith("REGEX"):
            base_score += 0.05
        elif matched_variant.startswith("AHO"):
            base_score += 0.15
            
        return min(1.0, base_score)

    def should_alert(self, meta: Dict[str, Any], payload: bytes, rule_id: str, 
                   confidence: float) -> bool:
        """Determine if an alert should be raised (false positive reduction)"""
        
        # Check whitelist
        if self.fp_reducer.is_whitelisted(meta):
            fp_logger.info("Whitelisted traffic: %s -> %s rule=%s", 
                         meta.get('src'), meta.get('dst'), rule_id)
            return False
            
        # Check normal traffic patterns
        if self.fp_reducer.is_normal_traffic(payload, meta):
            fp_logger.info("Normal traffic pattern: %s -> %s rule=%s", 
                         meta.get('src'), meta.get('dst'), rule_id)
            return False
            
        # Check confidence threshold
        if confidence < self.confidence_threshold:
            fp_logger.info("Low confidence: %s rule=%s conf=%.2f", 
                         meta.get('src'), rule_id, confidence)
            return False
            
        return True

    def match_payload(self, payload: bytes, meta: Dict[str, Any]):
        """Enhanced payload matching with false positive reduction"""
        
        # Update normal traffic patterns
        self.fp_reducer.update_normal_traffic(payload, meta)
        
        # Skip empty payloads
        if not payload or len(payload) == 0:
            return
            
        p = payload[:self.payload_bytes]
        
        # Get protocol context
        context = self.rule_matcher.get_protocol_context(p, meta)
        
        variants = generate_decodes(p, self.enable_decode)
        hits: List[Tuple[str, str, str, float]] = []  # (rule_id, message, variant, confidence)

        # AHO-Corasick matching
        if self.aho:
            try:
                s_raw = p.decode('latin1', errors='ignore')
                for end_index, (idx, rid, message, confidence) in self.aho.iter(s_raw):
                    conf_score = self.calculate_confidence_score(
                        self.rules_map.get(rid, {}), context, "AHO_raw"
                    )
                    hits.append((rid, message, "AHO_raw", conf_score))
            except Exception:
                console_logger.debug("AHO error", exc_info=True)

        # Rule-based matching
        for entry in self.compiled:
            r = entry["rule"]
            
            # Protocol check
            rule_proto = (r.get("proto") or "ANY").upper()
            if rule_proto != "ANY" and str(meta.get("proto") or "").upper() != rule_proto:
                continue

            # Destination port check with range support
            dst_port_rule = r.get("dst_port")
            dst_port_meta = meta.get("dport")
            if dst_port_rule is not None and dst_port_meta is not None:
                if isinstance(dst_port_rule, tuple):  # Port range
                    if not (dst_port_rule[0] <= dst_port_meta <= dst_port_rule[1]):
                        continue
                elif dst_port_rule != dst_port_meta:
                    continue

            # Source port check with range support
            src_port_rule = r.get("src_port")
            src_port_meta = meta.get("sport")
            if src_port_rule is not None and src_port_meta is not None:
                if isinstance(src_port_rule, tuple):  # Port range
                    if not (src_port_rule[0] <= src_port_meta <= src_port_rule[1]):
                        continue
                elif src_port_rule != src_port_meta:
                    continue

            # Pattern matching
            pb = entry.get("pattern_bytes")
            if pb and pb in p:
                conf_score = self.calculate_confidence_score(r, context, "BYTES_raw")
                hits.append((rule_id(r), r.get("message"), "BYTES_raw", conf_score))
                continue

            regex = entry.get("pattern_regex_compiled")
            if regex:
                for label, txt in variants:
                    if regex.search(txt):
                        conf_score = self.calculate_confidence_score(r, context, f"REGEX_{label}")
                        hits.append((rule_id(r), r.get("message"), f"REGEX_{label}", conf_score))
                        break

        # Process hits with false positive reduction
        for rid, message, variant, confidence in hits:
            alert_key = hashlib.sha1(
                f"{rid}|{meta.get('src')}|{meta.get('dst')}|{variant}".encode()
            ).hexdigest()[:12]
            
            # Throttle check
            if self.should_throttle(alert_key):
                console_logger.debug("throttled alert %s", alert_key)
                continue
                
            # False positive check
            if not self.should_alert(meta, p, rid, confidence):
                continue

            # Log alert
            try:
                rule_info = self.rules_map.get(rid, {})
                action = rule_info.get("action", "alert")
                severity = rule_info.get("severity", "medium")
                
                self.log_alert(meta, p, rid, message, variant, action, severity, confidence)
                
                # Auto-block if configured
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

    def should_throttle(self, sig: str) -> bool:
        now = time.time()
        last = self.last_alerts.get(sig)
        if last and (now - last) < self.alert_throttle:
            return True
        self.last_alerts[sig] = now
        return False

    def log_traffic(self, meta: Dict[str, Any], payload: bytes):
        """Log traffic with deduplication"""
        try:
            key = (meta.get('src'), meta.get('dst'), meta.get('sport'), 
                   meta.get('dport'), meta.get('proto'), hashlib.sha1(payload).hexdigest())
                   
            if key in self.logged_payloads:
                return
                
            self.logged_payloads.add(key)
            
            # Cleanup old entries
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

    def log_alert(self, meta: Dict[str, Any], payload: bytes, rid: str, message: str, 
                 matched_variant: str, action: str, severity: str, confidence: float):
        """Log alert with enhanced information"""
        try:
            key = (meta.get('src'), meta.get('dst'), meta.get('sport'),
                   meta.get('dport'), meta.get('proto'), hashlib.sha1(payload).hexdigest())
                   
            if key in self.logged_payloads:
                return
                
            self.logged_payloads.add(key)
            
            # Cleanup
            now = time.time()
            if now - self._last_cleanup > self.logged_payloads_cleanup_interval:
                self.logged_payloads.clear()
                self._last_cleanup = now
                
            ent = entropy(payload)
            hd = hexdump(payload[:2048])
            src = f"{meta.get('src')}:{meta.get('sport') or ''}"
            dst = f"{meta.get('dst')}:{meta.get('dport') or ''}"
            
            s = (f"ALERT [{rid}] {message} | proto={meta.get('proto')} {src}->{dst} "
                 f"variant={matched_variant} entropy={ent:.3f} confidence={confidence:.2f} "
                 f"action={action} severity={severity}\nhexdump:\n{hd}\n")
                 
            alerts_logger.info(s)
            console_logger.info("ALERT %s %s -> %s (%s) conf=%.2f", rid, src, dst, message, confidence)
            
            # Send to API
            try:
                api_payload = {
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
                    "confidence": confidence,
                    "payload": base64.b64encode(payload).decode('ascii'),
                    "severity": severity
                }

                # Uncomment to enable API alerts
                # response = requests.post(API_ALERT_ENDPOINT, json=api_payload, timeout=5)
                # if response.status_code == 201:
                #     console_logger.debug("Alert sent to API successfully")
                # else:
                #     console_logger.error("Failed to send alert to API: %s", response.status_code)
            except Exception as e:
                console_logger.error("Error sending alert to API: %s", e)
                
        except Exception:
            console_logger.exception("log_alert error")

    def _start_rules_watcher(self):
        """Start rules file watcher for automatic reloads"""
        class RulesFileHandler(FileSystemEventHandler):
            def __init__(self, ids: EnhancedIDS):
                self.ids = ids
                self.last_modified = 0

            def on_modified(self, event):
                if event.is_directory:
                    return
                if os.path.abspath(event.src_path) == os.path.abspath(self.ids.rules_path):
                    current_time = time.time()
                    # Debounce: only reload once per second
                    if current_time - self.last_modified > 1.0:
                        self.last_modified = current_time
                        console_logger.info("Rules file modified, reloading...")
                        self.ids.reload_rules()

        observer = Observer()
        event_handler = RulesFileHandler(self)
        observer.schedule(event_handler, path=os.path.dirname(self.rules_path), recursive=False)
        observer.start()
        console_logger.info("Started rules file watcher")

# ----------------- Packet processing -----------------
pkt_queue = queue.Queue(maxsize=20000)

def enqueue(pkt):
    try:
        pkt_queue.put_nowait(pkt)
    except queue.Full:
        console_logger.warning("Queue full, dropping packet")

def worker_loop(ids: EnhancedIDS, stop_event: threading.Event):
    """Enhanced worker loop with better protocol handling"""
    while not stop_event.is_set():
        try:
            pkt = pkt_queue.get(timeout=0.5)
        except queue.Empty:
            continue
            
        try:
            if IP not in pkt:
                continue
                
            ip_pkt = pkt[IP]
            
            # IP defragmentation
            res = ids.defr.push(ip_pkt)
            if res:
                ids.match_payload(res["assembled_bytes"], res)
                
            # TCP reassembly
            if TCP in ip_pkt:
                out = ids.reasm.feed(ip_pkt)
                if out:
                    assembled_bytes, conn_key = out
                    meta = {
                        "src": conn_key[0], "dst": conn_key[1],
                        "sport": conn_key[2], "dport": conn_key[3], 
                        "proto": "TCP"
                    }
                    ids.match_payload(assembled_bytes, meta)
                else:
                    # Process individual TCP packets
                    t = ip_pkt[TCP]
                    raw_payload = bytes(t.payload) if Raw in t and bytes(t.payload) else b""
                    if raw_payload:
                        meta = {
                            "src": ip_pkt.src, "dst": ip_pkt.dst,
                            "sport": t.sport, "dport": t.dport, 
                            "proto": "TCP"
                        }
                        ids.match_payload(raw_payload, meta)
                        
            # UDP packets
            elif UDP in ip_pkt:
                u = ip_pkt[UDP]
                raw_payload = bytes(u.payload) if Raw in u and bytes(u.payload) else b""
                if raw_payload:
                    meta = {
                        "src": ip_pkt.src, "dst": ip_pkt.dst,
                        "sport": u.sport, "dport": u.dport, 
                        "proto": "UDP"
                    }
                    ids.match_payload(raw_payload, meta)
                    
            # ICMP packets
            elif ICMP in ip_pkt:
                icmp = ip_pkt[ICMP]
                raw_payload = bytes(icmp.payload) if hasattr(icmp, 'payload') and icmp.payload else b""
                if raw_payload:
                    meta = {
                        "src": ip_pkt.src, "dst": ip_pkt.dst,
                        "proto": "ICMP"
                    }
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
    parser = argparse.ArgumentParser(description="Enhanced IDS with false positive reduction")
    parser.add_argument("--iface", required=True, help="Network interface to monitor")
    parser.add_argument("--filter", default="", help="BPF filter for packet capture")
    parser.add_argument("--payload-bytes", type=int, default=8192, help="Max payload bytes to inspect")
    parser.add_argument("--no-decode", action="store_true", help="Disable payload decoding")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--confidence", type=float, default=0.7, help="Minimum confidence threshold (0.0-1.0)")
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        ch.setLevel(logging.DEBUG)
        console_logger.setLevel(logging.DEBUG)
        
    # Initialize enhanced IDS
    ids = EnhancedIDS(
        RULES_PATH, 
        enable_decode=not args.no_decode, 
        payload_bytes=args.payload_bytes
    )
    ids.confidence_threshold = args.confidence
    
    stop_event = threading.Event()
    worker_thread = threading.Thread(target=worker_loop, args=(ids, stop_event), daemon=True)
    worker_thread.start()
    
    console_logger.info(
        "Starting enhanced IDS - iface=%s filter=%s payload_bytes=%d decode=%s confidence=%.2f",
        args.iface, args.filter, args.payload_bytes, not args.no_decode, args.confidence
    )
    
    try:
        sniff(iface=args.iface, filter=args.filter, prn=enqueue, store=False)
    except KeyboardInterrupt:
        console_logger.info("Stopping...")
    finally:
        stop_event.set()
        worker_thread.join()

if __name__ == "__main__":
    main()