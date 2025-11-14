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