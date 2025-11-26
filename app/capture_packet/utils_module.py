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
RULES_FIX_PATH = Path("app/capture_packet/rules_fix.json")
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
    except Exception as e:
        console_logger.error("Failed to load rules: %s", e)
        return []

    rules: List[Dict[str, Any]] = []
    for r in raw:
        rr = dict(r)

        # normalize protocol
        rr["proto"] = rr.get("proto", "ANY").upper()
        for p in ("dst_port", "src_port"):
            try:
                rr[p] = int(rr[p]) if rr.get(p) is not None else None
            except Exception:
                rr[p] = None

        # normalize content list (support string or dict)
        norm_contents = []
        for c in rr.get("content", []):
            if isinstance(c, str):
                norm_contents.append({
                    "pattern": c,
                    "nocase": False,
                    "fast_pattern": False,
                })
                continue

            if not isinstance(c, dict):
                continue

            content_dict = dict(c)
            content_dict["pattern"] = c.get("pattern") or c.get("value") or ""
            content_dict["nocase"] = bool(c.get("nocase"))
            content_dict["fast_pattern"] = bool(c.get("fast_pattern"))

            for int_field in ("offset", "depth", "distance", "within"):
                if c.get(int_field) is None:
                    continue
                try:
                    content_dict[int_field] = int(c[int_field])
                except Exception:
                    if int_field in ("offset", "distance"):
                        content_dict[int_field] = 0
                    else:
                        content_dict[int_field] = None

            for rate_field in ("count", "seconds"):
                if c.get(rate_field) is None:
                    continue
                try:
                    content_dict[rate_field] = int(c[rate_field])
                except Exception:
                    content_dict.pop(rate_field, None)

            if "key_fields" in c and not isinstance(c.get("key_fields"), (list, tuple)):
                content_dict.pop("key_fields", None)

            norm_contents.append(content_dict)
        rr["content"] = norm_contents

        # pcre optional
        rr["pcre"] = rr.get("pcre")

        # fields to check (e.g., http_uri, http_client_body)
        rr["field"] = rr.get("field", [])

        # flow (to_server, established,...)
        rr["flow"] = rr.get("flow", [])

        #rate_filter:
        rf = rr.get("rate_filter")
        if rf:
            rr["rate_filter"] = {
                "track": rf.get("track", "src_ip"),
                "count": int(rf.get("count", None)),
                "seconds": int(rf.get("seconds", None)),
            }
        else:
            rr["rate_filter"] = None
        rules.append(rr)

    console_logger.info("Loaded %d rules", len(rules))
    return rules

def compile_rules(raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Compile raw JSON rules thành byte-level + regex + PCRE,
    chuẩn bị cho pipeline AHO/content/PCRE match.
    """
    compiled: List[Dict[str, Any]] = []

    for r in raw_rules:
        ent: Dict[str, Any] = {"rule": r}

        # ---- Compile content ----
        compiled_contents = []
        for c in r.get("content", []):
            # Chuẩn hóa dict
            if isinstance(c, str):
                content_dict = {"pattern": c, "nocase": False, "fast_pattern": False}
            else:
                content_dict = {
                    "pattern": c.get("pattern") or c.get("value") or "",
                    "nocase": bool(c.get("nocase")),
                    "fast_pattern": bool(c.get("fast_pattern", False))
                }
                for field in ("offset", "depth", "distance", "within"):
                    if c.get(field) is None:
                        continue
                    try:
                        content_dict[field] = int(c[field])
                    except Exception:
                        if field in ("offset", "distance"):
                            content_dict[field] = 0
                        else:
                            content_dict[field] = None
                if c.get("field"):
                    content_dict["field"] = c.get("field")

            # Bytes-level
            pattern_bytes = content_dict["pattern"].encode("latin1", "ignore")

            # Regex-level
            flags = re.IGNORECASE if content_dict["nocase"] else 0
            try:
                regex = re.compile(re.escape(content_dict["pattern"]), flags)
            except re.error:
                regex = None

            compiled_contents.append({
                "raw": content_dict,
                "pattern_bytes": pattern_bytes,
                "regex": regex,
                "fast_pattern": content_dict["fast_pattern"]
            })

        ent["contents"] = compiled_contents

        # ---- Compile PCRE ----
        pcre = r.get("pcre")
        if pcre:
            try:
                ent["pcre_compiled"] = re.compile(pcre, re.DOTALL | re.IGNORECASE)
            except re.error:
                ent["pcre_compiled"] = None
        else:
            ent["pcre_compiled"] = None

        compiled.append(ent)

    return compiled


# ----------------- Aho automaton (optional) -----------------
try:
    import ahocorasick  # type: ignore
    AHO_AVAILABLE = True
except ImportError:
    AHO_AVAILABLE = False

# def build_aho(compiled_rules: List[Dict[str, Any]]) -> Optional[ahocorasick.Automaton]:
#     """
#     Tạo Aho-Corasick automaton từ compiled_rules.
#     Mỗi pattern bytes trong rule sẽ được thêm vào.
#     """
#     try:
#         aho = ahocorasick.Automaton()
#         idx = 0

#         for r in compiled_rules:
#             for c in r.get("contents", []):
#                 pattern_bytes: bytes = c.get("pattern_bytes")
#                 if not pattern_bytes:
#                     continue
#                 # key = bytes → decode latin1 để dùng AhoC python (hỗ trợ byte-safe)
#                 key = pattern_bytes.decode("latin1", "ignore")
#                 # value lưu index + rule_id + message
#                 aho.add_word(key, (idx, rule_id(r["rule"]), r["rule"].get("message")))
#                 idx += 1

#         if idx > 0:
#             aho.make_automaton()
#             console_logger.info("Built Aho-Corasick automaton with %d patterns", idx)
#             return aho, None
#         else:
#             return None, None
#     except Exception as e:
#         console_logger.warning("Failed building Aho-Corasick automaton: %s", e)
#         return None, None
# def build_aho(compiled_rules: list):
#     """
#     Build a Snort-like Aho-Corasick automaton from compiled_rules.
#     Each automaton key = fast pattern string, value = list of (rule_index, content_index)
    
#     Returns:
#         aho: pyahocorasick.Automaton
#         aho_map: Dict[str, List[Tuple[int,int]]], mapping fast pattern → candidate rules
#     """
#     if not AHO_AVAILABLE:
#         console_logger.info("Aho-Corasick not available, skipping automaton build")
#         return None, {}

#     try:
#         aho = ahocorasick.Automaton()
#         aho_map = {}  # key: pattern string -> list of (rule_idx, content_idx)

#         for r_idx, ent in enumerate(compiled_rules):
#             contents = ent.get("contents", [])
#             if not contents:
#                 continue

#             # Chọn fast_pattern(s), nếu không có thì dùng content[0]
#             fp_indices = [i for i, c in enumerate(contents) if c.get("fast_pattern")]
#             if not fp_indices:
#                 fp_indices = [0]

#             for ci in fp_indices:
#                 c = contents[ci]
#                 pb: bytes = c.get("pattern_bytes") or b""
#                 if not pb:
#                     continue

#                 # Latin1 decode để map 1:1 byte -> char
#                 key = pb.decode("latin1", "ignore")

#                 # Thêm vào external map để chứa tất cả candidate
#                 if key not in aho_map:
#                     aho_map[key] = []
#                 aho_map[key].append((r_idx, ci))

#                 # Thêm vào Aho automaton
#                 # Vì pyahocorasick overwrite nếu add_word trùng, nên chỉ add 1 lần
#                 if key not in aho:
#                     aho.add_word(key, key)

#         # Finalize automaton
#         aho.make_automaton()
#         console_logger.info("AHO automaton built with patterns (compiled_rules count=%d)", len(compiled_rules))
#         return aho, aho_map

#     except Exception as e:
#         console_logger.warning("Failed building AHO automaton: %s", e)
#         return None, {}
# build_aho: build automata per-field and aho_map includes (rule_idx, content_idx, field)
def build_aho(compiled_rules: list):
    """
    Build field-specific Aho-Corasick automata from compiled_rules.
    Returns:
        aho_by_field: Dict[field_name, Automaton]
        aho_map: Dict[key_str, List[(rule_idx, content_idx, field_name)]]
    """
    if not AHO_AVAILABLE:
        console_logger.info("Aho-Corasick not available, skipping automaton build")
        return {}, {}

    aho_by_field = {}
    aho_map = {}  # key -> list of (rule_idx, content_idx, field)

    try:
        for r_idx, ent in enumerate(compiled_rules):
            contents = ent.get("contents", []) or []
            for ci, c in enumerate(contents):
                pb: bytes = c.get("pattern_bytes") or b""
                if not pb:
                    continue
                key = pb.decode("latin1", "ignore")

                # Determine fields for this content (content-level field overrides rule-level field)
                raw = c.get("raw", {}) or {}
                fields = raw.get("field")
                if fields is None:
                    # try rule-level default field
                    rule_default_fields = ent.get("rule", {}).get("field")
                    fields = rule_default_fields or ["raw"]
                if isinstance(fields, str):
                    fields = [fields]

                # add key to each field's automaton
                for f in fields:
                    if f not in aho_by_field:
                        aho_by_field[f] = ahocorasick.Automaton()
                    # add_word only once per automaton
                    try:
                        if not aho_by_field[f].exists(key):  # pyahocorasick: use try/except if needed
                            aho_by_field[f].add_word(key, key)
                    except Exception:
                        # some pyahocorasick versions don't have exists; just try/except
                        try:
                            aho_by_field[f].add_word(key, key)
                        except Exception:
                            pass

                # update global map linking key -> (rule_idx, content_idx, field)
                if key not in aho_map:
                    aho_map[key] = []
                for f in fields:
                    aho_map[key].append((r_idx, ci, f))

        # finalize automata
        for f, a in aho_by_field.items():
            try:
                a.make_automaton()
            except Exception:
                pass

        console_logger.info("Built field-specific Aho-Corasick automata (fields=%d, rules=%d)", len(aho_by_field), len(compiled_rules))
        return aho_by_field, aho_map

    except Exception as e:
        console_logger.warning("Failed building field-specific AHO automata: %s", e)
        return {}, {}

    
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

def serialize_compiled_bytes(r):
    r_copy = dict(r)
    contents = []
    for c in r_copy.get("contents", []):
        c_copy = dict(c)
        if "pattern_bytes" in c_copy:
            c_copy["pattern_bytes"] = c_copy["pattern_bytes"].hex()
        # bỏ regex object vì không serialize được
        c_copy["regex"] = None
        contents.append(c_copy)
    r_copy["contents"] = contents

    # bỏ PCRE object
    r_copy["pcre_compiled"] = None
    return r_copy

# # viết hàm main để test load_rules:
# def main():
#     rules = load_rules(RULES_FIX_PATH)
#     compiled = compile_rules(rules)
#     aho, aho_map = build_aho(compiled)
#     print(f"Loaded {len(rules)} rules, compiled {len(compiled)} rules, AHO: {aho is not None}")
#     #in ra từng cái để check:
#     for i, r in enumerate(compiled):
#         print(f"Rule {i}: {serialize_compiled_bytes(r)}")
# if __name__ == "__main__":
#     main()