# app/services/manager_rules.py
import json
import threading
import binascii
import logging
import os
import uuid
from typing import Optional, Any, List, Dict
from pydantic import BaseModel, Field

# Keep a Rule model that matches your canonical rule shape
class Rule(BaseModel):
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    group_id: str
    proto: str = "ANY"
    dst_port: Optional[int] = None
    pattern_bytes: Optional[str] = None
    pattern_regex_bytes: Optional[str] = None
    pattern_hex: Optional[str] = None
    use_aho: bool = False
    message: str = ""
    severity: str = "low"   # low, medium, high, critical
    action: str = "log"     # log, alert, block


class RulesManager:
    """
    RulesManager: read / write / normalize rules.json and keep compiled_rules.
    - Important: do NOT hold the threading.Lock while performing file I/O (fsync / os.replace)
      to avoid deadlocks or blocking the API worker threads.
    """

    def __init__(self, rules_file: str):
        self.rules_file: str = rules_file
        self.rules: List[Dict[str, Any]] = []
        self.compiled_rules: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.rules_updated_event = threading.Event()
        self._skip_next_reload = False
        # load rules from disk at startup
        self.load_rules()

    # Atomic write helper (path + data)
    def _safe_write(self, path: str, data: Any) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        # mark to skip watcher reload if filewatcher present
        self._skip_next_reload = True
        logging.debug("[RULES] _safe_write completed, set _skip_next_reload=True")

    # Normalize a list of raw rules into canonical shape (keeps your fields)
    def _normalize_rules(self, raw_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for r in raw_rules:
            rr = dict(r)  # shallow copy so we don't mutate input

            # ensure uuid exists
            rr.setdefault("uuid", str(uuid.uuid4()))

            # backward compat: map "id" -> group_id if present
            if "id" in rr and "group_id" not in rr:
                rr["group_id"] = rr.pop("id")

            # ensure string types for textual fields
            rr["group_id"] = "" if rr.get("group_id") is None else str(rr.get("group_id"))
            rr["message"] = "" if rr.get("message") is None else str(rr.get("message"))
            rr.setdefault("proto", "ANY")
            rr.setdefault("pattern_bytes", None)
            rr.setdefault("pattern_regex_bytes", None)
            rr.setdefault("pattern_hex", None)
            rr.setdefault("use_aho", False)
            rr.setdefault("severity", "low")
            rr.setdefault("action", "log")

            # normalize dst_port into int or None
            dp = rr.get("dst_port")
            if dp in (None, "", "None"):
                rr["dst_port"] = None
            else:
                try:
                    rr["dst_port"] = int(dp)
                except Exception:
                    rr["dst_port"] = None

            # normalize use_aho into boolean
            rr["use_aho"] = str(rr.get("use_aho")).lower() in ("true", "1", "yes", "on")

            # ensure pattern_regex_bytes stored as string (or None)
            pr = rr.get("pattern_regex_bytes")
            rr["pattern_regex_bytes"] = None if pr in (None, "") else str(pr)

            normalized.append(rr)
        return normalized

    # Build lightweight "compiled" matcher entries (the IDS engine may compile regexes later)
    def _build_matchers(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        compiled: List[Dict[str, Any]] = []
        for r in rules:
            entry: Dict[str, Any] = {"rule": r}
            # If pattern_hex provided, try to unhexlify to bytes
            if r.get("pattern_hex") and not r.get("pattern_bytes"):
                try:
                    entry["pattern_bytes"] = binascii.unhexlify(r["pattern_hex"])
                except Exception:
                    entry["pattern_bytes"] = None
            elif r.get("pattern_bytes"):
                val = r["pattern_bytes"]
                entry["pattern_bytes"] = val.encode() if isinstance(val, str) else (
                    val if isinstance(val, (bytes, bytearray)) else None
                )
            else:
                entry["pattern_bytes"] = None

            # keep regex string as-is for engine (engine can compile)
            entry["pattern_regex"] = r.get("pattern_regex_bytes") if r.get("pattern_regex_bytes") else None

            compiled.append(entry)
        return compiled

    # Load rules from disk and normalize
    def load_rules(self) -> None:
        try:
            if not os.path.exists(self.rules_file):
                with self.lock:
                    self.rules = []
                    self.compiled_rules = []
                return

            with open(self.rules_file, "r", encoding="utf-8") as f:
                raw = json.load(f)

            normalized = self._normalize_rules(raw)
            with self.lock:
                self.rules = normalized
                self.compiled_rules = self._build_matchers(self.rules)
            # notify if other threads wait for update
            self.rules_updated_event.set()
            logging.info(f"[RULES] Loaded {len(self.rules)} rules from {self.rules_file}")
        except Exception as e:
            logging.exception("[RULES] Failed to load rules: %s", e)

    # Save rules to disk: copy under lock, write outside lock to avoid deadlock/blocking
    def save_rules(self) -> None:
        with self.lock:
            data_copy = [dict(r) for r in self.rules]
        # perform I/O outside lock
        self._safe_write(self.rules_file, data_copy)
        # notify
        self.rules_updated_event.set()

    # Add or update a rule (atomic from caller perspective)
    def add_or_update(self, rule_payload: Dict[str, Any]) -> Dict[str, Any]:
        logging.debug("[RULES] add_or_update start uuid=%s", rule_payload.get("uuid"))
        canonical = dict(rule_payload)
        # Ensure uuid exists
        if not canonical.get("uuid"):
            canonical["uuid"] = str(uuid.uuid4())

        # normalize the incoming payload
        canonical = self._normalize_rules([canonical])[0]

        updated = False
        with self.lock:
            for idx, r in enumerate(self.rules):
                if r.get("uuid") == canonical["uuid"]:
                    # update existing
                    self.rules[idx].update(canonical)
                    updated = True
                    break
            if not updated:
                # append new
                self.rules.append(canonical)
            # update compiled_rules in memory
            self.compiled_rules = self._build_matchers(self.rules)

        # persist to disk OUTSIDE lock to avoid blocking other threads
        self.save_rules()
        logging.debug("[RULES] add_or_update end uuid=%s (updated=%s)", canonical["uuid"], updated)
        return canonical

    # Delete by uuid
    def delete_by_uuid(self, uuid_val: str) -> bool:
        removed = False
        with self.lock:
            new_rules = [r for r in self.rules if r.get("uuid") != uuid_val]
            removed = len(new_rules) != len(self.rules)
            if removed:
                self.rules = new_rules
                self.compiled_rules = self._build_matchers(self.rules)
        if removed:
            self.save_rules()
            logging.info("[RULES] Deleted rule: %s", uuid_val)
            return True
        logging.debug("[RULES] UUID not found for delete: %s", uuid_val)
        return False

    # Return a copy of rules (thread-safe)
    def get_rules(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.rules]
