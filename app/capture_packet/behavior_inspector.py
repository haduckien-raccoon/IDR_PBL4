# behavior_inspector_snortstyle_fixed.py
import time
import threading
from collections import defaultdict, deque


class BehaviorInspector:
    """
    Stateful Behavior Detector – Snort style
    - HTTP flood / flow rate
    - Brute-force login
    - Anti-spam alert per IP + rule
    """

    def __init__(self):
        # Sliding windows per IP
        self.http_10s = defaultdict(deque)     # HTTP flood (10s)
        self.http_30s = defaultdict(deque)     # Flow rate (30s)
        self.login_fail = defaultdict(deque)   # Login brute-force (20s)

        # Last alert timestamp per IP + rule
        self.last_alert = {}

        # Thread safety
        self.lock = threading.Lock()

        # IDS thresholds: tăng một chút để giảm false-positive
        self.cfg = {
            "http_flood": {"interval": 10, "threshold": 100},   # requests /10s
            "flow_rate":  {"interval": 30, "threshold": 300},   # requests /30s
            "login_fail": {"interval": 20, "threshold": 8},     # failed login /20s
        }

        # Cooldown để tránh spam alert
        self.cooldowns = {
            "HTTP_FLOOD": 15,
            "FLOW_RATE": 20,
            "BRUTEFORCE": 30,
        }

    # ---------------------------
    # Clean old timestamps
    # ---------------------------
    def _clean_window(self, q: deque, now: float, interval: int) -> int:
        while q and now - q[0] > interval:
            q.popleft()
        return len(q)

    # ---------------------------
    # Check cooldown to prevent spam
    # ---------------------------
    def _should_alert(self, key: tuple) -> bool:
        now = time.time()
        last = self.last_alert.get(key, 0)
        cooldown = self.cooldowns.get(key[1], 10)
        if now - last < cooldown:
            return False
        self.last_alert[key] = now
        return True

    # ---------------------------
    # Main process function
    # ---------------------------
    def process(self, meta: dict, http_uri: str | None = None, status_code: int | None = None):
        now = time.time()
        src = meta.get("src", "0.0.0.0")
        events = []

        with self.lock:
            # ---------------------------
            # 1) HTTP flood (10s) & flow (30s)
            # ---------------------------
            if http_uri:
                q10 = self.http_10s[src]
                q30 = self.http_30s[src]

                # Clean old timestamps first
                count10 = self._clean_window(q10, now, self.cfg["http_flood"]["interval"])
                count30 = self._clean_window(q30, now, self.cfg["flow_rate"]["interval"])

                # Append current request
                q10.append(now)
                q30.append(now)
                count10 += 1
                count30 += 1

                # Trigger alert if >= threshold
                if count10 >= self.cfg["http_flood"]["threshold"]:
                    key = (src, "HTTP_FLOOD")
                    if self._should_alert(key):
                        events.append({
                            "rid": "HTTP-FLOOD",
                            "severity": "high",
                            "action": "alert",
                            "type": "dos",
                            "message": f"HTTP flood detected from {src} ({count10} req/{self.cfg['http_flood']['interval']}s)",
                            "window": f"{self.cfg['http_flood']['interval']}s",
                        })

                if count30 >= self.cfg["flow_rate"]["threshold"]:
                    key = (src, "FLOW_RATE")
                    if self._should_alert(key):
                        events.append({
                            "rid": "FLOW-RATE-ANOMALY",
                            "severity": "medium",
                            "action": "alert",
                            "type": "dos",
                            "message": f"Abnormal request rate from {src} ({count30} req/{self.cfg['flow_rate']['interval']}s)",
                            "window": f"{self.cfg['flow_rate']['interval']}s",
                        })

            # ---------------------------
            # 2) Brute-force login
            # ---------------------------
            if http_uri and http_uri.startswith("/login") and status_code in (401, 403):
                qf = self.login_fail[src]

                # Clean old timestamps first
                fail_count = self._clean_window(qf, now, self.cfg["login_fail"]["interval"])

                # Append current failure
                qf.append(now)
                fail_count += 1

                if fail_count >= self.cfg["login_fail"]["threshold"]:
                    key = (src, "BRUTEFORCE")
                    if self._should_alert(key):
                        events.append({
                            "rid": "BRUTE-FORCE",
                            "severity": "medium",
                            "action": "alert",
                            "type": "auth",
                            "message": f"Bruteforce detected from {src} ({fail_count} failures/{self.cfg['login_fail']['interval']}s)",
                        })

        return events
