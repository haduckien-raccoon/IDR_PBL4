# behavior_inspector_snortstyle_fixed.py
import time
import threading
from collections import defaultdict, deque


class BehaviorInspector:
    """
    Stateful Behavior Detector – Snort style
    - HTTP flood / flow rate
    - Brute-force login (content‑based)
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

        # IDS thresholds
        self.cfg = {
            "http_flood": {"interval": 10, "threshold": 100},   # requests /10s
            "flow_rate":  {"interval": 30, "threshold": 300},   # requests /30s
            "login_fail": {"interval": 20, "threshold": 8},     # failed login /20s
        }

        # Cooldowns
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
    def process(
        self,
        meta: dict,
        http_uri: str | None = None,
        status_code: int | None = None,
        method: str | None = None,
        response_body: bytes | None = None,
    ):
        now = time.time()
        src = meta.get("src", "0.0.0.0")
        events = []

        with self.lock:

            # ---------------------------
            # 1) HTTP flood / flow rate
            # ---------------------------
            if http_uri:
                q10 = self.http_10s[src]
                q30 = self.http_30s[src]

                count10 = self._clean_window(q10, now, self.cfg["http_flood"]["interval"])
                count30 = self._clean_window(q30, now, self.cfg["flow_rate"]["interval"])

                q10.append(now)
                q30.append(now)
                count10 += 1
                count30 += 1

                # HTTP Flood
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

                # Flow-rate anomaly
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
            # 2) Brute-force login detection (content‑based)
            # ---------------------------
            # - Website của bạn trả 200 OK cả khi sai mật khẩu
            # - Login fail được xác định bằng CONTENT trong response
            # ---------------------------

            login_fail_detected = False

            if (
                method == "POST"
                and http_uri
                and ("/login" in http_uri.lower())
                and response_body
            ):
                body = response_body.lower()

                # Pattern đặc trưng khi login thất bại
                if (
                    b"<form" in body
                    and b"dang nhap" in body  # Tiếng Việt unicode đã bị chuyển UTF-8 → bytes
                ):
                    login_fail_detected = True

                # Dự phòng trường hợp HTML khác nhau
                if b"/project_course/login" in body:
                    login_fail_detected = True

            if login_fail_detected:
                qf = self.login_fail[src]
                fail_count = self._clean_window(qf, now, self.cfg["login_fail"]["interval"])
                qf.append(now)
                fail_count += 1

                if fail_count >= self.cfg["login_fail"]["threshold"]:
                    key = (src, "BRUTEFORCE")
                    if self._should_alert(key):
                        events.append({
                            "rid": "BRUTE-FORCE",
                            "severity": "high",
                            "action": "alert",
                            "type": "auth",
                            "message": f"Bruteforce login attempts detected from {src} ({fail_count} fails/{self.cfg['login_fail']['interval']}s)",
                        })

        return events
