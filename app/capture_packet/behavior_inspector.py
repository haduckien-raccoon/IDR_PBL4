# import time
# import threading
# from collections import defaultdict, deque


# class BehaviorInspector:
#     """
#     Stateful Behavior Detector – Snort style
#     - DDOS detection (HTTP + RAW flood)
#     - Flow rate anomaly
#     - Brute-force login (content‑based)
#     """

#     def __init__(self, debug: bool = False):
#         # Sliding windows per IP
#         self.ddos_window = defaultdict(deque)    # HTTP + RAW flood (gộp)
#         self.flow_window = defaultdict(deque)    # Flow-rate (30s)
#         self.login_fail = defaultdict(deque)     # Login brute-force (20s)

#         # Last alert timestamp per IP + rule
#         self.last_alert = {}

#         # Thread safety
#         self.lock = threading.Lock()

#         # IDS thresholds
#         self.cfg = {
#             "ddos": {"interval": 10, "threshold": 200},   # events /10s
#             "flow_rate": {"interval": 30, "threshold": 300},  # events /30s
#             "login_fail": {"interval": 20, "threshold": 8},    # failed login /20s
#         }

#         # Cooldowns (seconds)
#         self.cooldowns = {
#             "DDOS": 15,
#             "FLOW_RATE": 20,
#             "BRUTEFORCE": 30,
#         }

#         self.debug = debug

#     # ---------------------------
#     def _clean_window(self, q: deque, now: float, interval: int) -> int:
#         """Remove timestamps older than interval and return count"""
#         while q and now - q[0] > interval:
#             q.popleft()
#         return len(q)

#     # ---------------------------
#     def _should_alert(self, key: tuple) -> bool:
#         """Check cooldown per IP + rule"""
#         now = time.time()
#         last = self.last_alert.get(key, 0)
#         cooldown = self.cooldowns.get(key[1], 10)
#         if now - last < cooldown:
#             return False
#         self.last_alert[key] = now
#         return True

#     # ---------------------------
#     def process(
#         self,
#         meta: dict,
#         http_uri: str | None = None,
#         status_code: int | None = None,
#         method: str | None = None,
#         response_body: bytes | None = None,
#         raw_packet: bool = False
#     ):
#         now = time.time()
#         src = meta.get("src", "0.0.0.0")
#         events = []

#         with self.lock:
#             # ---------------------------
#             # 1) DDOS detection (HTTP + RAW)
#             # ---------------------------
#             q_ddos = self.ddos_window[src]
#             interval_ddos = self.cfg["ddos"]["interval"]
#             threshold_ddos = self.cfg["ddos"]["threshold"]

#             # Clean old events
#             count_ddos = self._clean_window(q_ddos, now, interval_ddos)

#             # Append HTTP event
#             if http_uri or (meta.get("dst_port") == 80):
#                 q_ddos.append(now)
#                 count_ddos += 1

#             # Append RAW event
#             if raw_packet:
#                 q_ddos.append(now)
#                 count_ddos += 1

#             # Debug
#             if self.debug:
#                 print(
#                     f"[DEBUG][DDOS] src={src} "
#                     f"count={count_ddos} "
#                     f"proto={meta.get('proto')} "
#                     f"dport={meta.get('dst_port')}"
#                 )

#             # Check DDOS alert
#             if count_ddos >= threshold_ddos:
#                 key = (src, "DDOS")
#                 if self._should_alert(key):
#                     events.append({
#                         "rid": "DDOS",
#                         "severity": "high",
#                         "action": "block",
#                         "type": "dos",
#                         "message": f"DDOS detected from {src} ({count_ddos} events in {interval_ddos}s)",
#                     })

#             # ---------------------------
#             # 2) Flow-rate anomaly (30s window)
#             # ---------------------------
#             q_flow = self.flow_window[src]
#             interval_flow = self.cfg["flow_rate"]["interval"]
#             count_flow = self._clean_window(q_flow, now, interval_flow)
#             q_flow.append(now)
#             count_flow += 1

#             if self.debug:
#                 print(f"[DEBUG] {src} FLOW count={count_flow}")

#             if count_flow >= self.cfg["flow_rate"]["threshold"]:
#                 key = (src, "FLOW_RATE")
#                 if self._should_alert(key):
#                     events.append({
#                         "rid": "FLOW-RATE-ANOMALY",
#                         "severity": "high",
#                         "action": "block",
#                         "type": "dos",
#                         "message": f"Abnormal flow from {src} ({count_flow} req/{interval_flow}s)"
#                     })

#             # ---------------------------
#             # 3) Brute-force login detection
#             # ---------------------------
#             login_fail_detected = False
#             if method == "POST" and response_body:
#                 body = response_body.lower()
#                 if (b"<form" in body and b"dang nhap" in body) or b"/project_course/login" in body:
#                     login_fail_detected = True

#             if login_fail_detected:
#                 qf = self.login_fail[src]
#                 interval_login = self.cfg["login_fail"]["interval"]
#                 fail_count = self._clean_window(qf, now, interval_login)
#                 qf.append(now)
#                 fail_count += 1

#                 if self.debug:
#                     print(f"[DEBUG] {src} LOGIN_FAIL count={fail_count}")

#                 if fail_count >= self.cfg["login_fail"]["threshold"]:
#                     key = (src, "BRUTEFORCE")
#                     if self._should_alert(key):
#                         events.append({
#                             "rid": "BRUTE-FORCE",
#                             "severity": "high",
#                             "action": "alert",
#                             "type": "auth",
#                             "message": f"Bruteforce login attempts detected from {src} ({fail_count} fails/{interval_login}s)",
#                         })

#         return events

import time
import threading
from collections import defaultdict, deque


class BehaviorInspector:
    """
    Stateful Behavior Detector
    - DDOS flood (ALL packets: HTTP + RAW + SYN)
    - Flow-rate anomaly
    - Brute-force login (HTTP only)
    """

    def __init__(self, debug: bool = False):
        # Sliding windows
        self.ddos_window = defaultdict(deque)     # ALL packets
        self.flow_window = defaultdict(deque)     # ALL packets
        self.login_fail = defaultdict(deque)      # HTTP only

        self.last_alert = {}
        self.lock = threading.Lock()

        self.cfg = {
            "ddos": {"interval": 10, "threshold": 100},
            "flow_rate": {"interval": 30, "threshold": 300},
            "login_fail": {"interval": 20, "threshold": 8},
        }

        self.cooldowns = {
            "DDOS": 15,
            "FLOW_RATE": 20,
            "BRUTEFORCE": 30,
        }

        self.debug = debug

    # ---------------------------
    def _clean_window(self, q: deque, now: float, interval: int) -> int:
        while q and now - q[0] > interval:
            q.popleft()
        return len(q)

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

        proto = meta.get("proto")
        dport = meta.get("dst_port")

        # HTTP chỉ khi parse được URI
        is_http = bool(http_uri)
        is_raw = not is_http

        with self.lock:
            # =====================================================
            # 1) DDOS DETECTION (🔥 ALL PACKETS 🔥)
            # =====================================================
            q_ddos = self.ddos_window[src]
            interval = self.cfg["ddos"]["interval"]
            threshold = self.cfg["ddos"]["threshold"]

            count_ddos = self._clean_window(q_ddos, now, interval)

            # 🔥 MỖI PACKET = 1 EVENT
            q_ddos.append(now)
            count_ddos += 1

            if self.debug:
                print(
                    f"[DEBUG][DDOS] src={src} "
                    f"count={count_ddos} "
                    f"is_http={is_http} "
                    f"is_raw={is_raw} "
                    f"proto={proto} "
                    f"dport={dport}"
                )

            if count_ddos >= threshold:
                key = (src, "DDOS")
                if self._should_alert(key):
                    events.append({
                        "rid": "DDOS",
                        "severity": "high",
                        "action": "block",
                        "type": "dos",
                        "message": f"DDOS detected from {src} ({count_ddos}/{interval}s)",
                    })

            # =====================================================
            # 2) FLOW RATE (ALL PACKETS)
            # =====================================================
            q_flow = self.flow_window[src]
            interval_flow = self.cfg["flow_rate"]["interval"]

            count_flow = self._clean_window(q_flow, now, interval_flow)
            q_flow.append(now)
            count_flow += 1

            if self.debug:
                print(f"[DEBUG][FLOW] src={src} count={count_flow}")

            if count_flow >= self.cfg["flow_rate"]["threshold"]:
                key = (src, "FLOW_RATE")
                if self._should_alert(key):
                    events.append({
                        "rid": "FLOW-RATE-ANOMALY",
                        "severity": "high",
                        "action": "block",
                        "type": "dos",
                        "message": f"Abnormal flow from {src} ({count_flow}/{interval_flow}s)",
                    })

            # =====================================================
            # 3) BRUTE FORCE LOGIN (HTTP ONLY)
            # =====================================================
            if is_http and method == "POST" and response_body:
                body = response_body.lower()
                if b"login" in body or b"dang nhap" in body:
                    qf = self.login_fail[src]
                    interval_login = self.cfg["login_fail"]["interval"]

                    fail_count = self._clean_window(qf, now, interval_login)
                    qf.append(now)
                    fail_count += 1

                    if self.debug:
                        print(f"[DEBUG][LOGIN] src={src} fails={fail_count}")

                    if fail_count >= self.cfg["login_fail"]["threshold"]:
                        key = (src, "BRUTEFORCE")
                        if self._should_alert(key):
                            events.append({
                                "rid": "BRUTE-FORCE",
                                "severity": "high",
                                "action": "alert",
                                "type": "auth",
                                "message": f"Bruteforce login detected from {src}",
                            })

        return events
