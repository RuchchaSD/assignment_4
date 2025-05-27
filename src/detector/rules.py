# src/detector/rules.py
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from geopy.distance import geodesic # not required for this project
import scapy.all as sc # not required for this project

FAILED_LIMIT = 5
FAILED_WINDOW = timedelta(seconds=60)
TOGGLE_LIMIT = 10
TOGGLE_WINDOW = timedelta(seconds=30)

@dataclass
class Verdict:
    suspicious: bool
    rule_hit: str | None
    detail: dict

class AttackRules:
    def __init__(self):
        self._failed_logins = {}   # user ➜ deque[timestamps]
        self._device_toggles = {}  # user ➜ deque[timestamps]
        self._last_ip = {}         # user ➜ (lat, lon, ts)

    def _slide(self, dq: deque, now: datetime, window: timedelta):
        while dq and now - dq[0] > window:
            dq.popleft()

    def evaluate(self, ev, role, user, src, ts, ctx):
        # 1. brute-force login
        if ev == "login_attempt" and not ctx["success"]:
            dq = self._failed_logins.setdefault(user, deque())
            dq.append(ts); self._slide(dq, ts, FAILED_WINDOW)
            if len(dq) > FAILED_LIMIT:     # sliding-window rate limit
                return Verdict(True, "FAILED_LOGIN_BURST", {"user": user})

        # 2. toggle spam
        if ev == "toggle_device":
            dq = self._device_toggles.setdefault(user, deque())
            dq.append(ts); self._slide(dq, ts, TOGGLE_WINDOW)
            if len(dq) > TOGGLE_LIMIT and role != "ADMIN":
                return Verdict(True, "TOGGLE_SPAM", {"device": ctx["device"]})

        # 3. geo-fence impossible travel
        if "ip_coord" in ctx:      # ctx["ip_coord"] = (lat, lon)
            last = self._last_ip.get(user)
            self._last_ip[user] = (*ctx["ip_coord"], ts)
            if last:
                dist_km = geodesic(last[:2], ctx["ip_coord"]).km
                dt = (ts - last[2]).total_seconds() / 60
                if dist_km > 300 and dt < 5:
                    return Verdict(True, "GEO_IMPOSSIBLE", {"km": dist_km})

        # 4. packet storm via Scapy sniff callback (external)
        if ev == "packet_syn":
            if ctx["rate"] > 100:
                return Verdict(True, "SYN_FLOOD", {"rate": ctx["rate"]})

        # 5. camera motion outside schedule
        if ev == "camera_motion" and role != "ADMIN":
            if ctx["time"] not in range(8, 20):  # after-hours
                return Verdict(True, "MOTION_AFTER_HOURS", {})

        return Verdict(False, None, {})
