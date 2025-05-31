# src/detector/rules.py
from collections import deque, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import ipaddress

FAILED_LIMIT = 5
FAILED_WINDOW = timedelta(seconds=60)

CMD_LIMIT = 3          # dangerous cmd toggle burst
CMD_WINDOW = timedelta(seconds=30)

POWER_WINDOW = timedelta(minutes=5)
POWER_OUTLIER = 1.5    # 150 % of rolling mean
MIN_SAMPLES      = 5           # need at least this many points

SYN_RATE = 100         # packets/s threshold
RESOURCE_HIGH = 0.80   # 80 % for ≥ window
RESOURCE_WINDOW = timedelta(seconds=90)

MQTT_LIMIT = 10_000
MQTT_WINDOW = timedelta(seconds=100)

@dataclass
class Verdict:
    suspicious: bool
    rule_hit: str | None
    detail: dict

class AttackRules:
    """Rule engine – *never touches shared state directly*.
    It receives the three live lookup tables via __init__.”
    """
    def __init__(self,
                    verified_users,
                    known_devices,
                    exploitable_commands,
                    suspicious_flag):
        self.verified_users = verified_users
        self.known_devices = known_devices
        self.exploitable_commands = exploitable_commands
        self.suspicious_flag = suspicious_flag

        # sliding-window state (per user / device)
        self.failed = defaultdict(deque)
        self.cmd_burst = defaultdict(deque)
        self.power = defaultdict(list)
        self.syn_rate = defaultdict(int)
        self.resources = defaultdict(deque)
        self.mqtt = deque()

    # helper ------------------------------------------------------------
    @staticmethod
    def _slide(dq, now, window):
        while dq and now - dq[0] > window:
            dq.popleft()

    def evaluate(self, ev):
        e = ev  # alias
        ts = e.timestamp

        # 0. LAN-only guard ------------------------------------------------
        try:
            if not ipaddress.ip_address(e.source_id).is_private:
                self.suspicious_flag.set()     # global flag
                return Verdict(True, "NON_LAN_DEVICE",
                                {"ip": e.source_id})
        except ValueError:      # malformed IP
            self.suspicious_flag.set()
            return Verdict(True, "BAD_IP_FORMAT",
                            {"ip": e.source_id})

        # 1. unknown device / unknown user – only log ---------------------
        if e.source_id not in self.known_devices:
            return Verdict(False, "UNKNOWN_DEVICE", {"ip": e.source_id})
        if (uid_level := self.verified_users.get(e.user_id)) is None:
            return Verdict(False, "UNKNOWN_USER", {"user": e.user_id})
        if e.user_role not in ("ADMIN", "MANAGER", "USER"):
            return Verdict(False, "ROLE_UNKNOWN", {"role": e.user_role})
        if e.user_role == "USER" and uid_level != "USER":
            return Verdict(False, "PRIV_ESC_ATTEMPT",
                            {"user": e.user_id, "role": e.user_role})

        # 2. brute-force login -------------------------------------------
        if e.event_name == "login_attempt" and not e.context.get("success"):
            dq = self.failed[e.user_id]
            dq.append(ts); self._slide(dq, ts, FAILED_WINDOW)
            if len(dq) > FAILED_LIMIT:
                self.suspicious_flag.set()
                return Verdict(True, "FAILED_LOGIN_BURST",
                                {"user": e.user_id})

        # 3. dangerous command spam --------------------------------------
        if (e.event_name == "control_command"
                and e.context.get("command") in self.exploitable_commands):
            dq = self.cmd_burst[e.user_id]
            dq.append(ts); self._slide(dq, ts, CMD_WINDOW)
            if (len(dq) > CMD_LIMIT
                    and e.user_role != "ADMIN"):
                self.suspicious_flag.set()
                return Verdict(True, "DANGEROUS_CMD_SPAM",
                                {"cmd": e.context["command"],
                                "count": len(dq)})
        # 4. power anomaly -----------------------------------------------
        if e.event_name == "power_consumption":
            pct = float(e.context["percent"])
            if not 0 <= pct <= 100:        # basic sanity
                return Verdict(False, "POWER_VALUE_OUT_OF_RANGE",
                            {"value": pct})

            dq = self.power.setdefault(e.source_id, deque())
            
            # drop anything outside the 5-min sliding window BEFORE adding new reading
            while dq and ts - dq[0][1] > POWER_WINDOW:
                dq.popleft()

            # need enough historical samples to compute a stable mean
            if len(dq) < MIN_SAMPLES:
                dq.append((pct, ts))  # add current reading
                return Verdict(False, None, {})
            
            # Calculate mean from existing readings (excluding current)
            mean_val = sum(v for v, _ in dq) / len(dq)

            # Check if current reading is a spike
            if pct > POWER_OUTLIER * mean_val:
                self.suspicious_flag.set()
                result = Verdict(True, "POWER_SPIKE",
                            {"device": self.known_devices.get(e.source_id, "UNK"),
                                "value": pct,
                                "mean": round(mean_val, 2),
                                "window_points": len(dq)})
                # Add current reading after detection
                dq.append((pct, ts))
                return result
            
            # Add current reading if no spike detected
            dq.append((pct, ts))

        # 5. SYN flood ----------------------------------------------------
        if e.event_name == "packet_syn":
            rate = e.context["rate"]
            if rate > SYN_RATE:
                self.suspicious_flag.set()
                user_field = ("multiple" if e.context.get("multi_user")
                                else e.user_id)
                return Verdict(True, "SYN_FLOOD",
                                {"user": user_field, "rate": rate})

        # 6. system resource misuse --------------------------------------
        if e.event_name == "system_resource_usage":
            dq = self.resources[e.source_id]
            dq.append((e.context["usage"], ts))
            
            # Remove old entries outside the window
            while dq and ts - dq[0][1] > RESOURCE_WINDOW:
                dq.popleft()
                
            if (len(dq) >= RESOURCE_WINDOW.seconds     # ~1 per second?
                    and all(v >= RESOURCE_HIGH for v, _ in dq)):
                self.suspicious_flag.set()
                return Verdict(True, "RESOURCE_HOG",
                                {"device": self.known_devices[e.source_id]})

        # 7. MQTT message flood ------------------------------------------
        if e.event_name == "10000_messages_received":
            self.mqtt.append(ts); self._slide(self.mqtt, ts, MQTT_WINDOW)
            if len(self.mqtt) >= 1:            # each event already == 10 000 msgs
                self.suspicious_flag.set()
                return Verdict(True, "MQTT_FLOOD", {})

        # 8. legitimate burst? → let it pass -----------------------------
        return Verdict(False, None, {})
