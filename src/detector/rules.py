# src/detector/rules.py
"""
Attack detection rules engine for smart home security systems.

This module contains the core logic for detecting various types of cyber attacks
including brute force attempts, command injection, resource abuse, and network attacks.
"""

# src/detector/rules.py
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Set


class DetectionConfig:
    """Configuration constants for attack detection rules."""
    
    # Failed login detection
    FAILED_LOGIN_LIMIT = 5
    FAILED_LOGIN_WINDOW = timedelta(seconds=60)
    
    # Command spam detection  
    COMMAND_SPAM_LIMIT = 3
    COMMAND_SPAM_WINDOW = timedelta(seconds=30)
    
    # Power consumption anomaly detection
    POWER_ANALYSIS_WINDOW = timedelta(minutes=5)
    POWER_SPIKE_THRESHOLD = 1.5  # 150% of rolling mean
    POWER_MIN_SAMPLES = 5        # Minimum readings for stable mean
    
    # Network attack detection
    SYN_FLOOD_RATE = 100         # packets/second threshold
    
    # Resource abuse detection
    RESOURCE_HIGH_USAGE = 0.80   # 80% usage threshold
    RESOURCE_WINDOW = timedelta(seconds=90)
    
    # MQTT flood detection
    MQTT_FLOOD_LIMIT = 20_000  # 2 events × 10,000 messages each
    MQTT_FLOOD_WINDOW = timedelta(seconds=100)

@dataclass
class Verdict:
    """
    Result of evaluating an event against security rules.
    
    Attributes:
        suspicious: Whether the event indicates a potential attack
        rule_hit: Name of the triggered rule (None if no rule matched)
        detail: Additional context about the detection
    """
    suspicious: bool
    rule_hit: Optional[str]
    detail: Dict[str, Any]

class AttackRules:
    """
    Core security rules engine for detecting various attack patterns.
    
    This class implements detection logic for multiple attack types:
    - Brute force login attempts
    - Command injection and spam
    - Power consumption anomalies  
    - Network-based attacks (SYN floods)
    - Resource exhaustion attacks
    - MQTT message flooding
    - Geographic and device validation
    
    The engine maintains sliding window state for time-based analysis
    and supports per-device thread isolation.
    
    Example:
        >>> rules = AttackRules(users, devices, commands, flag)
        >>> verdict = rules.evaluate(event)
        >>> if verdict.suspicious:
        ...     print(f"Attack detected: {verdict.rule_hit}")
    """
    
    def __init__(self, 
                 verified_users: Dict[str, str],
                 known_devices: Dict[str, str], 
                 exploitable_commands: Set[str],
                 suspicious_flag) -> None:
        """
        Initialize the rules engine with configuration data.
        
        Args:
            verified_users: Mapping of user_id -> max_privilege_level
            known_devices: Mapping of device_ip -> device_type  
            exploitable_commands: Set of dangerous commands to monitor
            suspicious_flag: Threading event to signal suspicious activity
        """
        # Configuration data (read-only references)
        self.verified_users = verified_users
        self.known_devices = known_devices
        self.exploitable_commands = exploitable_commands
        self.suspicious_flag = suspicious_flag
        
        # Per-device sliding window state
        self.failed_logins = defaultdict(deque)
        self.command_bursts = defaultdict(deque) 
        self.power_readings = defaultdict(deque)
        self.resource_usage = defaultdict(deque)
        self.mqtt_events = deque()
    
    @staticmethod
    def _clean_sliding_window(window: deque, current_time: datetime, 
                             max_age: timedelta) -> None:
        """Remove expired entries from a sliding time window."""
        while window:
            # Check if the window contains timestamps or tuples
            first_item = window[0]
            if isinstance(first_item, tuple):
                # For tuples like (value, timestamp), compare with timestamp
                if current_time - first_item[1] > max_age:
                    window.popleft()
                else:
                    break
            else:
                # For raw timestamps
                if current_time - first_item > max_age:
                    window.popleft()
                else:
                    break
    
    def _validate_network_access(self, source_ip: str) -> Optional[Verdict]:
        """Validate that events come from legitimate network sources."""
        try:
            ip_addr = ipaddress.ip_address(source_ip)
            if not ip_addr.is_private:
                self.suspicious_flag.set()
                return Verdict(True, "NON_LAN_ACCESS", {"ip": source_ip})
        except ValueError:
            self.suspicious_flag.set() 
            return Verdict(True, "INVALID_IP_FORMAT", {"ip": source_ip})
        return None
    
    def _validate_user_and_device(self, event) -> Optional[Verdict]:
        """Validate user credentials and device registration."""
        # Unknown device (log but don't alert)
        if event.source_id not in self.known_devices:
            return Verdict(False, "UNKNOWN_DEVICE", {"ip": event.source_id})
            
        # Unknown user (log but don't alert) 
        user_privilege = self.verified_users.get(event.user_id)
        if user_privilege is None:
            return Verdict(False, "UNKNOWN_USER", {"user": event.user_id})
            
        # Invalid role
        if event.user_role not in ("ADMIN", "MANAGER", "USER"):
            return Verdict(False, "INVALID_ROLE", {"role": event.user_role})
            
        # Privilege escalation attempt
        if event.user_role == "USER" and user_privilege != "USER":
            return Verdict(False, "PRIVILEGE_ESCALATION", {
                "user": event.user_id, 
                "claimed_role": event.user_role
            })
        return None
    
    def _detect_brute_force(self, event) -> Optional[Verdict]:
        """Detect brute force login attacks."""
        if (event.event_name == "login_attempt" and 
            not event.context.get("success", True)):
            
            window = self.failed_logins[event.user_id]
            window.append(event.timestamp)
            self._clean_sliding_window(window, event.timestamp, 
                                     DetectionConfig.FAILED_LOGIN_WINDOW)
            
            if len(window) > DetectionConfig.FAILED_LOGIN_LIMIT:
                self.suspicious_flag.set()
                return Verdict(True, "BRUTE_FORCE_LOGIN", {
                    "user": event.user_id,
                    "attempts": len(window)
                })
        return None
    
    def _detect_command_injection(self, event) -> Optional[Verdict]:
        """Detect command injection and spam attacks."""
        if (event.event_name == "control_command" and
            event.context.get("command") in self.exploitable_commands):
            
            window = self.command_bursts[event.user_id]
            window.append(event.timestamp)
            self._clean_sliding_window(window, event.timestamp,
                                     DetectionConfig.COMMAND_SPAM_WINDOW)
            
            # Admin users exempt from command rate limiting
            if (len(window) > DetectionConfig.COMMAND_SPAM_LIMIT and 
                event.user_role != "ADMIN"):
                self.suspicious_flag.set()
                return Verdict(True, "COMMAND_INJECTION", {
                    "command": event.context["command"],
                    "user": event.user_id,
                    "count": len(window)
                })
        return None
    
    def _detect_power_anomaly(self, event) -> Optional[Verdict]:
        """Detect power consumption anomalies and spikes."""
        if event.event_name != "power_consumption":
            return None
            
        try:
            power_pct = float(event.context["percent"])
        except (KeyError, ValueError, TypeError):
            return Verdict(False, "INVALID_POWER_DATA", {
                "data": event.context.get("percent")
            })
            
        # Validate power reading range
        if not 0 <= power_pct <= 100:
            return Verdict(False, "POWER_OUT_OF_RANGE", {"value": power_pct})
        
        readings = self.power_readings[event.source_id]
        
        # Clean old readings
        self._clean_sliding_window(readings, event.timestamp,
                                 DetectionConfig.POWER_ANALYSIS_WINDOW)
        
        # Need sufficient historical data for anomaly detection
        if len(readings) < DetectionConfig.POWER_MIN_SAMPLES:
            readings.append((power_pct, event.timestamp))
            return None
            
        # Calculate baseline from historical readings
        historical_values = [value for value, _ in readings]
        baseline_mean = sum(historical_values) / len(historical_values)
        
        # Check for spike
        if power_pct > DetectionConfig.POWER_SPIKE_THRESHOLD * baseline_mean:
            self.suspicious_flag.set()
            verdict = Verdict(True, "POWER_ANOMALY", {
                "device": self.known_devices.get(event.source_id, "unknown"),
                "current_value": power_pct,
                "baseline_mean": round(baseline_mean, 2),
                "spike_ratio": round(power_pct / baseline_mean, 2),
                "samples": len(readings)
            })
            readings.append((power_pct, event.timestamp))
            return verdict
            
        # Normal reading - add to history
        readings.append((power_pct, event.timestamp))
        return None
    
    def _detect_network_attack(self, event) -> Optional[Verdict]:
        """Detect network-based attacks like SYN floods."""
        if event.event_name == "packet_syn":
            rate = event.context.get("rate", 0)
            if rate > DetectionConfig.SYN_FLOOD_RATE:
                self.suspicious_flag.set()
                return Verdict(True, "SYN_FLOOD", {
                    "user": ("multiple" if event.context.get("multi_user") 
                           else event.user_id),
                    "rate": rate,
                    "source": event.source_id
                })
        return None
    
    def _detect_resource_abuse(self, event) -> Optional[Verdict]:
        """Detect system resource exhaustion attacks."""
        if event.event_name == "system_resource_usage":
            try:
                usage = float(event.context["usage"])
            except (KeyError, ValueError, TypeError):
                return None
                
            window = self.resource_usage[event.source_id]
            window.append((usage, event.timestamp))
            
            # Clean old entries
            self._clean_sliding_window(window, event.timestamp,
                                     DetectionConfig.RESOURCE_WINDOW)
            
            # Check for sustained high usage
            if (len(window) >= DetectionConfig.RESOURCE_WINDOW.seconds and
                all(usage >= DetectionConfig.RESOURCE_HIGH_USAGE 
                    for usage, _ in window)):
                self.suspicious_flag.set()
                return Verdict(True, "RESOURCE_EXHAUSTION", {
                    "device": self.known_devices.get(event.source_id, "unknown"),
                    "duration_seconds": len(window),
                    "avg_usage": round(sum(u for u, _ in window) / len(window), 3)
                })
        return None
    
    def _detect_message_flood(self, event) -> Optional[Verdict]:
        """Detect MQTT/message flooding attacks."""
        if event.event_name == "10000_messages_received":
            self.mqtt_events.append(event.timestamp)
            self._clean_sliding_window(self.mqtt_events, event.timestamp,
                                        DetectionConfig.MQTT_FLOOD_WINDOW)
            
            # Need at least 2 events (20,000+ messages) within the window to be considered a flood
            if len(self.mqtt_events) >= 2:
                self.suspicious_flag.set()
                return Verdict(True, "MESSAGE_FLOOD", {
                    "events_in_window": len(self.mqtt_events),
                    "estimated_messages": len(self.mqtt_events) * 10000
                })
        return None
    
    def evaluate(self, event) -> Verdict:
        """
        Evaluate an event against all security rules.
        
        Args:
            event: Security event to analyze
            
        Returns:
            Verdict indicating whether the event is suspicious
        """
        # 1. Network validation (critical - checked first)
        verdict = self._validate_network_access(event.source_id)
        if verdict:
            return verdict
            
        # 2. User and device validation  
        verdict = self._validate_user_and_device(event)
        if verdict:
            return verdict
            
        # 3. Attack pattern detection
        for detector in [
            self._detect_brute_force,
            self._detect_command_injection, 
            self._detect_power_anomaly,
            self._detect_network_attack,
            self._detect_resource_abuse,
            self._detect_message_flood
        ]:
            verdict = detector(event)
            if verdict:
                return verdict
        
        # No rules triggered
        return Verdict(False, None, {})
