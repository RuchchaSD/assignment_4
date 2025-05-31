# src/detector/event.py
"""
Event data structure for the attack detection system.

This module defines the Event dataclass used to represent security events
that are processed by the attack detection engine.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict


@dataclass
class Event:
    """
    Represents a security event to be evaluated for suspicious activity.
    
    This is the core data structure used throughout the attack detection system.
    All security events (login attempts, device commands, network activity, etc.)
    are represented using this class.
    
    Attributes:
        event_name: Type of event being reported. Supported types include:
                   - "login_attempt": User authentication attempts
                   - "control_command": Device control operations  
                   - "power_consumption": Power usage readings
                   - "packet_syn": Network SYN packet events
                   - "system_resource_usage": CPU/memory/bandwidth usage
                   - "10000_messages_received": MQTT message flood events
        
        user_role: Role of the user who triggered the event.
                  Must be one of: "ADMIN", "MANAGER", "USER"
        
        user_id: Unique identifier of the user who triggered the event.
                Used for tracking per-user behavior patterns.
        
        source_id: IP address of the device/system that generated the event.
                  Must be a valid IPv4 address, preferably from local network.
        
        timestamp: When the event occurred. Used for time-based analysis
                  like sliding windows and rate limiting.
        
        context: Additional event-specific data. Common keys include:
                - "success": Boolean for login attempts
                - "command": String for control commands  
                - "percent": Float for power consumption
                - "rate": Integer for network packet rates
                - "usage": Float for resource usage (0.0-1.0)
                - "multi_user": Boolean for multi-user attacks
    
    Example:
        >>> from datetime import datetime
        >>> event = Event(
        ...     event_name="login_attempt",
        ...     user_role="USER", 
        ...     user_id="alice",
        ...     source_id="192.168.1.100",
        ...     timestamp=datetime.now(),
        ...     context={"success": False}
        ... )
    """
    event_name: str
    user_role: str
    user_id: str
    source_id: str
    timestamp: datetime
    context: Dict[str, Any]