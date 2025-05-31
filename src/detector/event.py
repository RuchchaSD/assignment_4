# src/detector/event.py
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

@dataclass
class Event:
    """Represents an event to be evaluated for suspicious activity. 
    Attributes:
        event_name: 
            Name of the event; This will be used to determine the type of event and the context data
            "login_attempt", "control_command","power_consumption", "packet_syn", "system_resource_usage", "10000_messages_received"
        user_role: 
            Role of the user who triggered the event;
            ("ADMIN", "USER", "MANAGER")
        user_id:
            Unique identifier of the user who triggered the event
        source_id:
            Ip address of the device/system component that generated the event
        timestamp: Timestamp when the event occurred
        context: Additional context data for the event(context can be anything that is relevant to the event)
    """   
    event_name: str
    user_role: str
    user_id: str
    source_id: str
    timestamp: datetime
    context: Dict[str, Any]