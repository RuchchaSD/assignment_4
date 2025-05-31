# src/detector/__init__.py
"""
Attack Detection System

A comprehensive security monitoring framework for smart home environments.
Provides real-time attack detection, threat analysis, and event logging.
"""

from .attack_detector import AttackDetector
from .event import Event
from .instrumentation import detector
from .log_writer import LogWriter
from .rules import AttackRules, Verdict

__version__ = "1.0.0"
__author__ = "Security Team"

__all__ = [
    'AttackDetector',
    'Event', 
    'detector',
    'LogWriter',
    'AttackRules',
    'Verdict'
] 