# src/detector/instrumentation.py
"""
Global instrumentation interface for the attack detection system.

This module provides a singleton detector instance and convenience functions
for logging security events. It's the main entry point for applications
that want to integrate attack detection.
"""

from .attack_detector import AttackDetector
from .event import Event

# Global singleton detector instance
detector = AttackDetector()

# Export the detector for direct access
__all__ = ['detector', 'Event']
