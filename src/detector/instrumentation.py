# src/detector/instrumentation.py
from .attack_detector import AttackDetector
from .event import Event

detector = AttackDetector()

def instrument(event: Event):
    detector.handle_event(event)
