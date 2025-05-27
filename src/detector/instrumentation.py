# src/detector/instrumentation.py
import threading
import queue
from datetime import datetime
from typing import Dict, Any, NamedTuple
from dataclasses import dataclass

from .rules import AttackRules
from .log_writer import LogWriter


@dataclass
class Event:
    """Represents an event to be evaluated for suspicious activity."""
    event_name: str
    user_role: str
    user_id: str
    source_id: str
    timestamp: datetime
    context: Dict[str, Any]


class AttackDetector:
    """Singleton class for detecting suspicious activities with thread-safe event processing."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(AttackDetector, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self._rules = AttackRules()
        self._logger = LogWriter("logs/suspicious.jsonl")
        
        # Thread-safe event buffer
        self._event_queue = queue.Queue()
        
        # Worker thread for processing events
        self._worker_thread = None
        self._shutdown_event = threading.Event()
        self._start_worker()
    
    def _start_worker(self):
        """Start the worker thread for processing events."""
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._worker_thread = threading.Thread(
                target=self._process_events,
                daemon=True,
                name="AttackDetectorWorker"
            )
            self._worker_thread.start()
    
    def _process_events(self):
        """Worker thread method that continuously processes events from the queue."""
        while not self._shutdown_event.is_set():
            try:
                # Wait for an event with timeout to allow checking shutdown
                event = self._event_queue.get(timeout=1.0)
                
                # Evaluate the event using the rules engine
                verdict = self._rules.evaluate(
                    event.event_name,
                    event.user_role,
                    event.user_id,
                    event.source_id,
                    event.timestamp,
                    event.context
                )
                
                # Log suspicious activities
                if verdict.suspicious:
                    self._logger.write(verdict)
                
                # Mark task as done
                self._event_queue.task_done()
                
            except queue.Empty:
                # Timeout occurred, continue to check shutdown
                continue
            except Exception as e:
                # Log any processing errors but continue running
                import logging
                logging.error(f"Error processing event: {e}")
                self._event_queue.task_done()
    
    def instrument(self, event_name: str, user_role: str, user_id: str, 
                    source_id: str, ts: datetime, ctx: Dict[str, Any]) -> None:
        """
        Queue an event for asynchronous evaluation.
        
        Args:
            event_name: Type of event (e.g., "login_attempt", "toggle_device")
            user_role: Role of the user performing the action
            user_id: Unique identifier for the user
            source_id: Source identifier (e.g., IP address, device ID)
            ts: Timestamp when the event occurred
            ctx: Additional context data for the event
        """
        event = Event(
            event_name=event_name,
            user_role=user_role,
            user_id=user_id,
            source_id=source_id,
            timestamp=ts,
            context=ctx
        )
        
        # Add event to the thread-safe queue
        self._event_queue.put(event)
    
    def shutdown(self):
        """Gracefully shutdown the detector and wait for pending events to be processed."""
        # Signal shutdown
        self._shutdown_event.set()
        
        # Wait for all queued events to be processed
        self._event_queue.join()
        
        # Wait for worker thread to finish
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5.0)
    
    def get_queue_size(self) -> int:
        """Get the current number of events waiting to be processed."""
        return self._event_queue.qsize()


# Global singleton instance
_detector = AttackDetector()


def instrument(event_name: str, user_role: str, user_id: str, source_id: str, ts: datetime, ctx: Dict[str, Any]) -> None:
    """
    Global function to instrument events for suspicious activity detection.
    This maintains backward compatibility with the existing API.
    
    Args:
        event_name: Type of event (e.g., "login_attempt", "toggle_device")
        user_role: Role of the user performing the action
        user_id: Unique identifier for the user
        source_id: Source identifier (e.g., IP address, device ID)
        ts: Timestamp when the event occurred
        ctx: Additional context data for the event
    """
    _detector.instrument(event_name, user_role, user_id, source_id, ts, ctx)


def get_detector() -> AttackDetector:
    """Get the global AttackDetector singleton instance."""
    return _detector
