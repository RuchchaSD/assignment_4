# src/detector/attack_detector.py
"""
Thread-safe attack detection system with per-device processing queues.

This module implements a singleton AttackDetector that processes security events
asynchronously using dedicated worker threads per device. It maintains shared
state for users, devices, and commands while ensuring thread isolation.
"""

import threading
from queue import Queue, Empty
from typing import Dict, Set

from .event import Event
from .log_writer import LogWriter
from .rules import AttackRules


class AttackDetector:
    """
    Singleton attack detection engine with thread-per-device architecture.
    
    This class manages:
    - Shared dictionaries for verified users/devices (thread-safe)
    - Per-device processing queues and worker threads
    - Global suspicious activity flag
    - Centralized logging for all events
    
    The singleton pattern ensures consistent state across the application
    while the thread-per-device design provides isolation and parallel processing.
    
    Key Features:
    - LAN-only validation for network security
    - Role-based access control with admin exemptions
    - Sliding window algorithms for temporal analysis
    - Comprehensive logging with structured output
    - Graceful shutdown with event queue draining
    
    Example:
        >>> detector = AttackDetector()
        >>> detector.update_user("alice", "USER")
        >>> detector.update_device("192.168.1.100", "sensor")
        >>> detector.handle_event(event)
        >>> if detector.suspicious_flag.is_set():
        ...     print("Attack detected!")
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Ensure singleton pattern - only one detector instance exists."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the detector with empty state (called only once)."""
        if self._initialized:
            return
            
        # Shared state (thread-safe via locks)
        self._users_lock = threading.Lock()
        self._devices_lock = threading.Lock()
        self._commands_lock = threading.Lock()
        
        self._verified_users: Dict[str, str] = {}
        self._known_devices: Dict[str, str] = {}
        self._exploitable_commands: Set[str] = set()
        
        # Global suspicious activity flag
        self.suspicious_flag = threading.Event()
        
        # Per-device processing infrastructure
        self._device_queues: Dict[str, Queue] = {}
        self._device_threads: Dict[str, threading.Thread] = {}
        self._device_rules: Dict[str, AttackRules] = {}
        self._shutdown_event = threading.Event()
        
        # Centralized logging
        self._log_writer = LogWriter("logs/attack_detection.log")
        
        self._initialized = True
    
    def update_user(self, user_id: str, max_privilege: str) -> None:
        """
        Add or update a verified user with their maximum privilege level.
        
        Args:
            user_id: Unique identifier for the user
            max_privilege: Highest role this user can assume ("ADMIN", "MANAGER", "USER")
            
        Thread-safe: Uses internal locking for concurrent access
        """
        with self._users_lock:
            self._verified_users[user_id] = max_privilege
    
    def update_device(self, device_ip: str, device_type: str) -> None:
        """
        Register a device as known/trusted in the system.
        
        Args:
            device_ip: IP address of the device (should be LAN address)
            device_type: Type/description of the device
            
        Thread-safe: Uses internal locking for concurrent access
        """
        with self._devices_lock:
            self._known_devices[device_ip] = device_type
    
    def update_command_list(self, commands: Set[str]) -> None:
        """
        Update the list of commands considered dangerous/exploitable.
        
        Args:
            commands: Set of command names to monitor for abuse
            
        Thread-safe: Uses internal locking for concurrent access
        Note: Mutates the existing set in place so worker threads see updates
        """
        with self._commands_lock:
            self._exploitable_commands.clear()
            self._exploitable_commands.update(commands)
    
    def _get_device_worker(self, device_ip: str) -> None:
        """
        Worker thread function for processing events from a specific device.
        
        This function runs in a loop, processing events from the device's queue
        until shutdown is signaled. Each device has its own worker thread and
        rules engine instance for complete isolation.
        
        Args:
            device_ip: IP address of the device this worker handles
        """
        # Create device-specific rules engine with read-only references
        with self._users_lock, self._devices_lock, self._commands_lock:
            rules = AttackRules(
                self._verified_users,  # Read-only reference
                self._known_devices,   # Read-only reference  
                self._exploitable_commands,  # Read-only reference
                self.suspicious_flag   # Shared flag
            )
        
        device_queue = self._device_queues[device_ip]
        
        while not self._shutdown_event.is_set():
            try:
                # Get event with timeout to allow periodic shutdown checks
                event = device_queue.get(timeout=0.1)
                
                # Process event through rules engine
                verdict = rules.evaluate(event)
                
                # Log the result
                self._log_writer.write(verdict)
                
                # Mark task as done
                device_queue.task_done()
                
            except Empty:
                # Timeout - check shutdown flag and continue
                continue
            except Exception as e:
                # Log unexpected errors but keep worker running
                import logging
                logging.error(f"Error processing event on device {device_ip}: {e}")
                if not device_queue.empty():
                    device_queue.task_done()
    
    def _ensure_device_worker(self, device_ip: str) -> None:
        """
        Ensure a worker thread exists for the specified device.
        
        Creates the device queue and worker thread if they don't exist.
        This allows for dynamic device registration.
        
        Args:
            device_ip: IP address of the device
        """
        if device_ip not in self._device_threads:
            # Create queue and thread for this device
            self._device_queues[device_ip] = Queue()
            
            worker = threading.Thread(
                target=self._get_device_worker,
                args=(device_ip,),
                name=f"DeviceWorker-{device_ip}",
                daemon=True
            )
            worker.start()
            
            self._device_threads[device_ip] = worker
    
    def handle_event(self, event: Event) -> None:
        """
        Queue an event for processing by the appropriate device worker.
        
        This method is non-blocking - it immediately queues the event
        and returns. The actual processing happens asynchronously.
        
        Args:
            event: Security event to be analyzed
            
        Thread-safe: Queue operations are thread-safe by design
        """
        device_ip = event.source_id
        
        # Ensure worker thread exists for this device
        self._ensure_device_worker(device_ip)
        
        # Queue event for processing
        self._device_queues[device_ip].put(event)
    
    def get_queue_size(self, device_ip: str = None) -> int:
        """
        Get the number of unprocessed events in queue(s).
        
        Args:
            device_ip: Specific device to check, or None for total across all devices
            
        Returns:
            Number of queued events
        """
        if device_ip:
            return self._device_queues.get(device_ip, Queue()).qsize()
        else:
            return sum(queue.qsize() for queue in self._device_queues.values())
    
    def shutdown(self, timeout: float = 5.0) -> bool:
        """
        Gracefully shutdown the detector, waiting for queues to drain.
        
        Args:
            timeout: Maximum time to wait for queue processing
            
        Returns:
            True if shutdown completed cleanly, False if timeout occurred
        """
        # Signal all workers to shutdown
        self._shutdown_event.set()
        
        # Wait for all queues to empty
        for device_ip, queue in self._device_queues.items():
            try:
                queue.join()  # Wait for all tasks to complete
            except:
                pass  # Continue even if join fails
        
        # Wait for worker threads to terminate
        for thread in self._device_threads.values():
            thread.join(timeout=timeout / len(self._device_threads))
        
        return all(not thread.is_alive() for thread in self._device_threads.values())
