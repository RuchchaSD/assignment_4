#!/usr/bin/env python3
"""
Example usage of the new singleton AttackDetector class.
Demonstrates thread-safe event processing and asynchronous evaluation.
"""

import time
import threading
from datetime import datetime
from src.detector import AttackDetector, instrument, get_detector


def simulate_events():
    """Simulate various security events from different threads."""
    
    # Get the singleton detector instance
    detector = get_detector()
    print(f"Detector instance ID: {id(detector)}")
    
    # Simulate failed login attempts (should trigger FAILED_LOGIN_BURST)
    print("\n=== Simulating failed login attempts ===")
    for i in range(7):
        instrument(
            event_name="login_attempt",
            user_role="USER", 
            user_id="alice",
            source_id="192.168.1.100",
            ts=datetime.now(),
            ctx={"success": False}
        )
        time.sleep(0.1)
    
    # Simulate device toggle spam (should trigger TOGGLE_SPAM)
    print("\n=== Simulating device toggle spam ===")
    for i in range(12):
        instrument(
            event_name="toggle_device",
            user_role="USER",
            user_id="bob", 
            source_id="192.168.1.101",
            ts=datetime.now(),
            ctx={"device": "smart_light_1"}
        )
        time.sleep(0.1)
    
    # Simulate impossible travel (should trigger GEO_IMPOSSIBLE)
    print("\n=== Simulating impossible travel ===")
    # First login from New York
    instrument(
        event_name="login_attempt",
        user_role="USER",
        user_id="charlie",
        source_id="192.168.1.102", 
        ts=datetime.now(),
        ctx={"success": True, "ip_coord": (40.7128, -74.0060)}  # NYC
    )
    
    time.sleep(0.1)
    
    # Second login from London 2 minutes later (impossible travel)
    instrument(
        event_name="login_attempt", 
        user_role="USER",
        user_id="charlie",
        source_id="192.168.1.103",
        ts=datetime.now(),
        ctx={"success": True, "ip_coord": (51.5074, -0.1278)}  # London
    )
    
    print(f"Events queued for processing: {detector.get_queue_size()}")


def worker_thread(thread_id):
    """Worker thread that generates events concurrently."""
    print(f"Thread {thread_id} starting...")
    
    for i in range(3):
        instrument(
            event_name="camera_motion",
            user_role="USER",
            user_id=f"user_{thread_id}",
            source_id=f"camera_{thread_id}",
            ts=datetime.now(),
            ctx={"time": 23}  # After hours - should trigger MOTION_AFTER_HOURS
        )
        time.sleep(0.2)
    
    print(f"Thread {thread_id} completed")


def test_singleton():
    """Test that AttackDetector is truly a singleton."""
    print("\n=== Testing Singleton Pattern ===")
    
    detector1 = AttackDetector()
    detector2 = AttackDetector() 
    detector3 = get_detector()
    
    print(f"detector1 ID: {id(detector1)}")
    print(f"detector2 ID: {id(detector2)}")
    print(f"detector3 ID: {id(detector3)}")
    print(f"All instances are the same: {detector1 is detector2 is detector3}")


def test_multithreading():
    """Test thread-safe event processing."""
    print("\n=== Testing Multithreading ===")
    
    # Create multiple threads that generate events
    threads = []
    for i in range(3):
        thread = threading.Thread(target=worker_thread, args=(i,))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print("All worker threads completed")


if __name__ == "__main__":
    print("=== AttackDetector Singleton Demo ===")
    
    # # Test singleton pattern
    # test_singleton()
    
    # Simulate various security events
    simulate_events()
    
    # Test multithreading
    test_multithreading()
    
    # Give some time for events to be processed
    print("\nWaiting for events to be processed...")
    time.sleep(3)
    
    # Check final queue size
    detector = get_detector()
    print(f"Final queue size: {detector.get_queue_size()}")
    
    # Graceful shutdown
    print("\nShutting down detector...")
    detector.shutdown()
    print("Detector shutdown complete")
    
    print("\nCheck 'logs/suspicious.jsonl' for detected suspicious activities!") 