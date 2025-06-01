#!/usr/bin/env python3
"""
Comprehensive API test suite for the Attack Detection REST API.

This module tests all API endpoints using HTTP requests, verifying that
the FastAPI server correctly processes security events and detects attacks.

Run:
    python test_api.py
    
Requirements:
    - API server running on localhost:8000
    - requests library installed
"""

import json
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, Any


class APITestClient:
    """HTTP client for testing the Attack Detection API."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize the test client with API base URL."""
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
    
    def post_event(self, event_name: str, user_id: str, user_role: str, 
                   source_id: str, context: Dict[str, Any] = None) -> Dict:
        """Post a security event to the API."""
        if context is None:
            context = {}
            
        event_data = {
            "event_name": event_name,
            "user_role": user_role,
            "user_id": user_id,
            "source_id": source_id,
            "context": context
        }
        
        response = self.session.post(f"{self.base_url}/events", json=event_data)
        response.raise_for_status()
        return response.json()
    
    def get_status(self) -> Dict:
        """Get current system status."""
        response = self.session.get(f"{self.base_url}/status")
        response.raise_for_status()
        return response.json()
    
    def clear_suspicious_flag(self) -> Dict:
        """Clear the suspicious activity flag."""
        response = self.session.post(f"{self.base_url}/status/clear")
        response.raise_for_status()
        return response.json()
    
    def configure_user(self, user_id: str, max_privilege: str) -> Dict:
        """Configure a user in the system."""
        user_data = {"user_id": user_id, "max_privilege": max_privilege}
        response = self.session.post(f"{self.base_url}/config/users", json=user_data)
        response.raise_for_status()
        return response.json()
    
    def configure_device(self, device_ip: str, device_type: str) -> Dict:
        """Register a device in the system."""
        device_data = {"device_ip": device_ip, "device_type": device_type}
        response = self.session.post(f"{self.base_url}/config/devices", json=device_data)
        response.raise_for_status()
        return response.json()
    
    def configure_commands(self, commands: list) -> Dict:
        """Update dangerous commands list."""
        commands_data = {"commands": commands}
        response = self.session.post(f"{self.base_url}/config/commands", json=commands_data)
        response.raise_for_status()
        return response.json()
    
    def get_attack_logs(self, limit: int = 50) -> Dict:
        """Get recent attack logs."""
        response = self.session.get(f"{self.base_url}/logs/attacks", params={"limit": limit})
        response.raise_for_status()
        return response.json()
    
    def wait_for_processing(self, timeout: float = 2.0) -> bool:
        """Wait for all events to be processed."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                status = self.get_status()
                # Check if all device queues are empty
                if all(size == 0 for size in status["queue_sizes"].values()):
                    time.sleep(0.1)  # Small delay for final processing
                    return True
                time.sleep(0.1)
            except:
                pass
        return True  # Continue even if status check fails
    
    def expect_with_sync(self, test_name: str, should_alert: bool) -> None:
        """Test expectation with proper synchronization."""
        # Wait for processing to complete
        self.wait_for_processing()
        
        try:
            status = self.get_status()
            actual_alert = status["suspicious_activity"]
            
            result = "PASS" if actual_alert == should_alert else "FAIL"
            print(f"{test_name:<40} → {result}")
            
            self.test_results.append({
                "test": test_name,
                "expected": should_alert,
                "actual": actual_alert,
                "passed": actual_alert == should_alert
            })
            
            # Clear flag for next test
            if actual_alert:
                self.clear_suspicious_flag()
                
        except Exception as e:
            print(f"{test_name:<40} → ERROR: {e}")
            self.test_results.append({
                "test": test_name,
                "expected": should_alert,
                "actual": None,
                "passed": False,
                "error": str(e)
            })
        
        time.sleep(0.1)  # Brief pause between tests


def run_api_tests():
    """Run comprehensive API tests."""
    print("=" * 70)
    print("COMPREHENSIVE ATTACK DETECTION API TEST SUITE")
    print("=" * 70)
    
    # Initialize test client
    client = APITestClient()
    
    # Test server connectivity
    try:
        response = client.session.get(f"{client.base_url}/health")
        response.raise_for_status()
        print(f"✅ API Server is running: {response.json()['status']}")
    except Exception as e:
        print(f"❌ Cannot connect to API server: {e}")
        print("   Please start the server with: python api_server.py")
        return False
    
    # =========================================================================
    # Setup: Configure the system
    # =========================================================================
    print("\n--- SYSTEM CONFIGURATION ---")
    
    # Configure users
    users = [
        ("alice", "USER"), ("eve", "USER"), ("admin", "ADMIN"), 
        ("manager", "MANAGER"), ("attacker", "USER"), ("attacker1", "USER"),
        ("attacker2", "USER"), ("attacker3", "USER"), ("user10", "USER"),
        ("user20", "USER"), ("user30", "USER"), ("user40", "USER"), ("user50", "USER")
    ]
    
    for user_id, privilege in users:
        client.configure_user(user_id, privilege)
    
    # Configure devices
    devices = [
        ("192.168.0.10", "thermostat"), ("192.168.0.20", "gateway"),
        ("192.168.0.30", "hvac"), ("192.168.0.40", "security_cam"),
        ("192.168.0.50", "smart_lock")
    ]
    
    for device_ip, device_type in devices:
        client.configure_device(device_ip, device_type)
    
    # Configure dangerous commands
    client.configure_commands(["shutdown", "poweroff", "reboot", "factory_reset"])
    
    print("✅ System configuration completed")
    
    # =========================================================================
    # Test Suite: All detection rules
    # =========================================================================
    
    print("\n--- BASELINE TESTS ---")
    client.post_event("login_attempt", "alice", "USER", "192.168.0.10", {"success": True})
    client.post_event("control_command", "alice", "USER", "192.168.0.10", {"command": "light_on"})
    client.expect_with_sync("Baseline no-alert", False)
    
    print("\n--- IP VALIDATION TESTS ---")
    client.post_event("login_attempt", "alice", "USER", "11.22.33.44", {"success": True})
    client.expect_with_sync("Non-LAN IP address", True)
    
    client.post_event("login_attempt", "alice", "USER", "invalid-ip", {"success": True})
    client.expect_with_sync("Malformed IP address", True)
    
    print("\n--- USER/DEVICE VALIDATION TESTS ---")
    client.post_event("login_attempt", "alice", "USER", "192.168.99.99", {"success": True})
    client.expect_with_sync("Unknown device", False)
    
    client.post_event("login_attempt", "unknown_user", "USER", "192.168.0.20", {"success": True})
    client.expect_with_sync("Unknown user", False)
    
    client.post_event("login_attempt", "alice", "INVALID_ROLE", "192.168.0.10", {"success": True})
    client.expect_with_sync("Unknown role", False)
    
    client.post_event("login_attempt", "manager", "USER", "192.168.0.10", {"success": True})
    client.expect_with_sync("Privilege escalation attempt", False)
    
    print("\n--- BRUTE FORCE TESTS ---")
    for i in range(6):
        client.post_event("login_attempt", "eve", "USER", "192.168.0.20", {"success": False})
    client.expect_with_sync("Failed login burst", True)
    
    print("\n--- COMMAND SPAM TESTS ---")
    for i in range(4):
        client.post_event("control_command", "eve", "USER", "192.168.0.20", {"command": "shutdown"})
    client.expect_with_sync("Dangerous command spam (USER)", True)
    
    for i in range(5):
        client.post_event("control_command", "admin", "ADMIN", "192.168.0.20", {"command": "factory_reset"})
    client.expect_with_sync("High-rate commands (ADMIN allowed)", False)
    
    print("\n--- POWER CONSUMPTION TESTS ---")
    client.post_event("power_consumption", "alice", "USER", "192.168.0.30", {"percent": -10})
    client.expect_with_sync("Invalid power value (negative)", False)
    
    client.post_event("power_consumption", "alice", "USER", "192.168.0.30", {"percent": 150})
    client.expect_with_sync("Invalid power value (>100%)", False)
    
    # Build baseline then spike
    for i in range(6):
        client.post_event("power_consumption", "alice", "USER", "192.168.0.30", {"percent": 30})
    client.post_event("power_consumption", "alice", "USER", "192.168.0.30", {"percent": 80})
    client.expect_with_sync("Power consumption spike", True)
    
    print("\n--- NETWORK ATTACK TESTS ---")
    client.post_event("packet_syn", "eve", "USER", "192.168.0.20", {"rate": 150, "multi_user": False})
    client.expect_with_sync("SYN flood attack", True)
    
    client.post_event("packet_syn", "attacker", "USER", "192.168.0.40", {"rate": 200, "multi_user": True})
    client.expect_with_sync("Multi-user SYN flood", True)
    
    print("\n--- RESOURCE ABUSE TESTS ---")
    for i in range(95):
        client.post_event("system_resource_usage", "alice", "USER", "192.168.0.30", {"usage": 0.85})
    client.expect_with_sync("System resource abuse", True)
    
    print("\n--- MQTT FLOOD TESTS ---")
    # Single event should not trigger
    client.post_event("10000_messages_received", "alice", "USER", "192.168.0.40", {})
    client.expect_with_sync("Single MQTT burst (10k msgs)", False)
    
    # Two events should trigger
    client.post_event("10000_messages_received", "alice", "USER", "192.168.0.40", {})
    client.post_event("10000_messages_received", "alice", "USER", "192.168.0.40", {})
    client.expect_with_sync("MQTT message flood (20k msgs)", True)
    
    print("\n--- PARALLEL API STRESS TEST ---")
    import threading
    
    def send_parallel_events():
        """Send multiple events simultaneously to test API concurrency."""
        events = [
            ("login_attempt", "attacker1", "USER", "192.168.0.10", {"success": False}),
            ("login_attempt", "attacker1", "USER", "192.168.0.10", {"success": False}),
            ("login_attempt", "attacker1", "USER", "192.168.0.10", {"success": False}),
            ("login_attempt", "attacker1", "USER", "192.168.0.10", {"success": False}),
            ("login_attempt", "attacker1", "USER", "192.168.0.10", {"success": False}),
            ("login_attempt", "attacker1", "USER", "192.168.0.10", {"success": False}),
            ("control_command", "attacker2", "USER", "192.168.0.20", {"command": "shutdown"}),
            ("control_command", "attacker2", "USER", "192.168.0.20", {"command": "shutdown"}),
            ("control_command", "attacker2", "USER", "192.168.0.20", {"command": "shutdown"}),
            ("control_command", "attacker2", "USER", "192.168.0.20", {"command": "shutdown"}),
            ("packet_syn", "attacker3", "USER", "192.168.0.30", {"rate": 180}),
        ]
        
        threads = []
        for event_name, user_id, user_role, source_id, context in events:
            t = threading.Thread(target=client.post_event, args=(event_name, user_id, user_role, source_id, context))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
    
    send_parallel_events()
    client.expect_with_sync("Parallel API attacks (multi-device)", True)
    
    # =========================================================================
    # Test additional API endpoints
    # =========================================================================
    
    print("\n--- API FUNCTIONALITY TESTS ---")
    
    # Test configuration stats
    try:
        stats = client.session.get(f"{client.base_url}/config/stats").json()
        print(f"✅ Configuration stats: {stats['users_configured']} users, {stats['devices_registered']} devices")
    except Exception as e:
        print(f"❌ Configuration stats failed: {e}")
    
    # Test attack logs
    try:
        logs = client.get_attack_logs(10)
        print(f"✅ Attack logs retrieved: {logs['total_returned']} attacks")
    except Exception as e:
        print(f"❌ Attack logs failed: {e}")
    
    # Test health check
    try:
        health = client.session.get(f"{client.base_url}/health").json()
        print(f"✅ Health check: {health['status']} (uptime: {health['uptime_seconds']:.1f}s)")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
    
    # =========================================================================
    # Results Summary
    # =========================================================================
    
    print("\n" + "=" * 70)
    print("API TEST SUITE RESULTS")
    print("=" * 70)
    
    total_tests = len(client.test_results)
    passed_tests = sum(1 for result in client.test_results if result["passed"])
    failed_tests = total_tests - passed_tests
    
    print(f"📊 Total Tests: {total_tests}")
    print(f"✅ Passed: {passed_tests}")
    print(f"❌ Failed: {failed_tests}")
    print(f"📈 Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if failed_tests > 0:
        print("\n🔍 Failed Tests:")
        for result in client.test_results:
            if not result["passed"]:
                error_info = f" (Error: {result.get('error', 'N/A')})" if result.get('error') else ""
                print(f"   ❌ {result['test']}: Expected {result['expected']}, Got {result.get('actual', 'N/A')}{error_info}")
    
    print(f"\n📁 Check logs/attack_detection.log for attack details")
    print(f"📁 Check logs/run.log for complete activity audit")
    
    return passed_tests == total_tests


if __name__ == "__main__":
    success = run_api_tests()
    exit(0 if success else 1) 