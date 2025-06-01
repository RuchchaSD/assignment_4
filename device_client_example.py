#!/usr/bin/env python3
"""
Example IoT device client for the Attack Detection API.

This script demonstrates how smart home devices can report security
events to the attack detection system via HTTP API calls.

Usage:
    python device_client_example.py
    
Requirements:
    - API server running on the network
    - requests library installed
"""

import json
import time
import requests
from datetime import datetime
from typing import Dict, Any


class IoTDevice:
    """Example IoT device that reports security events."""
    
    def __init__(self, device_ip: str, device_type: str, api_url: str = "http://localhost:8000"):
        """
        Initialize the IoT device.
        
        Args:
            device_ip: This device's IP address
            device_type: Type of device (thermostat, camera, etc.)
            api_url: URL of the attack detection API server
        """
        self.device_ip = device_ip
        self.device_type = device_type
        self.api_url = api_url
        self.session = requests.Session()
        
        # Register this device with the system
        self.register_device()
    
    def register_device(self) -> bool:
        """Register this device with the attack detection system."""
        try:
            response = self.session.post(
                f"{self.api_url}/config/devices",
                json={
                    "device_ip": self.device_ip,
                    "device_type": self.device_type
                },
                timeout=5
            )
            response.raise_for_status()
            print(f"✅ Device {self.device_ip} registered as {self.device_type}")
            return True
        except Exception as e:
            print(f"❌ Failed to register device: {e}")
            return False
    
    def report_event(self, event_name: str, user_id: str, user_role: str, 
                    context: Dict[str, Any] = None) -> bool:
        """
        Report a security event to the attack detection system.
        
        Args:
            event_name: Type of security event
            user_id: User who triggered the event
            user_role: Role of the user
            context: Additional event context
            
        Returns:
            True if event was successfully reported
        """
        if context is None:
            context = {}
        
        event_data = {
            "event_name": event_name,
            "user_role": user_role,
            "user_id": user_id,
            "source_id": self.device_ip,
            "context": context
        }
        
        try:
            response = self.session.post(
                f"{self.api_url}/events",
                json=event_data,
                timeout=5
            )
            response.raise_for_status()
            
            result = response.json()
            print(f"📡 Event reported: {event_name} by {user_id} → {result['status']}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to report event: {e}")
            return False
    
    def check_security_status(self) -> Dict[str, Any]:
        """Check if any suspicious activity has been detected."""
        try:
            response = self.session.get(f"{self.api_url}/status", timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Failed to check status: {e}")
            return {}


def simulate_smart_thermostat():
    """Simulate a smart thermostat reporting various events."""
    print("🌡️  Smart Thermostat Simulation")
    print("-" * 50)
    
    # Create thermostat device
    thermostat = IoTDevice("192.168.1.101", "smart_thermostat")
    
    # Simulate normal operation
    print("\n📊 Reporting normal operations...")
    thermostat.report_event("login_attempt", "alice", "USER", {"success": True})
    thermostat.report_event("temperature_change", "alice", "USER", {"old_temp": 20, "new_temp": 22})
    thermostat.report_event("power_consumption", "system", "USER", {"percent": 35})
    
    # Check status
    status = thermostat.check_security_status()
    if status:
        print(f"🔍 Security Status: {'🚨 SUSPICIOUS' if status['suspicious_activity'] else '✅ NORMAL'}")
    
    # Simulate suspicious activity
    print("\n⚠️  Simulating suspicious activity...")
    for i in range(6):
        thermostat.report_event("login_attempt", "unknown_user", "USER", {"success": False})
        time.sleep(0.1)
    
    # Check status again
    time.sleep(1)  # Wait for processing
    status = thermostat.check_security_status()
    if status:
        print(f"🔍 Security Status: {'🚨 SUSPICIOUS' if status['suspicious_activity'] else '✅ NORMAL'}")
        print(f"📈 Events Processed: {status['total_events_processed']}")


def simulate_security_camera():
    """Simulate a security camera reporting events."""
    print("\n📹 Security Camera Simulation")
    print("-" * 50)
    
    # Create camera device
    camera = IoTDevice("192.168.1.102", "security_camera")
    
    # Simulate motion detection events
    print("\n👁️  Reporting motion detection...")
    camera.report_event("motion_detected", "system", "USER", {"location": "front_door", "confidence": 0.95})
    camera.report_event("face_recognition", "alice", "USER", {"match_confidence": 0.98})
    
    # Simulate network attack detection
    print("\n🌐 Simulating network attack...")
    camera.report_event("packet_syn", "attacker", "USER", {"rate": 150, "multi_user": False})
    
    # Check final status
    time.sleep(1)
    status = camera.check_security_status()
    if status:
        print(f"🔍 Final Security Status: {'🚨 SUSPICIOUS' if status['suspicious_activity'] else '✅ NORMAL'}")


def simulate_smart_lock():
    """Simulate a smart lock with power monitoring."""
    print("\n🔐 Smart Lock Simulation")
    print("-" * 50)
    
    # Create smart lock device
    smart_lock = IoTDevice("192.168.1.103", "smart_lock")
    
    # Build power consumption baseline
    print("\n⚡ Building power consumption baseline...")
    for i in range(6):
        smart_lock.report_event("power_consumption", "system", "USER", {"percent": 25 + i})
        time.sleep(0.1)
    
    # Simulate power spike (potential tampering)
    print("\n⚡ Simulating power anomaly...")
    smart_lock.report_event("power_consumption", "system", "USER", {"percent": 75})
    
    # Check status
    time.sleep(1)
    status = smart_lock.check_security_status()
    if status:
        print(f"🔍 Security Status: {'🚨 SUSPICIOUS' if status['suspicious_activity'] else '✅ NORMAL'}")


def main():
    """Main function demonstrating device client usage."""
    print("🏠 IoT DEVICE CLIENT EXAMPLES")
    print("=" * 70)
    print("This demonstrates how IoT devices can report security events")
    print("to the Attack Detection API for real-time threat analysis.")
    print()
    
    # Check if API server is available
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            print("✅ API server is running locally")
        else:
            print("⚠️  API server responded but may have issues")
    except:
        print("❌ API server not available on localhost:8000")
        print("   Please start the server with: python api_server.py")
        print("   Or update the API URL in this script for your network")
        return
    
    # Run device simulations
    try:
        simulate_smart_thermostat()
        simulate_security_camera()  
        simulate_smart_lock()
        
        print("\n" + "=" * 70)
        print("🎯 SIMULATION COMPLETED")
        print("✅ All device types demonstrated event reporting")
        print("📊 Check the API logs for complete event analysis")
        print("🔍 Use the API endpoints to query system status")
        
    except KeyboardInterrupt:
        print("\n⚠️  Simulation interrupted by user")
    except Exception as e:
        print(f"\n❌ Simulation error: {e}")


if __name__ == "__main__":
    main() 