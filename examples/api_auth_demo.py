#!/usr/bin/env python3
#examples/api_auth_demo.py
"""
API Authentication Demonstration

This script demonstrates the API key authentication system
for the Attack Detection API by testing both protected and
unprotected endpoints.

Usage:
    python examples/api_auth_demo.py
"""

import requests
import json


def test_api_authentication():
    """Demonstrate API key authentication for protected endpoints."""
    base_url = "http://localhost:8000"
    api_key = "secret-api-key-12345"
    
    print("🔑 API AUTHENTICATION DEMONSTRATION")
    print("=" * 50)
    
    # Test 1: Unprotected endpoint (should work without API key)
    print("\n1. Testing UNPROTECTED endpoint (/health) - No API key needed:")
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✅ SUCCESS: Health check works without authentication")
            data = response.json()
            print(f"   Status: {data['status']}")
        else:
            print(f"❌ FAILED: Status code {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    # Test 2: Protected endpoint without API key (should fail)
    print("\n2. Testing PROTECTED endpoint (/config/stats) - Without API key:")
    try:
        response = requests.get(f"{base_url}/config/stats")
        if response.status_code == 401:
            print("✅ SUCCESS: Correctly rejected unauthorized request")
            error = response.json()
            print(f"   Error: {error['detail']}")
        else:
            print(f"❌ FAILED: Expected 401, got {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    # Test 3: Protected endpoint with WRONG API key (should fail)
    print("\n3. Testing PROTECTED endpoint (/config/stats) - With WRONG API key:")
    try:
        headers = {"X-API-Key": "wrong-api-key"}
        response = requests.get(f"{base_url}/config/stats", headers=headers)
        if response.status_code == 401:
            print("✅ SUCCESS: Correctly rejected invalid API key")
            error = response.json()
            print(f"   Error: {error['detail']}")
        else:
            print(f"❌ FAILED: Expected 401, got {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    # Test 4: Protected endpoint with CORRECT API key (should work)
    print("\n4. Testing PROTECTED endpoint (/config/stats) - With CORRECT API key:")
    try:
        headers = {"X-API-Key": api_key}
        response = requests.get(f"{base_url}/config/stats", headers=headers)
        if response.status_code == 200:
            print("✅ SUCCESS: Access granted with valid API key")
            data = response.json()
            print(f"   Users configured: {data['users_configured']}")
            print(f"   Devices registered: {data['devices_registered']}")
        else:
            print(f"❌ FAILED: Status code {response.status_code}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    # Test 5: Test all protected endpoints
    print("\n5. Testing ALL PROTECTED endpoints with correct API key:")
    protected_endpoints = [
        ("POST", "/status/clear", "Clear suspicious flag"),
        ("POST", "/config/users", "Configure user", {"user_id": "test", "max_privilege": "USER"}),
        ("POST", "/config/devices", "Register device", {"device_ip": "192.168.1.99", "device_type": "test"}),
        ("POST", "/config/commands", "Update commands", {"commands": ["test_cmd"]}),
        ("GET", "/config/stats", "Get stats"),
        ("GET", "/logs/attacks", "Get attack logs"),
        ("DELETE", "/system/shutdown", "Shutdown system")
    ]
    
    headers = {"X-API-Key": api_key}
    
    for method, endpoint, description, *payload in protected_endpoints:
        try:
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}", headers=headers)
            elif method == "POST":
                data = payload[0] if payload else {}
                response = requests.post(f"{base_url}{endpoint}", json=data, headers=headers)
            elif method == "DELETE":
                response = requests.delete(f"{base_url}{endpoint}", headers=headers)
            
            if 200 <= response.status_code < 300:
                print(f"   ✅ {description}: SUCCESS")
            else:
                print(f"   ❌ {description}: FAILED ({response.status_code})")
                
        except Exception as e:
            print(f"   ❌ {description}: ERROR - {e}")
    
    print("\n" + "=" * 50)
    print("🎯 AUTHENTICATION SUMMARY:")
    print("• Unprotected endpoints work without API key")
    print("• Protected endpoints require X-API-Key header")
    print("• Invalid/missing API keys are rejected with 401")
    print("• Valid API key grants access to all protected endpoints")
    
    # Additional demonstration: Event submission after user configuration
    print("\n6. Testing EVENT SUBMISSION after user configuration:")
    try:
        # First configure a test user (requires API key)
        headers = {"X-API-Key": api_key}
        user_data = {"user_id": "demo_user", "max_privilege": "USER"}
        response = requests.post(f"{base_url}/config/users", json=user_data, headers=headers)
        
        if response.status_code == 200:
            print("✅ SUCCESS: Test user 'demo_user' configured")
            
            # Now submit an event for this user (no API key needed for event submission)
            event_data = {
                "event_name": "login_attempt",
                "user_role": "USER",
                "user_id": "demo_user",
                "source_id": "192.168.1.200",
                "context": {"success": True, "demo": True}
            }
            
            event_response = requests.post(f"{base_url}/events", json=event_data)
            if event_response.status_code == 200:
                print("✅ SUCCESS: Event submitted successfully for configured user")
                print("   This demonstrates the workflow: configure users (auth required) → submit events (no auth)")
            else:
                print(f"❌ FAILED: Event submission failed ({event_response.status_code})")
        else:
            print(f"❌ FAILED: User configuration failed ({response.status_code})")
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    print("\n🔐 Protected endpoints:")
    print("  - /status/clear")
    print("  - /config/* (users, devices, commands, stats)")
    print("  - /logs/attacks")
    print("  - /system/shutdown")
    print("\n🌐 Public endpoints:")
    print("  - / (root)")
    print("  - /health")
    print("  - /status (GET)")
    print("  - /events (POST)")
    print("\n💡 Best Practice Workflow:")
    print("  1. Configure users/devices using protected endpoints (requires API key)")
    print("  2. IoT devices submit events using public /events endpoint (no API key)")
    print("  3. Monitor system status and retrieve logs using protected endpoints")


if __name__ == "__main__":
    test_api_authentication() 