"""
End-to-end comprehensive test for the AttackDetector / AttackRules stack.
Tests all rules + parallel threading with multiple devices.

Run:
    python example_usage.py
"""

from datetime import datetime, timedelta
import time
import threading

from src.detector.event import Event
from src.detector.instrumentation import detector   # singleton we created before

# ---------------------------------------------------------------------
# Prepare lookup tables ------------------------------------------------
detector.update_user("alice", "USER")
detector.update_user("eve",   "USER")
detector.update_user("admin", "ADMIN")
detector.update_user("manager", "MANAGER")

# Add test users for parallel testing
detector.update_user("attacker", "USER")
detector.update_user("attacker1", "USER")
detector.update_user("attacker2", "USER")
detector.update_user("attacker3", "USER")
detector.update_user("user10", "USER")
detector.update_user("user20", "USER")
detector.update_user("user30", "USER")
detector.update_user("user40", "USER")
detector.update_user("user50", "USER")

detector.update_device("192.168.0.10", "thermostat")
detector.update_device("192.168.0.20", "gateway")
detector.update_device("192.168.0.30", "hvac")
detector.update_device("192.168.0.40", "security_cam")
detector.update_device("192.168.0.50", "smart_lock")

detector.update_command_list({"shutdown", "poweroff", "reboot", "factory_reset"})

# ---------------------------------------------------------------------
# Helper ----------------------------------------------------------------
BASE = datetime.utcnow()

def send(event_name, user, role, ip, t_offset_s, ctx):
    ev = Event(
        event_name,
        role,
        user,
        ip,
        BASE + timedelta(seconds=t_offset_s),
        ctx
    )
    detector.handle_event(ev)

def send_parallel(events):
    """Send multiple events in parallel to test threading"""
    threads = []
    for event_name, user, role, ip, t_offset_s, ctx in events:
        t = threading.Thread(target=send, args=(event_name, user, role, ip, t_offset_s, ctx))
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in threads:
        t.join()

def wait_for_processing():
    """Wait for all device queues to be empty (all events processed)"""
    import time
    max_wait = 5.0  # Maximum wait time in seconds
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        # Check if all queues are empty
        all_empty = True
        for queue in detector._device_queues.values():
            if not queue.empty():
                all_empty = False
                break
        
        if all_empty:
            # Give a bit more time for final processing
            time.sleep(0.1)
            return True
            
        time.sleep(0.05)  # Short sleep before checking again
    
    # Timeout reached
    return False

def expect_with_sync(case, should_alert):
    """Expect function that waits for all processing to complete"""
    # Wait for all events to be processed
    if wait_for_processing():
        status = detector.suspicious_flag.is_set()
        result = "PASS" if status == should_alert else "FAIL"
        print(f"{case:<35} → {result}")
        detector.suspicious_flag.clear()
    else:
        print(f"{case:<35} → TIMEOUT")
        detector.suspicious_flag.clear()
    time.sleep(0.1)

print("=" * 60)
print("COMPREHENSIVE ATTACK DETECTOR TEST SUITE")
print("=" * 60)

# ---------------------------------------------------------------------
# 0  baseline sane behaviour ------------------------------------------
print("\n--- BASELINE TESTS ---")
send("login_attempt", "alice", "USER", "192.168.0.10", 0, {"success": True})
send("control_command", "alice", "USER", "192.168.0.10", 1, {"command": "light_on"})
expect_with_sync("Baseline no-alert", False)

# ---------------------------------------------------------------------
# 1  IP validation tests ----------------------------------------------
print("\n--- IP VALIDATION TESTS ---")
send("login_attempt", "alice", "USER", "11.22.33.44", 10, {"success": True})
expect_with_sync("Non-LAN IP address", True)

send("login_attempt", "alice", "USER", "invalid-ip", 20, {"success": True})
expect_with_sync("Malformed IP address", True)

# ---------------------------------------------------------------------
# 2  User/Device validation tests ------------------------------------
print("\n--- USER/DEVICE VALIDATION TESTS ---")
send("login_attempt", "alice", "USER", "192.168.99.99", 30, {"success": True})
expect_with_sync("Unknown device", False)

send("login_attempt", "unknown_user", "USER", "192.168.0.20", 40, {"success": True})
expect_with_sync("Unknown user", False)

send("login_attempt", "alice", "INVALID_ROLE", "192.168.0.10", 50, {"success": True})
expect_with_sync("Unknown role", False)

send("login_attempt", "manager", "USER", "192.168.0.10", 60, {"success": True})
expect_with_sync("Privilege escalation attempt", False)

# ---------------------------------------------------------------------
# 3  Brute force login tests -----------------------------------------
print("\n--- BRUTE FORCE TESTS ---")
for i in range(6):
    send("login_attempt", "eve", "USER", "192.168.0.20", 100 + i * 5,
         {"success": False})
expect_with_sync("Failed login burst", True)

# ---------------------------------------------------------------------
# 4  Dangerous command tests -----------------------------------------
print("\n--- COMMAND SPAM TESTS ---")
for i in range(4):
    send("control_command", "eve", "USER", "192.168.0.20", 200 + i * 5,
         {"command": "shutdown"})
expect_with_sync("Dangerous command spam (USER)", True)

for i in range(5):
    send("control_command", "admin", "ADMIN", "192.168.0.20", 300 + i * 5,
         {"command": "factory_reset"})
expect_with_sync("High-rate commands (ADMIN allowed)", False)

# ---------------------------------------------------------------------
# 5  Power consumption tests ------------------------------------------
print("\n--- POWER CONSUMPTION TESTS ---")
# Invalid power values
send("power_consumption", "alice", "USER", "192.168.0.30", 400, {"percent": -10})
expect_with_sync("Invalid power value (negative)", False)

send("power_consumption", "alice", "USER", "192.168.0.30", 405, {"percent": 150})
expect_with_sync("Invalid power value (>100%)", False)

# Power spike detection
for i in range(6):  # Build baseline
    send("power_consumption", "alice", "USER", "192.168.0.30",
         500 + i * 20, {"percent": 30})
send("power_consumption", "alice", "USER", "192.168.0.30", 620, {"percent": 80})
expect_with_sync("Power consumption spike", True)

# ---------------------------------------------------------------------
# 6  Network attack tests ---------------------------------------------
print("\n--- NETWORK ATTACK TESTS ---")
send("packet_syn", "eve", "USER", "192.168.0.20", 700,
     {"rate": 150, "multi_user": False})
expect_with_sync("SYN flood attack", True)

send("packet_syn", "attacker", "USER", "192.168.0.40", 710,
     {"rate": 200, "multi_user": True})
expect_with_sync("Multi-user SYN flood", True)

# ---------------------------------------------------------------------
# 7  Resource abuse tests --------------------------------------------
print("\n--- RESOURCE ABUSE TESTS ---")
for i in range(95):  # Extended high usage
    send("system_resource_usage", "alice", "USER", "192.168.0.30",
         800 + i, {"usage": 0.85})
expect_with_sync("System resource abuse", True)

# ---------------------------------------------------------------------
# 8  MQTT flood tests ------------------------------------------------
print("\n--- MQTT FLOOD TESTS ---")
send("10000_messages_received", "alice", "USER", "192.168.0.40", 1000, {})
expect_with_sync("MQTT message flood", True)

# ---------------------------------------------------------------------
# 9  PARALLEL THREADING TESTS ---------------------------------------
print("\n--- PARALLEL THREADING TESTS ---")

# Test 1: Simultaneous attacks from different devices
parallel_events_1 = [
    ("login_attempt", "attacker1", "USER", "192.168.0.10", 1100, {"success": False}),
    ("login_attempt", "attacker1", "USER", "192.168.0.10", 1105, {"success": False}),
    ("login_attempt", "attacker1", "USER", "192.168.0.10", 1110, {"success": False}),
    ("login_attempt", "attacker1", "USER", "192.168.0.10", 1115, {"success": False}),
    ("login_attempt", "attacker1", "USER", "192.168.0.10", 1120, {"success": False}),
    ("login_attempt", "attacker1", "USER", "192.168.0.10", 1125, {"success": False}),
    
    ("control_command", "attacker2", "USER", "192.168.0.20", 1100, {"command": "shutdown"}),
    ("control_command", "attacker2", "USER", "192.168.0.20", 1105, {"command": "shutdown"}),
    ("control_command", "attacker2", "USER", "192.168.0.20", 1110, {"command": "shutdown"}),
    ("control_command", "attacker2", "USER", "192.168.0.20", 1115, {"command": "shutdown"}),
    
    ("packet_syn", "attacker3", "USER", "192.168.0.30", 1100, {"rate": 180}),
]

send_parallel(parallel_events_1)
expect_with_sync("Parallel attacks (multi-device)", True)

# Test 2: High-frequency legitimate traffic vs attacks
parallel_events_2 = [
    # Legitimate admin activity
    ("control_command", "admin", "ADMIN", "192.168.0.40", 1200, {"command": "reboot"}),
    ("control_command", "admin", "ADMIN", "192.168.0.40", 1201, {"command": "shutdown"}),
    ("control_command", "admin", "ADMIN", "192.168.0.40", 1202, {"command": "factory_reset"}),
    
    # Simultaneous attack from different device
    ("packet_syn", "eve", "USER", "192.168.0.50", 1200, {"rate": 250}),
    
    # Normal user activity
    ("login_attempt", "alice", "USER", "192.168.0.10", 1200, {"success": True}),
    ("power_consumption", "alice", "USER", "192.168.0.30", 1200, {"percent": 45}),
]

send_parallel(parallel_events_2)
expect_with_sync("Mixed legitimate/attack traffic", True)

# Test 3: Resource exhaustion from multiple devices
resource_events = []
for device_num in range(10, 51, 10):  # 5 devices: .10, .20, .30, .40, .50
    for i in range(95):  # 95 events per device (more than 90 required)
        resource_events.append((
            "system_resource_usage", 
            f"user{device_num}", 
            "USER", 
            f"192.168.0.{device_num}", 
            1300 + i, 
            {"usage": 0.95}
        ))

send_parallel(resource_events)  # Send all events
expect_with_sync("Multi-device resource exhaustion", True)

# Test 4: Device isolation test (ensure per-device threads work)
isolation_events = [
    # Device 1: Power spikes
    ("power_consumption", "alice", "USER", "192.168.0.10", 1400, {"percent": 20}),
    ("power_consumption", "alice", "USER", "192.168.0.10", 1420, {"percent": 25}),
    ("power_consumption", "alice", "USER", "192.168.0.10", 1440, {"percent": 22}),
    ("power_consumption", "alice", "USER", "192.168.0.10", 1460, {"percent": 24}),
    ("power_consumption", "alice", "USER", "192.168.0.10", 1480, {"percent": 23}),
    ("power_consumption", "alice", "USER", "192.168.0.10", 1500, {"percent": 50}), # spike
    
    # Device 2: Login attempts (should be isolated from Device 1's power readings)
    ("login_attempt", "eve", "USER", "192.168.0.20", 1400, {"success": False}),
    ("login_attempt", "eve", "USER", "192.168.0.20", 1410, {"success": False}),
    ("login_attempt", "eve", "USER", "192.168.0.20", 1420, {"success": False}),
    ("login_attempt", "eve", "USER", "192.168.0.20", 1430, {"success": False}),
    ("login_attempt", "eve", "USER", "192.168.0.20", 1440, {"success": False}),
    ("login_attempt", "eve", "USER", "192.168.0.20", 1450, {"success": False}),
]

send_parallel(isolation_events)
expect_with_sync("Device isolation (power+login)", True)

print("\n" + "=" * 60)
print("COMPREHENSIVE TEST SUITE COMPLETED")
print("=" * 60)
print("Check logs/run.log for complete activity log")
print("Check logs/attack_detection.log for attacks only")
