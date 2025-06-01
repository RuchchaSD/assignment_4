# IoT Attack Detection System

## 1. Introduction and Approach

This project implements a comprehensive IoT security monitoring system designed to detect and prevent cyber attacks in smart home environments. Our approach focuses on real-time threat detection using a multi-layered architecture that combines:

- **Thread-per-device isolation**: Each IoT device gets its own processing queue and worker thread
- **Sliding window algorithms**: Time-based analysis for detecting patterns like brute force attacks
- **Rule-based detection engine**: 22 distinct security rules covering various attack vectors
- **RESTful API interface**: Allows IoT devices to report events via standard HTTP protocols
- **Role-based access control**: Different privilege levels (USER, MANAGER, ADMIN) with appropriate exemptions

The system is designed to handle the unique challenges of IoT security:
- Limited computational resources on IoT devices
- Need for centralized security monitoring
- Real-time attack detection and response
- Scalability to handle multiple devices simultaneously

## 2. Project Structure and Setup

### Project Structure
```
attack-detection-system/
├── src/
│   ├── detector/              # Core detection engine
│   │   ├── __init__.py        # Package initialization
│   │   ├── attack_detector.py # Main detection logic
│   │   ├── rules.py          # Security rules engine
│   │   ├── event.py          # Event data models
│   │   ├── log_writer.py     # Logging system
│   │   └── instrumentation.py # System instrumentation
│   └── api/                  # REST API components
│       ├── __init__.py       # Package initialization
│       └── server.py         # FastAPI server
├── examples/                 # Usage examples
│   ├── device_client_example.py # IoT device simulation
│   └── api_auth_demo.py     # Authentication demo
├── tests/                   # Test suites
│   ├── test_example_usage.py # Core detector tests
│   └── test_api.py          # API integration tests
├── logs/                    # Generated log files
└── README.md               # This file
```

### Project Setup
```bash
# Install dependencies
pip install fastapi uvicorn requests pydantic

# Create logs directory
mkdir -p logs

# Start the API server
python -m src.api.server

# In another terminal, run examples
python examples/device_client_example.py
python examples/api_auth_demo.py

# Run tests
python tests/test_example_usage.py
python tests/test_api.py
```

## 3. System Architecture

### Central Attack Detector Design

The system uses a singleton pattern with thread-per-device architecture for maximum isolation and scalability:

```python
# From src/detector/attack_detector.py
class AttackDetector:
    """
    Singleton attack detection engine with thread-per-device architecture.
    
    This class manages:
    - Shared dictionaries for verified users/devices (thread-safe)
    - Per-device processing queues and worker threads
    - Global suspicious activity flag
    - Centralized logging for all events
    """
    
    def _get_device_worker(self, device_ip: str) -> None:
        """Worker thread function for processing events from a specific device."""
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
                
                # Log the result with event context
                self._log_writer.write(verdict, event)
                
                # Mark task as done
                device_queue.task_done()
```

### IoT Device Communication Options

IoT devices can communicate with the attack detector through two main approaches:

#### Option 1: Direct HTTP API Calls

```python
# From examples/device_client_example.py
class IoTDevice:
    """Example IoT device that reports security events."""
    
    def report_event(self, event_name: str, user_id: str, user_role: str, 
                    context: Dict[str, Any] = None) -> bool:
        """Report a security event to the attack detection system."""
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
```

#### Option 2: Authenticated Configuration

```python
# From examples/api_auth_demo.py
# Protected endpoints require API key authentication
headers = {"X-API-Key": api_key}

# Configure users (requires authentication)
user_data = {"user_id": "alice", "max_privilege": "USER"}
response = requests.post(
    "http://localhost:8000/config/users", 
    json=user_data, 
    headers=headers
)

# Submit events (no authentication required)
event_data = {
    "event_name": "login_attempt",
    "user_role": "USER",
    "user_id": "alice",
    "source_id": "192.168.1.100",
    "context": {"success": False}
}
response = requests.post("http://localhost:8000/events", json=event_data)
```

## 4. Rules Evaluation and Logging

### Security Rules Engine

The system implements 22 security detection rules across multiple categories:

```python
# From src/detector/rules.py
class AttackRules:
    """Core security rules engine for detecting various attack patterns."""
    
    def _detect_brute_force(self, event) -> Optional[Verdict]:
        """Detect brute force login attacks."""
        if (event.event_name == "login_attempt" and 
            not event.context.get("success", True)):
            
            window = self.failed_logins[event.user_id]
            window.append(event.timestamp)
            self._clean_sliding_window(window, event.timestamp, 
                                     DetectionConfig.FAILED_LOGIN_WINDOW)
            
            if len(window) > DetectionConfig.FAILED_LOGIN_LIMIT:
                self.suspicious_flag.set()
                return Verdict(True, "BRUTE_FORCE_LOGIN", {
                    "user": event.user_id,
                    "attempts": len(window)
                })
        return None
    
    def _detect_resource_abuse(self, event) -> Optional[Verdict]:
        """Detect system resource exhaustion attacks."""
        if event.event_name == "system_resource_usage":
            window = self.resource_usage[event.source_id]
            window.append((usage, event.timestamp))
            
            # Clean old entries
            self._clean_sliding_window(window, event.timestamp,
                                     DetectionConfig.RESOURCE_WINDOW)
            
            # Check for sustained high usage
            if (len(window) >= DetectionConfig.RESOURCE_WINDOW.seconds and
                all(usage >= DetectionConfig.RESOURCE_HIGH_USAGE 
                    for usage, _ in window)):
                self.suspicious_flag.set()
                return Verdict(True, "RESOURCE_EXHAUSTION", {
                    "device": self.known_devices.get(event.source_id, "unknown"),
                    "duration_seconds": len(window),
                    "avg_usage": round(sum(u for u, _ in window) / len(window), 3)
                })
```

### Dual Logging System

```python
# From src/detector/log_writer.py
class LogWriter:
    """Handles dual-purpose logging for the attack detection system."""
    
    def write(self, verdict, event=None) -> None:
        """Write verdict to appropriate logs based on severity."""
        # Create structured record for JSON logging
        record: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "rule": verdict.rule_hit,
            "alert": verdict.suspicious,
            **verdict.detail
        }
        
        # Log all events to run.log with appropriate levels
        if verdict.suspicious:
            # Critical security alerts - make them very visible
            logging.warning(f"[SECURITY ALERT] {verdict.rule_hit}: {verdict.detail}")
        elif verdict.rule_hit:
            # Notable events (unknown users, validation issues, etc.)
            logging.info(f"[NOTICE] {verdict.rule_hit}: {verdict.detail}")
        else:
            # Normal operational events
            logging.debug(f"[NORMAL] {event_summary}")
        
        # Only write suspicious events to JSON log for analysis
        if verdict.suspicious:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")  # NDJSON format
```

### Integration with Attack Detector

```python
# From src/detector/attack_detector.py
def _get_device_worker(self, device_ip: str) -> None:
    """Worker thread processes events and logs results."""
    while not self._shutdown_event.is_set():
        try:
            event = device_queue.get(timeout=0.1)
            
            # Process event through rules engine
            verdict = rules.evaluate(event)
            
            # Log the result with event context
            self._log_writer.write(verdict, event)
            
            device_queue.task_done()
```

## 5. FastAPI Implementation

### API Server Architecture

```python
# From src/api/server.py
app = FastAPI(
    title="Attack Detection API",
    description="REST API for IoT Security Event Processing and Attack Detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# API Key Authentication
API_KEY = "secret-api-key-12345"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_api_key(api_key: str = Depends(api_key_header)):
    """Dependency to validate API key for protected endpoints."""
    if api_key != API_KEY:
        raise HTTPException(
            status_code=401, 
            detail="Invalid API key. Use header: X-API-Key: secret-api-key-12345"
        )
    return api_key
```

### Event Submission Endpoint

```python
# From src/api/server.py
@app.post("/events")
async def submit_event(event_request: EventRequest, background_tasks: BackgroundTasks):
    """Submit a security event for analysis."""
    try:
        # Create Event object
        event = Event(
            event_name=event_request.event_name,
            user_role=event_request.user_role,
            user_id=event_request.user_id,
            source_id=event_request.source_id,
            timestamp=datetime.utcnow(),
            context=event_request.context
        )
        
        # Submit to detector (non-blocking)
        detector.handle_event(event)
        server_stats["events_processed"] += 1
        
        return {
            "status": "accepted",
            "message": "Event queued for processing",
            "event_id": f"{event.source_id}_{server_stats['events_processed']}",
            "timestamp": event.timestamp.isoformat()
        }
```

### Authentication Demonstration

```python
# From examples/api_auth_demo.py
# Test protected endpoint without API key (should fail)
response = requests.get(f"{base_url}/config/stats")
if response.status_code == 401:
    print("✅ SUCCESS: Correctly rejected unauthorized request")

# Test with correct API key (should work)
headers = {"X-API-Key": api_key}
response = requests.get(f"{base_url}/config/stats", headers=headers)
if response.status_code == 200:
    print("✅ SUCCESS: Access granted with valid API key")
    data = response.json()
    print(f"   Users configured: {data['users_configured']}")
```

### API Testing

```python
# From tests/test_api.py
class AttackDetectionAPITester:
    """Comprehensive API testing client."""
    
    def submit_event(self, event_name: str, user_id: str, user_role: str, 
                    source_id: str, context: Dict[str, Any] = None) -> bool:
        """Submit an event via the API."""
        event_data = {
            "event_name": event_name,
            "user_role": user_role,
            "user_id": user_id,
            "source_id": source_id,
            "context": context
        }
        
        try:
            response = self.session.post(f"{self.base_url}/events", json=event_data, timeout=5)
            return response.status_code == 200
        except:
            return False
```

## 6. Testing and Results

### Comprehensive Test Coverage

The project includes two main test suites that verify all 22 security detection rules:

#### Core Detector Tests

```python
# From tests/test_example_usage.py
def main():
    print("COMPREHENSIVE ATTACK DETECTOR TEST SUITE")
    
    # Test brute force detection
    for i in range(6):
        send("login_attempt", "eve", "USER", "192.168.0.20", 100 + i * 5,
             {"success": False})
    expect_with_sync("Failed login burst", True)
    
    # Test resource abuse
    for i in range(95):  # Extended high usage
        send("system_resource_usage", "alice", "USER", "192.168.0.30",
             800 + i, {"usage": 0.85})
    expect_with_sync("System resource abuse", True)
```

#### API Integration Tests

```python
# From tests/test_api.py
def run_all_tests(self):
    """Run the complete test suite combining all detection tests + API tests."""
    # Test all 22 security rules via HTTP API
    self.submit_event("login_attempt", "alice", "USER", "11.22.33.44", {"success": True})
    self.expect_result("Non-LAN IP address", True)
    
    # Test API functionality
    response = self.session.get(f"{self.base_url}/config/stats", headers=self.auth_headers)
    if response.status_code == 200:
        print(f"Configuration stats -> PASS (Users: {users_count}, Devices: {devices_count})")
```

### Test Results

Both test suites achieve 100% success rate:

- **Core Detector Tests**: 22/22 tests PASS
- **API Integration Tests**: 24/24 tests PASS

Sample attack detection log showing various detected threats:

```json
// From logs/attack_detection.log
{"timestamp": "2025-06-01T12:57:33.365979", "rule": "NON_LAN_ACCESS", "alert": true, "ip": "11.22.33.44"}
{"timestamp": "2025-06-01T12:57:35.901499", "rule": "BRUTE_FORCE_LOGIN", "alert": true, "user": "eve", "attempts": 6}
{"timestamp": "2025-06-01T12:57:36.321927", "rule": "COMMAND_INJECTION", "alert": true, "command": "shutdown", "user": "eve", "count": 4}
{"timestamp": "2025-06-01T12:57:39.168817", "rule": "POWER_ANOMALY", "alert": true, "device": "hvac", "current_value": 80.0, "baseline_mean": 30.0, "spike_ratio": 2.67}
{"timestamp": "2025-06-01T12:57:40.573734", "rule": "RESOURCE_EXHAUSTION", "alert": true, "device": "hvac", "duration_seconds": 90, "avg_usage": 0.85}
```

## 7. Setup Guide for IoT Devices

### Step 1: Start the API Server

```bash
python -m src.api.server
```

The server will start on `http://localhost:8000` with endpoints:
- API Documentation: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

### Step 2: Configure Users and Devices

```python
# From examples/api_auth_demo.py
# Configure users (requires API key)
api_key = "secret-api-key-12345"
auth_headers = {"X-API-Key": api_key}

users_to_configure = [
    ("alice", "USER"),
    ("system", "USER"), 
    ("admin", "ADMIN")
]

for user_id, privilege in users_to_configure:
    user_data = {"user_id": user_id, "max_privilege": privilege}
    response = requests.post(
        "http://localhost:8000/config/users",
        json=user_data,
        headers=auth_headers
    )
```

### Step 3: IoT Device Integration

```python
# From examples/device_client_example.py
# Create IoT device instance
thermostat = IoTDevice("192.168.1.101", "smart_thermostat")

# Report normal operations
thermostat.report_event("login_attempt", "alice", "USER", {"success": True})
thermostat.report_event("temperature_change", "alice", "USER", {"old_temp": 20, "new_temp": 22})
thermostat.report_event("power_consumption", "system", "USER", {"percent": 35})

# Check security status
status = thermostat.check_security_status()
if status['suspicious_activity']:
    print("🚨 ALERT: Suspicious activity detected!")
```

### Step 4: Monitor Security Status

```python
# Check system status (no authentication required)
response = requests.get("http://localhost:8000/status")
status = response.json()
print(f"Suspicious: {status['suspicious_activity']}")
print(f"Events Processed: {status['total_events_processed']}")

# Get attack logs (requires authentication)
headers = {"X-API-Key": "secret-api-key-12345"}
response = requests.get("http://localhost:8000/logs/attacks", headers=headers)
attacks = response.json()["attacks"]
```

### Best Practice Workflow

1. **Initial Setup** (one-time, requires API key):
   - Configure all users with appropriate privileges
   - Register all IoT devices with their types
   - Set up dangerous command lists

2. **Runtime Operation** (continuous, no API key needed):
   - IoT devices report events to `/events` endpoint
   - Events are automatically queued and processed
   - Suspicious activities trigger alerts

3. **Monitoring** (periodic, requires API key for detailed logs):
   - Check `/status` for quick suspicious activity check
   - Review `/logs/attacks` for detailed attack analysis
   - Use `/config/stats` to verify system configuration

## Conclusion

This IoT Attack Detection System provides a robust, scalable solution for securing smart home environments. The combination of thread-per-device isolation, comprehensive detection rules, and RESTful API interface makes it suitable for real-world IoT deployments. The system successfully detects various attack patterns while maintaining high performance and reliability.