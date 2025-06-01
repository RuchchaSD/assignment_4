# Attack Detection System

A comprehensive, thread-safe cybersecurity monitoring framework designed for smart home and IoT environments. This system provides real-time attack detection, threat analysis, and structured logging with a focus on performance and scalability.

## 🏗️ Architecture Overview

### Core Components

- **AttackDetector**: Singleton engine managing global state and per-device processing
- **AttackRules**: Security rules engine implementing detection algorithms
- **Event**: Data structure representing security events
- **LogWriter**: Dual-purpose logging system for operations and security alerts

### Key Design Features

- **Thread-per-Device Architecture**: Isolated processing queues for each device
- **Singleton Pattern**: Consistent global state management
- **LAN-Only Validation**: Network security enforcement
- **Sliding Window Analysis**: Time-based attack pattern detection
- **Role-Based Access Control**: Admin exemptions and privilege validation
- **Comprehensive Logging**: Separate operational and security alert logs

## 🚀 Quick Start

### Installation

```bash
git clone <repository-url>
cd attack-detector
pip install -r requirements.txt
```

### Basic Usage

```python
from src.detector import detector, Event
from datetime import datetime

# Configure the system
detector.update_user("alice", "USER")
detector.update_device("192.168.1.100", "thermostat")
detector.update_command_list({"shutdown", "reboot", "factory_reset"})

# Log a security event
event = Event(
    event_name="login_attempt",
    user_role="USER",
    user_id="alice",
    source_id="192.168.1.100",
    timestamp=datetime.now(),
    context={"success": False}
)

detector.handle_event(event)

# Check for alerts
if detector.suspicious_flag.is_set():
    print("🚨 Security threat detected!")
```

### Running the Test Suite

```bash
python example_usage.py
```

This comprehensive test validates all detection rules with 20 test cases covering:
- Baseline legitimate operations
- Network validation (LAN-only, IP format validation)
- User/device authentication
- Brute force attack detection
- Command injection and spam
- Power consumption anomalies
- Network attacks (SYN floods)
- Resource exhaustion
- MQTT message flooding
- Parallel threading scenarios

### Option 1: Direct Library Usage
```bash
python example_usage.py  # Run all 21 tests
```

### Option 2: REST API Usage
```bash
# Terminal 1: Start API server
python api_server.py

# Terminal 2: Run API tests  
python test_api.py       # 19 tests via HTTP
python device_client_example.py  # IoT device simulation
python api_auth_demo.py  # Authentication demonstration
```

## 🛡️ Security Detection Rules

### 1. Network Validation
- **Non-LAN Access**: Blocks external IP addresses
- **Malformed IPs**: Validates IP address format
- **Device Registration**: Tracks known/unknown devices

### 2. Authentication Security
- **Brute Force Detection**: 5+ failed logins in 60 seconds
- **Privilege Escalation**: Role validation against user profiles
- **Unknown Users**: Logs unregistered user activity

### 3. Command Security
- **Dangerous Commands**: Monitors high-risk operations
- **Command Spam**: 3+ dangerous commands in 30 seconds
- **Admin Exemptions**: Privilege-based rate limiting

### 4. Power Anomaly Detection
- **Consumption Spikes**: 150% above rolling baseline
- **Sliding Window**: 5-minute analysis window
- **Minimum Samples**: Requires 5+ readings for stability

### 5. Network Attack Detection
- **SYN Flood**: 100+ packets/second threshold
- **Multi-user Attacks**: Coordinated attack detection

### 6. Resource Protection
- **High Usage**: 80%+ sustained resource consumption
- **Exhaustion Window**: 90-second analysis period
- **Cross-device Monitoring**: System-wide resource tracking

### 7. Message Flood Protection
- **MQTT Floods**: 20,000+ messages in 100 seconds
- **Protocol Agnostic**: Adaptable to various message protocols

## 📊 Logging Strategy

The system implements a dual-logging strategy:

### Complete Activity Log (`logs/run.log`)
- **All Events**: Every system interaction
- **Multiple Levels**: DEBUG, INFO, WARNING
- **Operational Audit**: Complete activity trail
- **Format**: Human-readable with timestamps

### Security Alerts (`logs/attack_detection.log`)
- **Attacks Only**: Suspicious events exclusively
- **Structured Data**: JSON format for analysis
- **SOC Integration**: Ready for security operations
- **Automated Processing**: Machine-readable format

## 🔧 Configuration

### User Management
```python
# Add users with maximum privilege levels
detector.update_user("admin", "ADMIN")
detector.update_user("manager", "MANAGER")  
detector.update_user("alice", "USER")
```

### Device Registration
```python
# Register trusted devices
detector.update_device("192.168.1.100", "thermostat")
detector.update_device("192.168.1.101", "security_camera")
detector.update_device("192.168.1.102", "smart_lock")
```

### Command Security
```python
# Define high-risk commands
dangerous_commands = {
    "shutdown", "poweroff", "reboot", 
    "factory_reset", "format", "delete"
}
detector.update_command_list(dangerous_commands)
```

## 🧪 Testing & Validation

### Test Coverage
- **20 Comprehensive Tests**: All detection rules covered
- **Parallel Threading**: Multi-device scenario validation
- **Edge Cases**: Invalid data and boundary conditions
- **Performance**: Queue processing and synchronization

### Success Metrics
- ✅ 100% Test Pass Rate (20/20)
- ✅ 634 Total Activity Log Entries
- ✅ 50 Security Alert Detections
- ✅ Zero Race Conditions
- ✅ Complete Thread Isolation

## 📁 Project Structure

```
attack-detector/
├── src/
│   └── detector/
│       ├── __init__.py          # Package exports
│       ├── attack_detector.py   # Core detection engine
│       ├── rules.py            # Security rules implementation
│       ├── event.py            # Event data structure
│       ├── log_writer.py       # Logging system
│       └── instrumentation.py  # Global singleton access
├── logs/                       # Generated log files
├── example_usage.py           # Comprehensive test suite
├── requirements.txt           # Minimal dependencies
├── README.md                  # This documentation
└── .gitignore                # Version control exclusions
```

## 🔒 Security Considerations

### Thread Safety
- **Per-device Isolation**: Separate queues and workers
- **Shared State Protection**: Locking for user/device updates
- **Global Alert Flag**: Thread-safe event signaling

### Performance
- **Non-blocking Operations**: Asynchronous event processing
- **Memory Efficiency**: Sliding window state management
- **Scalable Architecture**: Handles multiple devices simultaneously

### Reliability
- **Graceful Shutdown**: Queue draining and thread cleanup
- **Error Handling**: Continues operation despite individual failures
- **State Persistence**: Maintains detection state across events

## 🚀 Production Deployment

### System Requirements
- **Python 3.8+**: Modern Python for type hints and dataclasses
- **Standard Library Only**: No external dependencies for core functionality
- **RAM**: Minimal overhead with sliding window efficiency
- **Storage**: Log rotation recommended for long-term deployment

### Integration Points
- **SIEM Systems**: JSON log format for security information management
- **Monitoring**: Health checks via queue size and flag status
- **Alerting**: Hook into `suspicious_flag` for real-time notifications

**Security Notice**: This system is designed for educational purposes as part of EN4720 Security in Cyber-Physical Systems (Assignment 4). It provides no security guarantees and should not be used in production environments without extensive testing and hardening.

## 🔐 API Authentication

The REST API uses **static API key authentication** to protect sensitive endpoints from unauthorized access.

### API Key: `secret-api-key-12345`

### Protected Endpoints (Require Authentication)
All configuration, logging, and administrative endpoints require the API key:

```
X-API-Key: secret-api-key-12345
```

- **POST** `/status/clear` - Clear suspicious activity flag
- **POST** `/config/users` - Add/update users
- **POST** `/config/devices` - Register devices  
- **POST** `/config/commands` - Update dangerous commands list
- **GET** `/config/stats` - Get system configuration stats
- **GET** `/logs/attacks` - Retrieve attack detection logs
- **DELETE** `/system/shutdown` - Shutdown the system

### Public Endpoints (No Authentication)
Core operational endpoints remain publicly accessible for IoT devices:

- **GET** `/` - API information
- **GET** `/health` - Health check
- **GET** `/status` - Get suspicious activity status
- **POST** `/events` - Submit security events (IoT devices)

### Usage Examples

**❌ Without API Key (Rejected):**
```bash
curl http://localhost:8000/config/stats
# Response: 401 Unauthorized
```

**✅ With API Key (Accepted):**
```bash
curl -H "X-API-Key: secret-api-key-12345" http://localhost:8000/config/stats
# Response: Configuration data
```

**✅ Python Example:**
```python
headers = {"X-API-Key": "secret-api-key-12345"}
response = requests.get("http://localhost:8000/config/stats", headers=headers)
```

### Security Benefits
- **Administrative Protection**: Configuration changes require authentication
- **Log Access Control**: Attack logs are protected from unauthorized viewing
- **System Security**: Critical operations like shutdown are authenticated
- **IoT Device Access**: Event submission remains frictionless for devices