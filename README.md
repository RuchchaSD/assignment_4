# Attack Detector - Singleton Architecture

This project implements a thread-safe, singleton-based attack detection system that processes security events asynchronously.

## Architecture Overview

### Key Components

1. **AttackDetector (Singleton)**: The main detection engine that processes events asynchronously
2. **AttackRules**: Contains the logic for evaluating different types of attacks
3. **LogWriter**: Handles logging of suspicious activities
4. **Event**: Data class representing a security event

### Thread-Safe Design

The new architecture uses:
- **Singleton Pattern**: Ensures only one detector instance exists globally
- **Thread-Safe Queue**: Events are queued for processing without blocking the calling thread
- **Worker Thread**: A dedicated background thread processes events asynchronously
- **Graceful Shutdown**: Proper cleanup and event processing completion

## Usage

### Basic Usage

```python
from src.detector import instrument, get_detector
from datetime import datetime

# Log a security event (non-blocking)
instrument(
    event_name="login_attempt",
    user_role="USER",
    user_id="alice", 
    source_id="192.168.1.100",
    ts=datetime.now(),
    ctx={"success": False}
)

# Get the detector instance
detector = get_detector()
print(f"Events in queue: {detector.get_queue_size()}")
```

### Advanced Usage

```python
from src.detector import AttackDetector

# Get singleton instance
detector = AttackDetector()

# Use the detector directly
detector.instrument(
    event_name="toggle_device",
    user_role="USER",
    user_id="bob",
    source_id="device_123", 
    ts=datetime.now(),
    ctx={"device": "smart_lock"}
)

# Graceful shutdown (waits for all events to be processed)
detector.shutdown()
```

## Supported Attack Types

1. **FAILED_LOGIN_BURST**: Too many failed login attempts in a short time
2. **TOGGLE_SPAM**: Excessive device toggling by non-admin users
3. **GEO_IMPOSSIBLE**: Impossible travel between geographic locations
4. **SYN_FLOOD**: High rate of SYN packets detected
5. **MOTION_AFTER_HOURS**: Camera motion detected outside business hours

## Event Types

- `login_attempt`: User login events
- `toggle_device`: Device state changes
- `packet_syn`: Network SYN packet events
- `camera_motion`: Motion detection events

## Configuration

The detector uses these default thresholds:
- Failed login limit: 5 attempts in 60 seconds
- Device toggle limit: 10 toggles in 30 seconds
- Impossible travel: >300km in <5 minutes
- SYN flood: >100 packets/second
- After-hours: Outside 8 AM - 8 PM

## Output

Suspicious activities are logged to:
- `logs/suspicious.jsonl`: NDJSON format with event details
- `logs/run.log`: General application logs

## Running the Example

```bash
python example_usage.py
```

This will demonstrate:
- Singleton pattern verification
- Thread-safe event processing
- Various attack simulations
- Graceful shutdown

## Benefits of New Architecture

1. **Non-blocking**: Event logging doesn't block the calling thread
2. **Thread-safe**: Multiple threads can safely log events simultaneously  
3. **Scalable**: Events are processed asynchronously in the background
4. **Reliable**: Proper error handling and graceful shutdown
5. **Maintainable**: Clean separation of concerns with singleton pattern 