#!/usr/bin/env python3
"""
FastAPI REST API server for the Attack Detection System.

This server exposes the attack detector functionality through HTTP endpoints,
allowing IoT devices and smart home components to report security events
and check for suspicious activity.

Key Features:
- Event submission endpoint for devices
- Suspicious activity status checking
- Configuration management (users, devices, commands)
- Health monitoring and statistics
- LAN-only access with proper CORS handling

Usage:
    python api_server.py
    
Then devices can POST events to: http://192.168.x.x:8000/events
"""

import asyncio
import uvicorn
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.detector import detector, Event


# =============================================================================
# Pydantic Models for API Request/Response
# =============================================================================

class EventRequest(BaseModel):
    """Request model for submitting security events."""
    event_name: str = Field(..., description="Type of security event")
    user_role: str = Field(..., description="Role of the user triggering the event")
    user_id: str = Field(..., description="Unique identifier for the user")
    source_id: str = Field(..., description="IP address of the source device")
    context: Dict = Field(default={}, description="Additional event context")
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_name": "login_attempt",
                "user_role": "USER",
                "user_id": "alice",
                "source_id": "192.168.1.100",
                "context": {"success": False}
            }
        }

class UserRequest(BaseModel):
    """Request model for user configuration."""
    user_id: str = Field(..., description="Unique user identifier")
    max_privilege: str = Field(..., description="Maximum privilege level", pattern="^(ADMIN|MANAGER|USER)$")

class DeviceRequest(BaseModel):
    """Request model for device registration."""
    device_ip: str = Field(..., description="Device IP address")
    device_type: str = Field(..., description="Type/description of device")

class CommandsRequest(BaseModel):
    """Request model for updating dangerous commands list."""
    commands: List[str] = Field(..., description="List of dangerous commands to monitor")

class StatusResponse(BaseModel):
    """Response model for system status."""
    suspicious_activity: bool = Field(..., description="Whether suspicious activity is detected")
    total_events_processed: int = Field(..., description="Total number of events processed")
    queue_sizes: Dict[str, int] = Field(..., description="Queue sizes per device")
    uptime_seconds: float = Field(..., description="Server uptime in seconds")

class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str = Field(..., description="Server health status")
    timestamp: str = Field(..., description="Current server timestamp")
    version: str = Field(..., description="API version")
    uptime_seconds: float = Field(..., description="Server uptime in seconds")


# =============================================================================
# FastAPI Application Setup
# =============================================================================

app = FastAPI(
    title="Attack Detection API",
    description="REST API for IoT Security Event Processing and Attack Detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for LAN access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://192.168.*", "http://10.*", "http://172.*"],  # LAN networks
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Global statistics
server_stats = {
    "start_time": datetime.utcnow(),
    "events_processed": 0,
    "api_calls": 0
}


# =============================================================================
# API Endpoints
# =============================================================================

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information."""
    return {
        "service": "Attack Detection API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for monitoring."""
    server_stats["api_calls"] += 1
    uptime = (datetime.utcnow() - server_stats["start_time"]).total_seconds()
    
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        version="1.0.0",
        uptime_seconds=uptime
    )

@app.post("/events")
async def submit_event(event_request: EventRequest, background_tasks: BackgroundTasks):
    """
    Submit a security event for analysis.
    
    This endpoint accepts security events from IoT devices and queues them
    for processing by the attack detection engine.
    """
    server_stats["api_calls"] += 1
    
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
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid event data: {str(e)}")

@app.get("/status", response_model=StatusResponse)
async def get_status():
    """
    Get current system status including suspicious activity detection.
    
    Returns information about whether any suspicious activity has been
    detected and current system statistics.
    """
    server_stats["api_calls"] += 1
    
    # Get queue sizes for all devices
    queue_sizes = {}
    if hasattr(detector, '_device_queues'):
        queue_sizes = {
            device_ip: queue.qsize() 
            for device_ip, queue in detector._device_queues.items()
        }
    
    uptime = (datetime.utcnow() - server_stats["start_time"]).total_seconds()
    
    return StatusResponse(
        suspicious_activity=detector.suspicious_flag.is_set(),
        total_events_processed=server_stats["events_processed"],
        queue_sizes=queue_sizes,
        uptime_seconds=uptime
    )

@app.post("/status/clear")
async def clear_suspicious_flag():
    """Clear the suspicious activity flag."""
    server_stats["api_calls"] += 1
    detector.suspicious_flag.clear()
    return {"status": "cleared", "message": "Suspicious activity flag cleared"}

@app.post("/config/users")
async def add_user(user_request: UserRequest):
    """Add or update a user in the system."""
    server_stats["api_calls"] += 1
    
    detector.update_user(user_request.user_id, user_request.max_privilege)
    
    return {
        "status": "success",
        "message": f"User {user_request.user_id} configured with {user_request.max_privilege} privilege"
    }

@app.post("/config/devices")
async def add_device(device_request: DeviceRequest):
    """Register a device in the system."""
    server_stats["api_calls"] += 1
    
    detector.update_device(device_request.device_ip, device_request.device_type)
    
    return {
        "status": "success", 
        "message": f"Device {device_request.device_ip} registered as {device_request.device_type}"
    }

@app.post("/config/commands")
async def update_commands(commands_request: CommandsRequest):
    """Update the list of dangerous commands to monitor."""
    server_stats["api_calls"] += 1
    
    detector.update_command_list(set(commands_request.commands))
    
    return {
        "status": "success",
        "message": f"Updated dangerous commands list with {len(commands_request.commands)} commands"
    }

@app.get("/config/stats")
async def get_configuration_stats():
    """Get statistics about current system configuration."""
    server_stats["api_calls"] += 1
    
    stats = {
        "users_configured": len(getattr(detector, '_verified_users', {})),
        "devices_registered": len(getattr(detector, '_known_devices', {})),
        "dangerous_commands": len(getattr(detector, '_exploitable_commands', set())),
        "active_device_queues": len(getattr(detector, '_device_queues', {})),
        "server_stats": server_stats
    }
    
    return stats

@app.get("/logs/attacks")
async def get_attack_logs(limit: int = 50):
    """Get recent attack detection logs."""
    server_stats["api_calls"] += 1
    
    try:
        import json
        attacks = []
        with open("logs/attack_detection.log", "r") as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                if line.strip():
                    attacks.append(json.loads(line.strip()))
        
        return {
            "attacks": attacks,
            "total_returned": len(attacks)
        }
    except FileNotFoundError:
        return {"attacks": [], "total_returned": 0}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading logs: {str(e)}")

@app.delete("/system/shutdown")
async def shutdown_system():
    """Gracefully shutdown the detection system."""
    server_stats["api_calls"] += 1
    
    success = detector.shutdown(timeout=10.0)
    
    return {
        "status": "shutdown" if success else "timeout",
        "message": "System shutdown completed" if success else "Shutdown timeout - some workers may still be running"
    }


# =============================================================================
# Server Startup
# =============================================================================

if __name__ == "__main__":
    print("🚀 Starting Attack Detection API Server...")
    print("📡 Accessible to LAN devices on port 8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 Health Check: http://localhost:8000/health")
    
    # Configure uvicorn to bind to all LAN interfaces
    uvicorn.run(
        app,
        host="0.0.0.0",  # Listen on all interfaces for LAN access
        port=8000,
        log_level="info",
        access_log=True
    ) 