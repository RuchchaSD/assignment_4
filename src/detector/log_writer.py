# src/detector/log_writer.py
"""
Logging system for the attack detection framework.

This module provides structured logging capabilities that separate
complete activity logs from security alerts.
"""

import json
import logging
import pathlib
from datetime import datetime
from typing import Any, Dict


class LogWriter:
    """
    Handles dual-purpose logging for the attack detection system.
    
    This class manages two types of logs:
    1. Complete activity log (run.log) - All events and activities
    2. Attack detection log (JSON) - Only suspicious events for analysis
    
    The logging strategy ensures that:
    - SOC operators see actionable alerts in run.log
    - Complete audit trail is preserved in JSON format
    - No log spam from normal operations
    - Structured data for automated analysis
    
    Attributes:
        path: Path to the JSON attack detection log file
        
    Example:
        >>> writer = LogWriter("logs/attacks.log")
        >>> verdict = Verdict(True, "FAILED_LOGIN_BURST", {"user": "eve"})
        >>> writer.write(verdict)
    """
    
    def __init__(self, path: str) -> None:
        """
        Initialize the LogWriter with specified paths.
        
        Args:
            path: File path for the JSON attack detection log
            
        Note:
            The run.log path is fixed at "logs/run.log"
            Creates necessary directories if they don't exist
        """
        # Ensure log directory exists
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        
        # Configure logging to capture all activity levels
        logging.basicConfig(
            level=logging.DEBUG,
            filename="logs/run.log",
            format="%(asctime)s %(levelname)s %(message)s",
            filemode='a'  # Append mode
        )
        
    def write(self, verdict) -> None:
        """
        Write verdict to appropriate logs based on severity.
        
        Logging strategy:
        - All events go to run.log (complete activity audit)
        - Only suspicious events go to JSON log (SOC analysis)
        - Different log levels for different event types
        
        Args:
            verdict: Verdict object containing detection results
        """
        # Create structured record for JSON logging
        record: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "rule": verdict.rule_hit,
            "alert": verdict.suspicious,
            **verdict.detail
        }
        
        # Log all events to run.log with appropriate levels
        if verdict.suspicious:
            # Critical security alerts
            logging.warning(f"ALERT {verdict.rule_hit}: {verdict.detail}")
        elif verdict.rule_hit:
            # Notable events (unknown users, validation issues, etc.)
            logging.info(f"INFO {verdict.rule_hit}: {verdict.detail}")
        else:
            # Normal operational events
            logging.debug(f"NORMAL: {verdict.detail}")
        
        # Only write suspicious events to JSON log for analysis
        if verdict.suspicious:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")  # NDJSON format
            except IOError as e:
                logging.error(f"Failed to write attack log: {e}")
                
    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about logged events.
        
        Returns:
            Dictionary with counts of different event types
        """
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
            stats = {
                "total_alerts": len(lines),
                "unique_rules": len(set(
                    json.loads(line).get("rule", "unknown")
                    for line in lines if line.strip()
                ))
            }
            return stats
        except (IOError, json.JSONDecodeError):
            return {"total_alerts": 0, "unique_rules": 0}
