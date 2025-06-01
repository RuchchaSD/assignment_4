#!/usr/bin/env python3
"""
Automated test runner for the Attack Detection API.

This script automatically:
1. Starts the FastAPI server in the background
2. Waits for it to be ready
3. Runs the comprehensive test suite
4. Stops the server and reports results

Usage:
    python run_api_tests.py
    
Requirements:
    - FastAPI, uvicorn, requests packages
    - All source files in place
"""

import os
import sys
import time
import signal
import requests
import subprocess
from pathlib import Path


class APITestRunner:
    """Automated test runner for the Attack Detection API."""
    
    def __init__(self):
        """Initialize the test runner."""
        self.server_process = None
        self.base_url = "http://localhost:8000"
        self.max_startup_wait = 30  # seconds
        
    def check_dependencies(self) -> bool:
        """Check if required dependencies are available."""
        try:
            import fastapi
            import uvicorn
            import requests
            import src.detector
            print("✅ All required dependencies are available")
            return True
        except ImportError as e:
            print(f"❌ Missing dependency: {e}")
            print("   Please install with: pip install fastapi uvicorn requests")
            return False
    
    def clean_logs(self) -> None:
        """Clean up old log files before starting."""
        log_dir = Path("logs")
        if log_dir.exists():
            for log_file in log_dir.glob("*.log"):
                try:
                    log_file.unlink()
                    print(f"🧹 Cleaned {log_file}")
                except:
                    pass
        else:
            log_dir.mkdir(exist_ok=True)
    
    def start_server(self) -> bool:
        """Start the FastAPI server in the background."""
        print("🚀 Starting API server...")
        
        try:
            # Start server as subprocess
            self.server_process = subprocess.Popen(
                [sys.executable, "api_server.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
            
            # Wait for server to be ready
            start_time = time.time()
            while time.time() - start_time < self.max_startup_wait:
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=1)
                    if response.status_code == 200:
                        print(f"✅ API server is ready (took {time.time() - start_time:.1f}s)")
                        return True
                except:
                    time.sleep(0.5)
            
            print(f"❌ API server failed to start within {self.max_startup_wait}s")
            return False
            
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return False
    
    def stop_server(self) -> None:
        """Stop the API server gracefully."""
        if self.server_process:
            print("🛑 Stopping API server...")
            
            try:
                # Try graceful shutdown first
                requests.delete(f"{self.base_url}/system/shutdown", timeout=5)
                time.sleep(2)
            except:
                pass
            
            # Force terminate if still running
            if self.server_process.poll() is None:
                if os.name == 'nt':
                    # Windows
                    self.server_process.terminate()
                else:
                    # Unix-like
                    os.killpg(os.getpgid(self.server_process.pid), signal.SIGTERM)
                
                # Wait for process to end
                try:
                    self.server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.server_process.kill()
            
            print("✅ API server stopped")
    
    def run_tests(self) -> bool:
        """Run the API test suite."""
        print("🧪 Running API test suite...")
        
        try:
            # Import and run the test module
            from test_api import run_api_tests
            return run_api_tests()
        except Exception as e:
            print(f"❌ Test execution failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def generate_report(self, test_success: bool, start_time: float) -> None:
        """Generate a summary report of the test run."""
        duration = time.time() - start_time
        
        print("\n" + "=" * 70)
        print("AUTOMATED API TEST REPORT")
        print("=" * 70)
        
        print(f"⏱️  Total Duration: {duration:.1f} seconds")
        print(f"🎯 Test Result: {'SUCCESS' if test_success else 'FAILURE'}")
        
        # Log file information
        log_files = ["logs/run.log", "logs/attack_detection.log"]
        for log_file in log_files:
            if Path(log_file).exists():
                size = Path(log_file).stat().st_size
                print(f"📁 {log_file}: {size} bytes")
        
        # Server logs if available
        if self.server_process and self.server_process.stdout:
            print("📡 Server output available in process logs")
        
        print("=" * 70)
        
        return test_success
    
    def run(self) -> bool:
        """Run the complete automated test suite."""
        start_time = time.time()
        test_success = False
        
        print("🤖 AUTOMATED API TEST RUNNER")
        print("=" * 70)
        
        try:
            # Step 1: Check dependencies
            if not self.check_dependencies():
                return False
            
            # Step 2: Clean up old logs
            self.clean_logs()
            
            # Step 3: Start the server
            if not self.start_server():
                return False
            
            # Step 4: Run tests
            test_success = self.run_tests()
            
        except KeyboardInterrupt:
            print("\n⚠️  Test run interrupted by user")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Step 5: Always stop the server
            self.stop_server()
            
            # Step 6: Generate report
            self.generate_report(test_success, start_time)
        
        return test_success


def main():
    """Main entry point for the automated test runner."""
    runner = APITestRunner()
    success = runner.run()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 