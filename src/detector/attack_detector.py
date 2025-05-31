# src/detector/attack_detector.py
import threading, queue, logging
from typing import Dict, Set
from .rules import AttackRules, Verdict
from .event import Event
from .log_writer import LogWriter

class AttackDetector:
    def __init__(self,
                    verified_users: Dict[str, str] | None = None,
                    known_devices: Dict[str, str] | None = None,
                    exploitable_cmds: Set[str] | None = None,
                    log_path: str = "logs/attack_detection.log"):
        self.verified_users = verified_users or {}
        self.known_devices = known_devices or {}
        self.exploitable_cmds = exploitable_cmds or set()
        self.suspicious_flag = threading.Event()
        
        # Initialize log writer
        self.log_writer = LogWriter(log_path)

        self._device_queues: Dict[str, queue.Queue] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    # ------- public updaters -------------------------------------------
    def update_user(self, user_id, role):         # role = MAX privilege
        with self._lock:
            self.verified_users[user_id] = role

    def update_device(self, ip, dtype):
        with self._lock:
            self.known_devices[ip] = dtype

    def update_command_list(self, cmd_set):
        with self._lock:
            self.exploitable_cmds = cmd_set

    # ------- entry point ------------------------------------------------
    def handle_event(self, ev: Event):
        q = self._device_queues.get(ev.source_id)
        if q is None:
            q = queue.Queue()
            self._device_queues[ev.source_id] = q
            t = threading.Thread(target=self._worker,
                                args=(ev.source_id, q),
                                daemon=True)
            self._threads[ev.source_id] = t
            t.start()
        q.put(ev)

    # ------- worker loop per device ------------------------------------
    def _worker(self, ip, q: queue.Queue):
        rules = AttackRules(self.verified_users,
                            self.known_devices,
                            self.exploitable_cmds,
                            self.suspicious_flag)
        while True:
            ev = q.get()
            verdict: Verdict = rules.evaluate(ev)
            
            # Write to log (LogWriter handles selective console logging)
            self.log_writer.write(verdict)
                
            q.task_done()
