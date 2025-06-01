# Cyber-Attack Detection for Smart-Home / IoT Installations  
_Milestone 4 – “Cyber-Attack Detection in a Smart-Home System” (University Project)_

<p align="center">
  <img src="docs/figures/architecture-overview.svg" width="640" alt="System architecture (placeholder)" />
</p>

> **TL;DR** – A FastAPI-based, rule-driven security layer any smart-home device can call with a single “analytics-style” snippet.  
> Fourteen detection rules, dual-channel JSON logging, and 22 fully automated tests.  
> **Python 3.11 • FastAPI • pytest**

---

## 1  Introduction & Approach  

Consumer IoT ecosystems mix dozens of low-power devices that ship with minimal
security. The goal of this semester project is to **identify and differentiate
cyber-attack attempts from authorised requests** without heavyweight ML or
external databases.  
We adopted a _lightweight, rule-based strategy_:

* Devices post JSON **`Event`** objects to a central gateway.  
* A singleton **`AttackDetector`** evaluates each event against **14 sliding-window rules**.  
* Verdicts are logged; suspicious ones also raise a global flag for dashboards / SIEM.  
* All state lives in RAM → median latency **\< 50 ms** even on commodity hardware.

---

## 2  Project Structure, Setup & Run Examples  

```

.
├── attack\_detector.py          # singleton core
├── rules.py                    # 14 detection rules
├── log\_writer.py               # dual-channel logging
├── server.py                   # FastAPI gateway
├── instrumentation.py          # 1-liner snippet helper
├── examples/
│   ├── device\_client\_example.py   # simulates an IoT device
│   └── api\_auth\_demo.py           # shows admin-API usage
├── tests/
│   ├── test\_example\_usage.py
│   └── test\_api.py
└── docs/                     # figs + assignment brief (optional)

````

### Quick Start (Unix / Windows WSL)

```bash
# 1. clone & set up environment
git clone https://github.com/<YOU>/smart-home-ids.git
cd smart-home-ids
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements.txt   # FastAPI, uvicorn, pytest, pydantic …

# 2. run the gateway
uvicorn server:app --reload

# 3. in another shell, post a sample event
python examples/device_client_example.py
````

---

## 3  High-Level System Architecture

> **\[FIGURE 1 – component diagram here]**

| Layer              | Responsibility                                                                   | Key Module           |
| ------------------ | -------------------------------------------------------------------------------- | -------------------- |
| **Device snippet** | Serialises a local action into an `Event` dataclass and fires `POST /events`     | `instrumentation.py` |
| **REST gateway**   | Validates JSON, queues event, serves Swagger, secures admin routes (`X-API-Key`) | `server.py`          |
| **AttackDetector** | Thread-per-device workers; passes each event through the rule engine             | `attack_detector.py` |
| **Rules Engine**   | Stateless functions with per-rule sliding windows                                | `rules.py`           |
| **LogWriter**      | Writes `run.log` (all) & `attack_detection.log` (alerts)                         | `log_writer.py`      |

```python
# attack_detector.py – core enqueue API  (excerpt)
class AttackDetector:
    _instance: 'AttackDetector' | None = None

    def enqueue_event(self, evt: Event) -> None:
        self._ensure_worker(evt.source_id)
        self._queues[evt.source_id].put(evt)
```

---

## 4  Event Evaluation & Logging Pipeline

### 4.1 Rule Evaluation

Each rule is a pure function that receives the event plus a per-rule context
object. It either returns a **`Verdict`** or `None`:

```python
# rules.py – brute-force rule (abridged)
def _detect_brute_force(e: Event, ctx: Ctx) -> Verdict | None:
    fails = ctx.failed_logins[e.user_id]
    fails.append(e.timestamp)
    if len(fails) > 5 and fails[-1] - fails[0] <= timedelta(seconds=60):
        return Verdict("BRUTE_FORCE_LOGIN", suspicious=True,
                       detail={"user": e.user_id, "attempts": len(fails)})
```

* **Network / identity validation** (`NON_LAN_ACCESS`, `UNKNOWN_DEVICE`, …)
* **Authentication & command abuse** (`BRUTE_FORCE_LOGIN`, `COMMAND_INJECTION`)
* **Value anomalies** (`POWER_ANOMALY`, `RESOURCE_EXHAUSTION`)
* **Student extensions** (`SYN_FLOOD`, `MESSAGE_FLOOD`)

### 4.2 Logging

```python
# log_writer.py – dual-channel sink (excerpt)
def write(self, verdict: Verdict, event: Event | None = None) -> None:
    line = {"ts": utcnow(), "rule": verdict.rule_hit,
            "alert": verdict.suspicious, **verdict.detail}
    self._run_log.info(json.dumps(line))
    if verdict.suspicious:
        self._alert_log.info(json.dumps(line))
```

* **`logs/run.log`** – every processed event (rotated daily).
* **`logs/attack_detection.log`** – alert subset; ND-JSON for SIEM.
* Clearing the global alert flag: `POST /status/clear` (admin key required).

---

## 5  FastAPI Gateway & Usage Examples

### 5.1 Selected End-Points (`server.py`)

```python
@app.post("/events")          # public, high-frequency
async def submit(evt: Event):
    detector.enqueue_event(evt)
    return {"queued": True}

@app.get("/status")           # public poll
async def status():
    return detector.current_status()

@app.put("/config/thresholds") # admin, API-key protected
async def update(cfg: ThresholdCfg,
                 api_key: str = Depends(api_guard)):
    detector.reload_thresholds(cfg)
    return {"reloaded": True}
```

### 5.2 Admin API Demo (`examples/api_auth_demo.py`)

```python
key = os.environ["IDS_ADMIN_KEY"]
r = requests.put("http://localhost:8000/config/thresholds",
                 headers={"X-API-Key": key},
                 json={"brute_force": {"count": 7, "window": 90}})
print(r.json())
```

---

## 6  Tests & Results

| Suite                       | Purpose                                                         | Pass / Fail        |
| --------------------------- | --------------------------------------------------------------- | ------------------ |
| **`test_example_usage.py`** | Directly drives `AttackDetector`; hits every rule & benign path | 26/26 ✓            |
| **`test_api.py`**           | Full HTTP path incl. auth & config routes                       | 22/22 ✓            |
| Integration runtime         | End-to-end latency / throughput checks                          | all thresholds met |

Excerpt from **`attack_detection.log`**:

```
{"ts":"2025-06-01T12:10:33Z","rule":"BRUTE_FORCE_LOGIN","alert":true,"user":"eve","attempts":6}
{"ts":"2025-06-01T12:11:02Z","rule":"SYN_FLOOD","alert":true,"src":"192.168.0.7"}
```

Run all tests:

```bash
pytest -q
# 48 passed in 6.11s
```

---

## 7  Integrating with Your IoT Device

1. **Import the helper**

   ```python
   from instrumentation import handle_event, Event
   ```
2. **Emit an event** whenever something security-relevant happens:

   ```python
   handle_event(Event(
       "login_attempt", "USER", user_id,
       device_ip, datetime.utcnow(),
       {"success": success_bool}
   ))
   ```
3. **Optional admin operations** (update thresholds, clear flag) – see
   `examples/api_auth_demo.py`.

**Deployment tips**

* Put the FastAPI service behind Nginx with HTTPS or run inside Docker Compose.
* For lab testing, `examples/device_client_example.py` spams synthetic events at 10 Hz.

---

## 8  Reference Material

* Assignment brief: `docs/EN4720_Milestone_4.pdf`
* Swagger JSON: reachable at `GET /openapi.json` once the server is running.
<!-- * Full technical report (LaTeX): `docs/report.pdf`. -->

---
<!-- 
### License

MIT – see `LICENSE`. -->

<!-- --- -->

> *Happy hacking – and keep your smart home safe!*
