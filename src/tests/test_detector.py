from datetime import datetime, timedelta
from detector.instrumentation import instrument

def test_burst_login_triggers():
    now = datetime.utcnow()
    for i in range(6):
        instrument("login_attempt", "USER", "bob", "10.0.0.1",
                    now + timedelta(seconds=i*10), {"success": False})
    with open("logs/suspicious.jsonl") as f:
        alerts = [json.loads(l) for l in f.readlines()]
    assert any(a["rule"] == "FAILED_LOGIN_BURST" for a in alerts)
