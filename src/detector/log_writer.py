import json, pathlib, logging
from datetime import datetime

class LogWriter:
    def __init__(self, path: str):
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        logging.basicConfig(level=logging.INFO,
                            filename="logs/run.log",
                            format="%(asctime)s %(levelname)s %(message)s")

    def write(self, verdict):
        rec = {"ts": datetime.utcnow().isoformat(),
                "rule": verdict.rule_hit,
               **verdict.detail,
                "ALERT": verdict.suspicious}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")   # NDJSON
        logging.warning(f"ALERT: {rec}")
