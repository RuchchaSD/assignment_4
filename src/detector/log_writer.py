import json, pathlib, logging
from datetime import datetime

class LogWriter:
    def __init__(self, path: str):
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        logging.basicConfig(level=logging.DEBUG,
                            filename="logs/run.log",
                            format="%(asctime)s %(levelname)s %(message)s")

    def write(self, verdict):
        rec = {"ts": datetime.utcnow().isoformat(),
                "rule": verdict.rule_hit,
               **verdict.detail,
                "ALERT": verdict.suspicious}
        
        # Always log all events to run.log
        if verdict.suspicious:
            logging.warning(f"ALERT {verdict.rule_hit}: {verdict.detail}")
        elif verdict.rule_hit:
            logging.info(f"INFO {verdict.rule_hit}: {verdict.detail}")
        else:
            logging.debug(f"NORMAL: {verdict.detail}")
        
        # Only write attack detections to JSON file
        if verdict.suspicious:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec) + "\n")   # NDJSON
