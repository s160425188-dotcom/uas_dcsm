import os
import json
from datetime import datetime

class AuditLogger:
    def __init__(self, log_file=None):
        default_path = os.path.join(os.environ.get("LOG_DIR", "."), "audit_logs.json")
        self.log_file = log_file or default_path
        log_dir = os.path.dirname(self.log_file)
        if log_dir and log_dir != ".":
            os.makedirs(log_dir, exist_ok=True)
        self.service_name = os.environ.get("SERVICE_NAME", "storage")

    def log(self, user: str, role: str, action: str, resource: str, decision: str, reason: str = ""):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": self.service_name,
            "user": user,
            "role": role,
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason
        }
        print(f"[AUDIT LOG] {json.dumps(entry)}", flush=True)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

audit_logger = AuditLogger()
