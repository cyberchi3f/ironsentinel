"""YAML config with defaults. Safe by default: response.dry_run = true."""
from __future__ import annotations
import copy, uuid
from typing import Any, Dict

try:
    import yaml
except ImportError:
    yaml = None

DEFAULTS: Dict[str, Any] = {
    "agent": {"id": None, "log_level": "INFO", "queue_size": 50000, "state_dir": "/var/lib/ironsentinel"},
    "monitors": {
        "file": {"paths": [], "immutable_paths": [], "exclude": ["*.log", "*.tmp", "*.swp", "*.pid"], "recursive": True},
        "registry": {"enabled": False, "keys": [], "poll_seconds": 5},
        "cloud": {"enabled": False, "poll_seconds": 60, "sources": []},
    },
    "maintenance_windows": [],     # [{start:"22:00", end:"02:00", days:[0..6], paths:[...]}]
    "ml": {"anomaly_threshold": 0.75, "ransom_entropy": 7.2, "ransom_burst": 15, "ransom_window_s": 30,
           "business_hours": [8, 18]},
    "baseline": {"paths": [], "auto_rollback": True},
    "threat_intel": {"virustotal": {"enabled": False, "api_key": ""},
                     "misp": {"enabled": False, "url": "", "api_key": "", "verify_tls": True},
                     "opencti": {"enabled": False, "url": "", "api_key": "", "verify_tls": True},
                     "abuseipdb": {"enabled": False, "api_key": ""}},
    "response": {"dry_run": True, "terminate": True, "quarantine": True, "isolate_on": ["ransomware", "deception_hit"],
                 "management_subnets": [], "playbooks_dir": "/etc/ironsentinel/playbooks"},
    "integrations": {
        "audit_all": True,          # ship every attributed event (contextual audit trail), not just alerts
        "fortigate": {"enabled": False, "host": "", "api_token": "", "vdom": "root",
                      "quarantine_group": "IronSentinel_Quarantine", "verify_tls": True},
        "sophos": {"enabled": False, "client_id": "", "client_secret": ""},
        "wazuh": {"enabled": False, "jsonl_path": "/var/log/ironsentinel/alerts.json",
                  "syslog_host": "", "syslog_port": 514},
        "elk": {"enabled": False, "url": "http://localhost:9200", "index": "ironsentinel",
                "username": "", "password": "", "verify_tls": True},
        "syslog": {"enabled": False, "host": "", "port": 514, "protocol": "udp", "format": "cef"},
    },
    "padie": {"enabled": True, "inject_score": 0.5, "max_decoys": 6, "session_ttl_min": 90,
              "decoy_dir": "/var/lib/ironsentinel/decoys", "plant_roots": []},
}


def _merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in (b or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


class Config:
    def __init__(self, path: str | None = None, overrides: dict | None = None):
        data: dict = {}
        if path and yaml:
            try:
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
            except FileNotFoundError:
                pass
        self._d = _merge(_merge(DEFAULTS, data), overrides or {})
        if not self._d["agent"]["id"]:
            self._d["agent"]["id"] = str(uuid.uuid4())

    def get(self, *keys, default=None):
        n: Any = self._d
        for k in keys:
            if not isinstance(n, dict) or k not in n:
                return default
            n = n[k]
        return n
