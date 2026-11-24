"""Core data models: enums, FileEvent, Alert (+ CEF / JSON serialisation)."""
from __future__ import annotations
import platform, uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional

VERSION = "2.0.0"


class ThreatLevel(IntEnum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4


class EventType(str, Enum):
    FILE_CREATED = "file_created"; FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"; FILE_RENAMED = "file_renamed"
    FILE_OPENED = "file_opened"; PERM_CHANGED = "perm_changed"
    REG_CHANGED = "registry_changed"; CLOUD_CHANGE = "cloud_change"
    BASELINE_DRIFT = "baseline_drift"; IMMUTABLE_VIOLATION = "immutable_violation"
    RANSOMWARE = "ransomware"; ANOMALY = "anomaly"; DECEPTION_HIT = "deception_hit"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class FileEvent:
    event_type: EventType = EventType.FILE_MODIFIED
    path: str = ""
    old_path: Optional[str] = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_now)
    sha256_before: Optional[str] = None
    sha256_after: Optional[str] = None
    entropy_before: float = 0.0
    entropy_after: float = 0.0
    pid: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_cmdline: Optional[str] = None
    user: Optional[str] = None
    hostname: str = field(default_factory=platform.node)
    os_platform: str = field(default_factory=platform.system)
    threat_level: ThreatLevel = ThreatLevel.INFO
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    intel_hits: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False          # inside an approved maintenance window


@dataclass
class Alert:
    title: str
    description: str
    threat_level: ThreatLevel
    event: Optional[FileEvent] = None
    actions_taken: List[str] = field(default_factory=list)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_now)

    def to_json(self) -> Dict[str, Any]:
        e = self.event
        return {
            "@timestamp": self.timestamp.isoformat(),
            "ironsentinel": {"version": VERSION, "alert_id": self.alert_id,
                             "title": self.title, "description": self.description,
                             "severity": self.threat_level.name,
                             "actions_taken": self.actions_taken},
            "event": {"type": e.event_type.value if e else None,
                      "anomaly_score": e.anomaly_score if e else 0.0},
            "file": {"path": e.path if e else None,
                     "hash_before": e.sha256_before if e else None,
                     "hash_after": e.sha256_after if e else None,
                     "entropy_delta": round(e.entropy_after - e.entropy_before, 3) if e else None},
            "process": {"pid": e.pid if e else None, "name": e.process_name if e else None,
                        "path": e.process_path if e else None,
                        "cmdline": e.process_cmdline if e else None},
            "user": {"name": e.user if e else None},
            "host": {"name": e.hostname if e else None, "os": e.os_platform if e else None},
            "threat_intel": e.intel_hits if e else [],
            "mitre": {"tactics": e.mitre_tactics if e else [],
                      "techniques": e.mitre_techniques if e else []},
        }

    def to_cef(self) -> str:
        def hdr(s: str) -> str:
            return str(s).replace("\\", "\\\\").replace("|", "\\|")
        def ext(s: Any) -> str:
            return str(s).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")
        e = self.event
        sev = min(10, self.threat_level * 2 + (1 if self.threat_level else 0))
        fields = {"rt": int(self.timestamp.timestamp() * 1000), "msg": self.description}
        if e:
            fields.update({"shost": e.hostname, "fname": e.path, "suser": e.user or "-",
                           "sproc": e.process_name or "-", "fileHash": e.sha256_after or "-",
                           "cs1Label": "mitre_techniques", "cs1": ",".join(e.mitre_techniques)})
        body = " ".join(f"{k}={ext(v)}" for k, v in fields.items())
        sig = e.event_type.value if e else "alert"
        return f"CEF:0|DexAShield|IronSentinel|{VERSION}|{hdr(sig)}|{hdr(self.title)}|{sev}|{body}"
