"""
PADIE — Predictive Attack-chain Deception Injection Engine  (Ironsentinel's differentiating feature)

Reactive FIM:  change -> alert -> analyst.
PADIE:         change -> map to ATT&CK -> predict attacker's NEXT technique -> plant a tailored decoy
               exactly where that technique looks -> any touch of the decoy = confirmed malicious (≈0 FP).

Pipeline:  events -> AttackSession (per actor) -> TransitionPredictor (Markov prior blended with
           observed transitions) -> DecoyFactory (technique-specific fakes with unique canary IDs)
           -> DecoyWatch (any open/modify/delete of a decoy => DECEPTION_HIT).
Safety:    never overwrites a real file; decoys hold only random fake secrets; IronSentinel's own PID is ignored;
           everything planted is removed on shutdown.
"""
from __future__ import annotations
import base64, json, logging, os, secrets, time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Alert, EventType, FileEvent, ThreatLevel

log = logging.getLogger("ironsentinel.padie")

TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
                "Exfiltration", "Impact"]
TECH = {  # technique -> tactic
    "T1059": "Execution", "T1059.001": "Execution", "T1059.004": "Execution",
    "T1547.001": "Persistence", "T1546": "Persistence", "T1053": "Persistence",
    "T1070": "Defense Evasion", "T1070.004": "Defense Evasion",
    "T1003.001": "Credential Access", "T1003.002": "Credential Access", "T1003.003": "Credential Access",
    "T1552.001": "Credential Access", "T1552.004": "Credential Access", "T1555": "Credential Access",
    "T1082": "Discovery", "T1083": "Discovery", "T1021.004": "Lateral Movement", "T1021.006": "Lateral Movement",
    "T1078": "Lateral Movement", "T1005": "Collection", "T1213": "Collection", "T1560": "Collection",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1486": "Impact", "T1565.001": "Impact",
}
# Prior transition beliefs (seeded from public ATT&CK group reporting; tune/replace with your own telemetry).
PRIOR: Dict[str, List[Tuple[str, float]]] = {
    "T1059": [("T1083", .35), ("T1082", .25), ("T1003.001", .15), ("T1547.001", .15), ("T1552.001", .10)],
    "T1059.001": [("T1003.001", .30), ("T1082", .25), ("T1547.001", .25), ("T1070", .20)],
    "T1059.004": [("T1552.001", .30), ("T1003.002", .25), ("T1083", .25), ("T1021.004", .20)],
    "T1082": [("T1083", .35), ("T1059", .25), ("T1552.001", .20), ("T1003.001", .20)],
    "T1083": [("T1005", .30), ("T1552.001", .30), ("T1213", .20), ("T1560", .20)],
    "T1552.001": [("T1021.004", .40), ("T1078", .30), ("T1560", .20), ("T1041", .10)],
    "T1552.004": [("T1021.004", .50), ("T1078", .30), ("T1041", .20)],
    "T1003.001": [("T1021.006", .40), ("T1078", .30), ("T1560", .20), ("T1041", .10)],
    "T1003.002": [("T1078", .45), ("T1021.004", .35), ("T1560", .20)],
    "T1021.004": [("T1059.004", .35), ("T1552.004", .25), ("T1560", .25), ("T1048", .15)],
    "T1005": [("T1560", .50), ("T1041", .30), ("T1048", .20)],
    "T1213": [("T1560", .45), ("T1041", .35), ("T1048", .20)],
    "T1560": [("T1041", .55), ("T1048", .35), ("T1070.004", .10)],
}
PATH_HINTS = {  # substring of a touched path -> techniques it evidences
    "/etc/shadow": ["T1003.002"], "/etc/passwd": ["T1082"], "ntds.dit": ["T1003.003"], "lsass": ["T1003.001"],
    ".aws/credentials": ["T1552.001"], ".env": ["T1552.001"], "wp-config.php": ["T1552.001"],
    ".ssh/id_": ["T1552.004"], ".ssh/known_hosts": ["T1083"], ".ssh/authorized_keys": ["T1547.001"],
    ".bash_history": ["T1070"], "/cron": ["T1053"], "\\run\\": ["T1547.001"], "\\startup\\": ["T1547.001"],
}


def techniques_for(ev: FileEvent) -> List[str]:
    p = ev.path.replace("\\", "/").lower()
    out = list(ev.mitre_techniques)
    for k, v in PATH_HINTS.items():
        if k.replace("\\", "/") in p:
            out += v
    if ev.event_type == EventType.RANSOMWARE:
        out.append("T1486")
    if ev.process_name and ev.process_name.lower() in {"powershell.exe", "pwsh", "pwsh.exe"}:
        out.append("T1059.001")
    elif ev.process_name and ev.process_name.lower() in {"bash", "sh", "zsh", "dash"}:
        out.append("T1059.004")
    return list(dict.fromkeys(out))


@dataclass
class AttackSession:
    actor: str
    last: float = field(default_factory=time.time)
    techniques: List[str] = field(default_factory=list)
    predicted: List[Tuple[str, float]] = field(default_factory=list)
    decoys: List[str] = field(default_factory=list)
    confirmed: bool = False

    def depth(self) -> int:
        d = [TACTIC_ORDER.index(TECH[t]) for t in self.techniques if TECH.get(t) in TACTIC_ORDER]
        return max(d) if d else 0

    def score(self) -> float:
        return round(0.5 * min(len(self.techniques) / 8, 1) + 0.5 * self.depth() / (len(TACTIC_ORDER) - 1), 3)


class TransitionPredictor:
    def __init__(self, alpha=0.3):
        self.alpha = alpha
        self.obs: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def learn(self, a: str, b: str):
        self.obs[a][b] += 1

    def predict(self, s: AttackSession, k=2) -> List[Tuple[str, float]]:
        if not s.techniques:
            return []
        last = s.techniques[-1]
        prior = dict(PRIOR.get(last) or PRIOR.get(last.split(".")[0], []))
        o = self.obs.get(last, {})
        tot = sum(o.values()) or 1
        mix = {t: (1 - self.alpha) * prior.get(t, 0) + self.alpha * o.get(t, 0) / tot for t in set(prior) | set(o)}
        for t in s.techniques:
            mix.pop(t, None)
        z = sum(mix.values()) or 1
        return [(t, round(p / z, 3)) for t, p in sorted(mix.items(), key=lambda x: -x[1])[:k]]


class DecoyFactory:
    """Technique -> (relative path under a plant root, content). All secrets are random and inert."""

    def __init__(self):
        self.users = ["svc-backup", "deploy", "dbadmin", "jenkins"]
        self.hosts = ["prod-db-01", "vault-02", "dc-01", "nas-01"]

    def _b64(self, n=24): return base64.b64encode(secrets.token_bytes(n)).decode()
    def _id(self): return "is-" + secrets.token_hex(6)

    def build(self, tech: str) -> Optional[Tuple[str, bytes, str]]:
        cid = self._id()
        t = tech
        if t in ("T1552.001", "T1078"):
            return ".aws/credentials", (f"[default]\naws_access_key_id = AKIA{secrets.token_hex(8).upper()}\n"
                                        f"aws_secret_access_key = {self._b64(30)}\nregion = eu-west-1\n").encode(), cid
        if t in ("T1552.004", "T1021.004"):
            return f".ssh/id_rsa_{cid[-4:]}", ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(self._b64(48) for _ in range(12)) +
                                               "\n-----END OPENSSH PRIVATE KEY-----\n").encode(), cid
        if t == "T1003.002":
            return "backup/SAM.bak", b"regf" + secrets.token_bytes(4096), cid
        if t == "T1003.003":
            return "backup/ntds_snapshot.dit", b"\xef\xcd\xab\x89" + secrets.token_bytes(8192), cid
        if t == "T1003.001":
            return "temp/lsass_dump.dmp", b"MDMP" + secrets.token_bytes(8192), cid
        if t in ("T1213", "T1005", "T1555"):
            return f"config/db_{cid[-4:]}.json", json.dumps({"host": f"{self.hosts[0]}.corp.internal", "user": self.users[2],
                                                              "password": self._b64(18), "port": 5432}, indent=2).encode(), cid
        if t in ("T1560", "T1041", "T1048"):
            return f"backup/finance_export_{cid[-4:]}.csv", ("account,iban,balance\n" + "\n".join(
                f"{secrets.randbelow(10**6)},XX{secrets.randbelow(10**14):014d},{secrets.randbelow(10**7)}" for _ in range(40))).encode(), cid
        return None


class PadieEngine:
    def __init__(self, cfg, self_pid: Optional[int] = None):
        self.enabled = cfg.get("padie", "enabled", default=True)
        self.inject_score = cfg.get("padie", "inject_score", default=0.5)
        self.max_decoys = cfg.get("padie", "max_decoys", default=6)
        self.ttl = cfg.get("padie", "session_ttl_min", default=90) * 60
        roots = cfg.get("padie", "plant_roots", default=[]) or [cfg.get("padie", "decoy_dir")]
        self.roots = [Path(r) for r in roots]
        self.sessions: Dict[str, AttackSession] = {}
        self.predictor, self.factory = TransitionPredictor(), DecoyFactory()
        self.decoys: Dict[str, dict] = {}            # absolute path -> {id, technique, session}
        self.self_pid = self_pid or os.getpid()

    # watchers should include these paths in their observer
    def watch_paths(self) -> List[str]:
        return [str(r) for r in self.roots if r.exists()]

    def _actor(self, ev: FileEvent) -> str:
        return f"{ev.user}@{ev.hostname}"

    def _session(self, ev: FileEvent) -> AttackSession:
        now = time.time()
        for k in [k for k, s in self.sessions.items() if now - s.last > self.ttl]:
            del self.sessions[k]
        s = self.sessions.setdefault(self._actor(ev), AttackSession(self._actor(ev)))
        s.last = now
        return s

    def _plant(self, tech: str, s: AttackSession) -> Optional[str]:
        built = self.factory.build(tech)
        if not built:
            return None
        rel, data, cid = built
        for root in self.roots:
            dest = root / rel
            if dest.exists():                      # never clobber a real file
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                os.chmod(dest, 0o600)
            except OSError:
                continue
            self.decoys[str(dest)] = {"id": cid, "technique": tech, "session": s.actor}
            s.decoys.append(str(dest))
            return str(dest)
        return None

    def process(self, ev: FileEvent) -> List[Alert]:
        """Returns alerts (decoy injected / deception hit). Mutates ev on a hit."""
        if not self.enabled or ev.pid == self.self_pid:
            return []
        alerts: List[Alert] = []
        meta = self.decoys.get(ev.path) or (self.decoys.get(ev.old_path) if ev.old_path else None)
        if meta:                                                   # tripwire
            s = self.sessions.setdefault(meta["session"], AttackSession(meta["session"]))
            s.confirmed = True
            ev.event_type, ev.threat_level = EventType.DECEPTION_HIT, ThreatLevel.CRITICAL
            ev.mitre_techniques += [meta["technique"]]
            ev.meta["decoy_id"] = meta["id"]
            alerts.append(Alert("DECEPTION HIT — confirmed hostile activity",
                                f"{ev.user}/{ev.process_name or 'unknown process'} touched decoy {ev.path} (id {meta['id']}, "
                                f"lures {meta['technique']}). Kill-chain depth {s.depth()}/{len(TACTIC_ORDER)-1}; "
                                f"observed: {', '.join(s.techniques[-6:]) or 'n/a'}.", ThreatLevel.CRITICAL, ev))
            return alerts
        techs = techniques_for(ev)
        if not techs and ev.threat_level < ThreatLevel.MEDIUM and ev.anomaly_score < 0.4:
            return []
        s = self._session(ev)
        for t in techs:
            if t not in s.techniques:
                if s.techniques:
                    self.predictor.learn(s.techniques[-1], t)
                s.techniques.append(t)
        s.predicted = self.predictor.predict(s)
        # Planting is cheap and harmless, so trigger early: once the actor reaches credential-access depth, or the
        # session score / event severity / anomaly score is high.
        trigger = (s.score() >= self.inject_score or s.depth() >= TACTIC_ORDER.index("Credential Access")
                   or ev.threat_level >= ThreatLevel.HIGH or ev.anomaly_score >= 0.75)
        if trigger and s.predicted and len(s.decoys) < self.max_decoys:
            for tech, prob in s.predicted:
                if any(self.decoys[d]["technique"] == tech for d in s.decoys):
                    continue
                path = self._plant(tech, s)
                if path:
                    alerts.append(Alert(f"PADIE decoy planted for predicted {tech}",
                                        f"Session {s.actor}: observed {s.techniques[-4:]}; next-step prediction {tech} "
                                        f"({prob:.0%}). Decoy at {path}. Kill-chain score {s.score()}.",
                                        ThreatLevel.MEDIUM, ev))
        return alerts

    def cleanup(self):
        for p in list(self.decoys):
            try:
                os.unlink(p)
            except OSError:
                pass
        self.decoys.clear()

    def report(self) -> List[dict]:
        return [{"actor": s.actor, "techniques": s.techniques, "predicted": s.predicted, "score": s.score(),
                 "depth": s.depth(), "decoys": s.decoys, "confirmed": s.confirmed} for s in self.sessions.values()]
