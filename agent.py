"""Orchestrator: sensors -> (maintenance/immutable/baseline -> ransomware -> anomaly -> intel -> PADIE) -> response -> SIEM."""
from __future__ import annotations
import asyncio, logging, os, platform, signal
from datetime import datetime, timezone
from pathlib import PurePath
from typing import List, Optional

from .baseline import BaselineStore
from .config import Config
from .detection import AnomalyScorer, RansomwareDetector
from .intel import IntelAggregator
from .models import Alert, EventType, FileEvent, ThreatLevel
from .monitors import CloudMonitor, FileMonitor, RegistryMonitor
from .padie import PadieEngine
from .response import ContainmentEngine
from .siem import SiemDispatcher

log = logging.getLogger("ironsentinel.agent")
EXEC_EXT = {".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".so", ".dylib", ".jar", ".scr", ".msi"}
MUTATING = {EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED, EventType.FILE_RENAMED, EventType.PERM_CHANGED}


class MaintenanceWindows:
    """Windows like {start:"22:00", end:"02:00", days:[0..6], paths:[...]}; evaluated in UTC (overnight windows supported)."""
    def __init__(self, windows): self.w = windows or []

    def active(self, path: str, ts: Optional[datetime] = None) -> bool:
        ts = ts or datetime.now(timezone.utc)
        clk = ts.strftime("%H:%M")
        for w in self.w:
            if ts.weekday() not in w.get("days", range(7)): continue
            s, e = w["start"], w["end"]
            if not ((s <= clk <= e) if s <= e else (clk >= s or clk <= e)): continue
            if not w.get("paths") or any(path.startswith(p) for p in w["paths"]): return True
        return False


def under(path: str, roots: List[str]) -> bool:
    p = os.path.normcase(os.path.abspath(path))
    return any(p == os.path.normcase(os.path.abspath(r)) or p.startswith(os.path.normcase(os.path.abspath(r)) + os.sep) for r in roots)


class IronSentinel:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        logging.basicConfig(level=cfg.get("agent", "log_level", default="INFO"), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        sd = cfg.get("agent", "state_dir")
        self.queue: asyncio.Queue = asyncio.Queue(cfg.get("agent", "queue_size"))
        self.stop = asyncio.Event()
        self.mw = MaintenanceWindows(cfg.get("maintenance_windows"))
        self.immutable = cfg.get("monitors", "file", "immutable_paths", default=[])
        self.baseline = BaselineStore(os.path.join(sd, "baseline")) if cfg.get("baseline", "paths") or os.path.isdir(os.path.join(sd, "baseline")) else None
        if self.baseline:
            for p in cfg.get("baseline", "paths", default=[]):
                if not any(k.startswith(p) for k in self.baseline.index):
                    n = self.baseline.add_tree(p) if os.path.isdir(p) else int(bool(self.baseline.add(p)))
                    log.info("baselined %d files under %s", n, p)
        m = cfg.get("ml", default={})
        self.ransom = RansomwareDetector(m["ransom_entropy"], m["ransom_burst"], m["ransom_window_s"])
        self.anomaly = AnomalyScorer(m)
        self.intel = IntelAggregator(cfg)
        self.padie = PadieEngine(cfg)
        self.response = ContainmentEngine(cfg, self.baseline, sd)
        self.siem = SiemDispatcher(cfg)
        self.alerts: List[Alert] = []                  # kept for tests/API; bounded below

    async def _emit(self, a: Alert):
        self.alerts.append(a); del self.alerts[:-5000]
        log.log(logging.CRITICAL if a.threat_level >= ThreatLevel.CRITICAL else logging.WARNING if a.threat_level >= ThreatLevel.MEDIUM else logging.INFO,
                "[%s] %s — %s %s", a.threat_level.name, a.title, a.description, a.actions_taken or "")
        await self.siem.send(a)

    async def handle(self, ev: FileEvent):
        """Full pipeline for one event. Public so it can be driven directly by tests or other sensors."""
        ev.suppressed = self.mw.active(ev.path, ev.timestamp)
        found: List[Alert] = []
        if ev.suppressed:                              # approved change: keep baseline current, stay quiet
            if self.baseline and ev.event_type in {EventType.FILE_MODIFIED, EventType.FILE_CREATED} and ev.path in self.baseline.index:
                await asyncio.to_thread(self.baseline.add, ev.path)
            if self.siem.audit_all: await self.siem.send(Alert("maintenance-window change", ev.path, ThreatLevel.INFO, ev))
            return
        if ev.event_type == EventType.FILE_OPENED and ev.path not in self.padie.decoys and not ev.meta.get("sensor"):
            return          # raw opens are noise unless on a decoy or reported by a trusted external sensor (auditd/Sysmon/ETW/EndpointSecurity)

        # 1. immutable paths: zero tolerance
        if ev.event_type in MUTATING and self.immutable and under(ev.path, self.immutable):
            ev.event_type, ev.threat_level = EventType.IMMUTABLE_VIOLATION, ThreatLevel.CRITICAL
            ev.mitre_techniques += ["T1565.001"]; ev.mitre_tactics += ["Impact"]
            found.append(Alert("IMMUTABLE PATH VIOLATED", f"{ev.path} changed outside an approved window (user={ev.user}, proc={ev.process_name}).", ThreatLevel.CRITICAL, ev))

        # 2. signed-baseline drift (+ deletion)
        elif self.baseline and ev.event_type in MUTATING:
            if ev.event_type == EventType.FILE_RENAMED and ev.old_path in self.baseline.index:
                target, actual = ev.old_path, None            # baselined file moved away
            elif ev.event_type == EventType.FILE_DELETED:
                target, actual = ev.path, None
            else:
                target, actual = ev.path, ev.sha256_after
            d = self.baseline.drift(target, actual)
            if d:
                ev.event_type, ev.threat_level = EventType.BASELINE_DRIFT, max(ev.threat_level, ThreatLevel.HIGH)
                ev.mitre_techniques += ["T1565.001"]
                found.append(Alert("Baseline drift", f"{target} differs from signed baseline ({d['expected'][:12]}… -> {(d['actual'] or 'DELETED')[:12]}).", ThreatLevel.HIGH, ev))
                if not self.cfg.get("baseline", "auto_rollback"): ev.meta["no_rollback"] = True
                else: ev.path = target

        # 3. ransomware behaviour
        hit, score, why = self.ransom.assess(ev)
        if hit:
            ev.event_type, ev.threat_level, ev.anomaly_score = EventType.RANSOMWARE, ThreatLevel.CRITICAL, score
            ev.mitre_techniques += ["T1486"]; ev.mitre_tactics += ["Impact"]
            found.append(Alert("RANSOMWARE BEHAVIOUR", f"{ev.path}: {', '.join(why)} (confidence {score:.2f}) by {ev.process_name or 'unknown'} pid={ev.pid}.", ThreatLevel.CRITICAL, ev))
        elif ev.event_type in MUTATING:
            # 4. behavioural anomaly
            s, reasons = self.anomaly.score(ev)
            ev.anomaly_score = max(ev.anomaly_score, s)
            if s >= self.cfg.get("ml", "anomaly_threshold"):
                ev.threat_level = max(ev.threat_level, ThreatLevel.HIGH)
                found.append(Alert("Behavioural anomaly", f"{ev.path} by {ev.user}: {', '.join(reasons)} (score {s:.2f}).", ThreatLevel.HIGH, ev))

        # 5. threat intel for suspicious or executable content
        malicious = False
        if self.intel.active and (ev.threat_level >= ThreatLevel.MEDIUM or PurePath(ev.path).suffix.lower() in EXEC_EXT) and ev.event_type in {EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_RENAMED}:
            ev.intel_hits = await self.intel.enrich(ev)
            malicious = any(h.get("malicious") for h in ev.intel_hits)
            if malicious:
                ev.threat_level = ThreatLevel.CRITICAL
                h = next(h for h in ev.intel_hits if h.get("malicious"))
                found.append(Alert("Threat-intel match", f"{ev.path} sha256={ev.sha256_after[:16] if ev.sha256_after else '?'}… flagged by {h['source']} ({h.get('family') or h.get('category') or h.get('ip') or 'IOC'}).", ThreatLevel.CRITICAL, ev))

        # 6. PADIE: predict + deceive (runs on every event so decoy tripwires always fire)
        found += self.padie.process(ev)

        # 7. response
        if ev.threat_level >= ThreatLevel.HIGH and ev.event_type != EventType.BASELINE_DRIFT or ev.event_type == EventType.BASELINE_DRIFT or malicious:
            acts = await self.response.respond(ev, malicious)
            if acts and found: found[-1].actions_taken = acts
        for a in found: await self._emit(a)
        if self.siem.audit_all and not found: await self.siem.send(Alert(ev.event_type.value, ev.path, ThreatLevel.INFO, ev))

    async def _worker(self):
        while not self.stop.is_set():
            try: ev = await asyncio.wait_for(self.queue.get(), 1.0)
            except asyncio.TimeoutError: continue
            try: await self.handle(ev)
            except Exception:
                log.exception("pipeline error on %s", ev.path)

    async def run(self):
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try: loop.add_signal_handler(sig, self.stop.set)
            except NotImplementedError: pass          # Windows
        tasks = [asyncio.create_task(self._worker()),
                 asyncio.create_task(FileMonitor(self.cfg, self.queue, self.padie.watch_paths(), tripwire=lambda p: p in self.padie.decoys).run(self.stop))]
        if self.cfg.get("monitors", "registry", "enabled") and platform.system() == "Windows":
            tasks.append(asyncio.create_task(RegistryMonitor(self.cfg, self.queue).run(self.stop)))
        if self.cfg.get("monitors", "cloud", "enabled"):
            tasks.append(asyncio.create_task(CloudMonitor(self.cfg, self.queue).run(self.stop)))
        log.info("IronSentinel %s online (dry_run=%s, padie=%s)", self.cfg.get("agent", "id"), self.response.dry, self.padie.enabled)
        await self.stop.wait()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.padie.cleanup(); await self.siem.close()
        log.info("stopped")
