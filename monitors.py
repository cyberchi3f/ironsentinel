"""Sensors: cross-platform file monitor (watchdog), Windows registry poller, cloud bucket poller."""
from __future__ import annotations
import asyncio, fnmatch, logging, os, platform, stat, threading, time
from typing import Dict, List, Optional, Tuple

from .models import EventType, FileEvent
from .util import current_user, file_entropy, process_holding, sha256_file

log = logging.getLogger("ironsentinel.monitors")
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:                                   # pragma: no cover
    FileSystemEventHandler, Observer = object, None


class _Handler(FileSystemEventHandler):
    """Runs in watchdog's thread; hands events to the asyncio loop. Keeps last-known (sha, entropy) per path
    so every modification carries before/after state."""

    def __init__(self, loop, queue, exclude, debounce=0.15, tripwire=None):
        self.loop, self.q, self.exclude, self.debounce, self.tripwire = loop, queue, exclude, debounce, tripwire
        self._timers: Dict[str, threading.Timer] = {}
        self._lock = threading.Lock()
        self.state: Dict[str, Tuple[Optional[str], float]] = {}
        self._last: Dict[str, float] = {}

    def _skip(self, p: str) -> bool:
        n = os.path.basename(p)
        return any(fnmatch.fnmatch(n, pat) for pat in self.exclude)

    def _emit(self, ev: FileEvent):
        self.loop.call_soon_threadsafe(self._put, ev)

    def _put(self, ev):
        try:
            self.q.put_nowait(ev)
        except asyncio.QueueFull:
            log.warning("event queue full — dropping %s", ev.path)

    def _build(self, etype: EventType, path: str, old: Optional[str] = None, attribute=True) -> FileEvent:
        ev = FileEvent(event_type=etype, path=path, old_path=old, user=current_user())
        prev = self.state.get(path) or (self.state.get(old) if old else None) or (None, 0.0)
        ev.sha256_before, ev.entropy_before = prev
        if etype != EventType.FILE_DELETED:
            ev.sha256_after, ev.entropy_after = sha256_file(path), file_entropy(path)
            try:
                st = os.stat(path)
                ev.meta.update(size=st.st_size, mode=oct(stat.S_IMODE(st.st_mode)), uid=getattr(st, "st_uid", None))
            except OSError:
                pass
            self.state[path] = (ev.sha256_after, ev.entropy_after)
        else:
            self.state.pop(path, None)
        if attribute and etype in (EventType.FILE_MODIFIED, EventType.FILE_CREATED, EventType.FILE_OPENED):
            ev.pid, ev.process_name, ev.process_path, ev.process_cmdline = process_holding(path)
        return ev

    def prime(self, root: str):
        for dp, _, fs in os.walk(root):
            for f in fs:
                p = os.path.join(dp, f)
                if not self._skip(p):
                    self.state[p] = (sha256_file(p), file_entropy(p))

    def on_created(self, e):
        if not e.is_directory and not self._skip(e.src_path):
            self._emit(self._build(EventType.FILE_CREATED, e.src_path))

    def on_modified(self, e):
        if e.is_directory or self._skip(e.src_path):
            return
        self._coalesce(e.src_path)

    def _coalesce(self, path: str):
        """Trailing-edge debounce: a write is usually truncate+write+close (several raw events). Wait for the
        burst to settle, then hash ONCE so we always see the final content (leading-edge debounce would
        hash the empty/partial file and miss the encryption)."""
        with self._lock:
            t = self._timers.pop(path, None)
            if t: t.cancel()
            t = threading.Timer(self.debounce, self._fire, args=(path,))
            t.daemon = True
            self._timers[path] = t
            t.start()

    def _fire(self, path: str):
        with self._lock:
            self._timers.pop(path, None)
        if os.path.exists(path):
            self._emit(self._build(EventType.FILE_MODIFIED, path))

    def on_deleted(self, e):
        if not e.is_directory and not self._skip(e.src_path):
            self._emit(self._build(EventType.FILE_DELETED, e.src_path, attribute=False))

    def on_moved(self, e):
        if not e.is_directory:
            self._emit(self._build(EventType.FILE_RENAMED, e.dest_path, old=e.src_path))

    def on_opened(self, e):
        """Read-access tripwire (inotify). Deliberately NOT hashing or touching state: our own reads also raise
        'opened' events, so only registered tripwire paths (PADIE decoys) are reported, and cheaply."""
        if e.is_directory or not (self.tripwire and self.tripwire(e.src_path)):
            return
        ev = FileEvent(event_type=EventType.FILE_OPENED, path=e.src_path, user=current_user())
        ev.pid, ev.process_name, ev.process_path, ev.process_cmdline = process_holding(e.src_path)
        self._emit(ev)


class FileMonitor:
    def __init__(self, cfg, queue, extra_paths: Optional[List[str]] = None, tripwire=None):
        self.cfg, self.q, self.tripwire = cfg, queue, tripwire
        self.paths = list(dict.fromkeys(
            list(cfg.get("monitors", "file", "paths", default=[])) +
            list(cfg.get("monitors", "file", "immutable_paths", default=[])) +
            list(cfg.get("baseline", "paths", default=[])) + (extra_paths or [])))
        self.observer = None

    async def run(self, stop: asyncio.Event):
        if Observer is None:
            log.error("watchdog not installed; file monitoring disabled"); return
        loop = asyncio.get_running_loop()
        h = _Handler(loop, self.q, self.cfg.get("monitors", "file", "exclude", default=[]), tripwire=self.tripwire)
        self.observer = Observer()
        n = 0
        for p in self.paths:
            if os.path.isdir(p):
                h.prime(p)
                self.observer.schedule(h, p, recursive=self.cfg.get("monitors", "file", "recursive", default=True))
                n += 1
            elif os.path.isfile(p):
                self.observer.schedule(h, os.path.dirname(p) or ".", recursive=False)
                h.state[p] = (sha256_file(p), file_entropy(p)); n += 1
            else:
                log.warning("watch path missing: %s", p)
        self.observer.start()
        log.info("file monitor watching %d paths (%s)", n, platform.system())
        await stop.wait()
        self.observer.stop(); self.observer.join(timeout=5)



class RegistryMonitor:
    """Windows persistence/config keys by polling winreg (swap for ETW/RegNotifyChangeKeyValue at scale)."""

    def __init__(self, cfg, queue):
        self.cfg, self.q = cfg, queue

    def _snap(self, key: str) -> Dict[str, str]:
        import winreg
        hive, _, sub = key.partition("\\")
        root = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[hive]
        out = {}
        try:
            with winreg.OpenKey(root, sub) as k:
                i = 0
                while True:
                    try:
                        n, v, _t = winreg.EnumValue(k, i); out[n] = repr(v); i += 1
                    except OSError:
                        break
        except OSError:
            pass
        return out

    async def run(self, stop: asyncio.Event):
        if platform.system() != "Windows":
            return
        keys = self.cfg.get("monitors", "registry", "keys", default=[])
        every = self.cfg.get("monitors", "registry", "poll_seconds", default=5)
        prev = {k: self._snap(k) for k in keys}
        while not stop.is_set():
            await asyncio.sleep(every)
            for k in keys:
                cur = self._snap(k)
                for n in set(cur) | set(prev[k]):
                    if cur.get(n) != prev[k].get(n):
                        ev = FileEvent(EventType.REG_CHANGED, f"{k}\\{n}", user=current_user(),
                                       mitre_techniques=["T1547.001"], mitre_tactics=["Persistence"])
                        ev.meta.update(before=prev[k].get(n), after=cur.get(n))
                        self.q.put_nowait(ev)
                prev[k] = cur


class CloudMonitor:
    """Polls S3 / Azure Blob / GCS inventories and diffs ETags (use native event streams — CloudTrail/EventGrid/
    Pub/Sub — for production latency; polling keeps the agent dependency-light)."""

    def __init__(self, cfg, queue):
        self.cfg, self.q, self.snap = cfg, queue, {}

    def _list(self, src: dict) -> Dict[str, str]:
        t = src["type"]
        if t == "aws_s3":
            import boto3
            out = {}
            for page in boto3.client("s3").get_paginator("list_objects_v2").paginate(Bucket=src["bucket"], Prefix=src.get("prefix", "")):
                for o in page.get("Contents", []):
                    out[f"s3://{src['bucket']}/{o['Key']}"] = o["ETag"]
            return out
        if t == "azure_blob":
            from azure.storage.blob import BlobServiceClient
            c = BlobServiceClient.from_connection_string(src["connection_string"]).get_container_client(src["container"])
            return {f"azure://{src['container']}/{b.name}": b.etag for b in c.list_blobs()}
        if t == "gcp_gcs":
            from google.cloud import storage
            return {f"gs://{src['bucket']}/{b.name}": b.md5_hash for b in storage.Client().list_blobs(src["bucket"], prefix=src.get("prefix", ""))}
        return {}

    async def run(self, stop: asyncio.Event):
        if not self.cfg.get("monitors", "cloud", "enabled"):
            return
        every = self.cfg.get("monitors", "cloud", "poll_seconds", default=60)
        while not stop.is_set():
            for i, src in enumerate(self.cfg.get("monitors", "cloud", "sources", default=[])):
                try:
                    cur = await asyncio.to_thread(self._list, src)
                except Exception as exc:
                    log.error("cloud poll failed (%s): %s", src.get("type"), exc); continue
                prev = self.snap.get(i)
                if prev is not None:
                    for k in set(cur) | set(prev):
                        if cur.get(k) != prev.get(k):
                            op = "created" if k not in prev else "deleted" if k not in cur else "modified"
                            ev = FileEvent(EventType.CLOUD_CHANGE, k, sha256_before=prev.get(k), sha256_after=cur.get(k), user="cloud")
                            ev.meta["op"] = op
                            self.q.put_nowait(ev)
                self.snap[i] = cur
            try:
                await asyncio.wait_for(stop.wait(), timeout=every)
            except asyncio.TimeoutError:
                pass
