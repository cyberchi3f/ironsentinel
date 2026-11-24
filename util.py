"""Hashing, entropy, process/user attribution helpers."""
from __future__ import annotations
import getpass, hashlib, math, os
from typing import Optional, Tuple

try:
    import psutil
except ImportError:                       # degrade gracefully
    psutil = None


def sha256_file(path: str, chunk: int = 1 << 20) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def file_entropy(path: str, sample: int = 65536) -> float:
    try:
        with open(path, "rb") as f:
            return shannon_entropy_bytes(f.read(sample))
    except OSError:
        return 0.0


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def owner_of_pid(pid: int) -> Optional[str]:
    if psutil:
        try:
            return psutil.Process(pid).username()
        except Exception:
            return None
    return None


def process_holding(path: str, budget_s: float = 0.25) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Best-effort: which process has `path` open right now (pid, name, exe, cmdline).
    Polling open handles is racy; production sensors should use fanotify (Linux),
    ETW/Sysmon (Windows) or EndpointSecurity (macOS) for exact attribution."""
    if not psutil:
        return None, None, None, None
    import time
    target = os.path.normcase(os.path.abspath(path))
    me, deadline = os.getpid(), time.monotonic() + budget_s   # bounded cost per event
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        if time.monotonic() > deadline:
            break
        if p.info["pid"] == me:
            continue
        try:
            for f in p.open_files():
                if os.path.normcase(f.path) == target:
                    return p.info["pid"], p.info["name"], p.info["exe"], " ".join(p.info["cmdline"] or [])
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue
    return None, None, None, None


def remote_ips_for_pid(pid: int) -> list[str]:
    if not psutil or not pid:
        return []
    try:
        return sorted({c.raddr.ip for c in psutil.Process(pid).net_connections(kind="inet") if c.raddr})
    except Exception:
        return []
