"""Behavioural detection: ransomware (entropy + velocity + extension) and anomaly scoring."""
from __future__ import annotations
import math, os, time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import PurePath
from typing import Deque, Dict, List, Optional, Tuple

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None

from .models import EventType, FileEvent

# Compressed/encrypted-by-nature formats: high entropy here is NORMAL, so entropy alone is not evidence.
HIGH_ENTROPY_NATIVE = {".zip", ".gz", ".7z", ".rar", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".docx",
                       ".xlsx", ".pptx", ".pdf", ".xz", ".bz2", ".apk", ".jar"}
RANSOM_EXTS = {".locked", ".encrypted", ".enc", ".crypt", ".crypto", ".lockbit", ".ryk", ".akira", ".blackcat"}
RANSOM_NOTE_HINTS = ("readme", "decrypt", "restore_files", "how_to_recover", "recover_your")


def _ext(p: str) -> str:
    return PurePath(p).suffix.lower()


class RansomwareDetector:
    """Fuses independent signals; any single weak signal never fires alone.
       S1 entropy jump on a normally low-entropy file   S2 known ransom extension/rename
       S3 burst of modifications by one actor/dir       S4 ransom-note drop
       Compressed formats are excluded from S1 to avoid false positives."""

    def __init__(self, entropy_thr=7.2, burst=15, window_s=30):
        self.thr, self.burst, self.window = entropy_thr, burst, window_s
        self._hits: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=500))

    def _actor(self, ev: FileEvent) -> str:
        return f"pid:{ev.pid}" if ev.pid else f"dir:{os.path.dirname(ev.path)}"

    def assess(self, ev: FileEvent, now: Optional[float] = None) -> Tuple[bool, float, List[str]]:
        now = now or time.time()
        score, why = 0.0, []
        ext = _ext(ev.path)
        if ev.event_type in (EventType.FILE_MODIFIED, EventType.FILE_CREATED, EventType.FILE_RENAMED):
            jump = ev.entropy_after - ev.entropy_before
            if ext not in HIGH_ENTROPY_NATIVE and ev.entropy_after >= self.thr and jump >= 1.5:
                score = max(score, 0.55); why.append(f"entropy_jump={jump:.2f}")
                dq = self._hits[self._actor(ev)]
                dq.append(now)
                n = sum(1 for t in dq if now - t <= self.window)
                if n >= self.burst:
                    score = max(score, min(0.97, 0.80 + 0.01 * (n - self.burst))); why.append(f"burst={n}/{self.window}s")
            if ext in RANSOM_EXTS:
                score = max(score, 0.90); why.append(f"ransom_ext={ext}")
            if ev.event_type == EventType.FILE_CREATED and any(h in PurePath(ev.path).stem.lower() for h in RANSOM_NOTE_HINTS) and ext in {".txt", ".html", ".hta"}:
                score = max(score, 0.60); why.append("ransom_note_name")
        return score >= 0.80, score, why


class BehaviourProfiler:
    """Per-(user, directory) online profile: first-seen, off-hours, rare-hour, bulk-operation signals."""

    def __init__(self, business_hours=(8, 18), warmup_events=200):
        self.bh, self.warmup = business_hours, warmup_events
        self.seen: Dict[str, List[int]] = defaultdict(lambda: [0] * 24)
        self.total = 0
        self._recent: Deque[float] = deque(maxlen=1000)

    @staticmethod
    def key(ev: FileEvent) -> str:
        return f"{ev.user}|{os.path.dirname(ev.path)}"

    def score(self, ev: FileEvent, learn=True) -> Tuple[float, List[str]]:
        k, h, reasons, s = self.key(ev), ev.timestamp.hour, [], 0.0
        hist = self.seen[k]
        n = sum(hist)
        off = ev.timestamp.weekday() >= 5 or not (self.bh[0] <= h < self.bh[1])
        if off:
            s += 0.25; reasons.append("off_hours")
        if self.total >= self.warmup:           # don't cry wolf while still learning
            if n == 0:
                s += 0.35; reasons.append("first_seen_user_path")
            elif hist[h] / n < 0.02:
                s += 0.20; reasons.append("rare_hour_for_entity")
        now = ev.timestamp.timestamp()
        self._recent.append(now)
        burst = sum(1 for t in self._recent if now - t <= 10)
        if burst >= 50:
            s += 0.30; reasons.append(f"bulk_ops={burst}/10s")
        if ev.event_type == EventType.PERM_CHANGED:
            s += 0.15; reasons.append("permission_change")
        if learn:
            hist[h] += 1; self.total += 1
        return min(s, 1.0), reasons


class AnomalyScorer:
    """Behaviour profile fused with an Isolation Forest once enough data has been seen."""

    FEATS = 8

    def __init__(self, cfg_ml: dict):
        self.profiler = BehaviourProfiler(tuple(cfg_ml.get("business_hours", (8, 18))))
        self.buf: List[np.ndarray] = []
        self.model = None
        self.retrain_every = 2000

    @staticmethod
    def vec(ev: FileEvent) -> np.ndarray:
        t = ev.timestamp
        return np.array([t.hour, t.weekday(), ev.entropy_after, ev.entropy_after - ev.entropy_before,
                         len(PurePath(ev.path).parts), list(EventType).index(ev.event_type),
                         1.0 if ev.pid else 0.0, math.log10((ev.meta.get("size") or 0) + 1)], dtype=float)

    def score(self, ev: FileEvent) -> Tuple[float, List[str]]:
        base, reasons = self.profiler.score(ev)
        v = self.vec(ev)
        self.buf.append(v)
        if IsolationForest and len(self.buf) >= self.retrain_every and len(self.buf) % self.retrain_every == 0:
            self.model = IsolationForest(n_estimators=150, contamination=0.02, random_state=7).fit(np.vstack(self.buf[-20000:]))
        if self.model is not None:
            iso = float(np.clip(0.5 - self.model.decision_function(v.reshape(1, -1))[0] * 2, 0, 1))
            if iso > 0.7:
                reasons.append(f"iforest={iso:.2f}")
            return 0.6 * base + 0.4 * iso, reasons
        return base, reasons
