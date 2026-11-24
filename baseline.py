"""HMAC-signed baseline of critical files with verified atomic rollback."""
from __future__ import annotations
import hmac, hashlib, json, logging, os, secrets, shutil, tempfile
from pathlib import Path
from typing import Dict, Optional

from .util import sha256_file

log = logging.getLogger("ironsentinel.baseline")


class BaselineStore:
    """<dir>/index.json (path -> {sha256, mode}) + index.sig (HMAC-SHA256) + files/<sha256> (content-addressed copies).
    A tampered index fails HMAC verification and is refused. NOTE: a root attacker who can read the key can re-sign;
    for stronger guarantees, ship `index_digest()` to the SIEM/WORM store on every update (done by the agent)
    and keep the key in a TPM/HSM/KMS."""

    def __init__(self, directory: str, key_path: Optional[str] = None):
        self.dir = Path(directory)
        (self.dir / "files").mkdir(parents=True, exist_ok=True)
        self.key = self._key(Path(key_path) if key_path else self.dir / "signing.key")
        self.index: Dict[str, dict] = {}
        self.tampered = False
        self._load()

    @staticmethod
    def _key(p: Path) -> bytes:
        if p.exists():
            return p.read_bytes()
        p.parent.mkdir(parents=True, exist_ok=True)
        k = secrets.token_bytes(32)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k)
        return k

    def _sig(self, raw: bytes) -> bytes:
        return hmac.new(self.key, raw, hashlib.sha256).digest()

    def _load(self):
        ip, sp = self.dir / "index.json", self.dir / "index.sig"
        if not ip.exists():
            return
        raw = ip.read_bytes()
        if not sp.exists() or not hmac.compare_digest(self._sig(raw), sp.read_bytes()):
            self.tampered = True
            log.critical("Baseline index failed signature check — refusing to trust it")
            return
        self.index = json.loads(raw)

    def _save(self):
        raw = json.dumps(self.index, indent=1, sort_keys=True).encode()
        (self.dir / "index.json").write_bytes(raw)
        (self.dir / "index.sig").write_bytes(self._sig(raw))

    def index_digest(self) -> str:
        return hashlib.sha256(json.dumps(self.index, sort_keys=True).encode()).hexdigest()

    def add(self, path: str) -> Optional[str]:
        sha = sha256_file(path)
        if not sha:
            return None
        blob = self.dir / "files" / sha
        if not blob.exists():
            shutil.copy2(path, blob)
            os.chmod(blob, 0o400)
        self.index[path] = {"sha256": sha, "mode": os.stat(path).st_mode & 0o7777}
        self._save()
        return sha

    def add_tree(self, root: str) -> int:
        n = 0
        for dp, _, fs in os.walk(root):
            for f in fs:
                n += bool(self.add(os.path.join(dp, f)))
        return n

    def drift(self, path: str, actual_sha: Optional[str]) -> Optional[dict]:
        exp = self.index.get(path)
        if not exp or self.tampered:
            return None
        if actual_sha != exp["sha256"]:        # actual_sha None == file deleted
            return {"path": path, "expected": exp["sha256"], "actual": actual_sha}
        return None

    def restore(self, path: str) -> bool:
        exp = self.index.get(path)
        blob = self.dir / "files" / (exp["sha256"] if exp else "")
        if not exp or not blob.exists() or sha256_file(str(blob)) != exp["sha256"]:
            log.error("No verified baseline copy for %s", path)
            return False
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
        os.close(fd)
        try:
            shutil.copyfile(blob, tmp)
            os.chmod(tmp, exp["mode"])
            os.replace(tmp, path)             # atomic swap
            return sha256_file(path) == exp["sha256"]
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
