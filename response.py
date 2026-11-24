"""Automated containment. SAFE BY DEFAULT: response.dry_run=true logs what *would* happen.
Actions: terminate process tree, quarantine file, rollback from signed baseline, isolate endpoint (reversible),
FortiGate quarantine group, Sophos Central isolation, operator playbooks."""
from __future__ import annotations
import asyncio, hashlib, json, logging, os, platform, shutil, socket, subprocess, time
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import aiohttp

from .baseline import BaselineStore
from .models import EventType, FileEvent
from .util import sha256_file

log = logging.getLogger("ironsentinel.response")
OS = platform.system().lower()
PROTECTED_NAMES = {"systemd", "init", "launchd", "wininit.exe", "csrss.exe", "lsass.exe", "services.exe", "sshd", "winlogon.exe"}


async def _run(*cmd, timeout=15) -> int:
    p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    try:
        return await asyncio.wait_for(p.wait(), timeout)
    except asyncio.TimeoutError:
        p.kill(); return -1


def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9)); return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class NetworkIsolator:
    """Reversible isolation using a dedicated chain/rule-set (never flushes the host firewall)."""
    CHAIN = "IRONSENTINEL_ISO"

    def __init__(self, allow: List[str]):
        self.allow = allow

    async def isolate(self) -> bool:
        if OS == "linux":
            await _run("iptables", "-N", self.CHAIN)
            rc = [await _run("iptables", "-F", self.CHAIN), await _run("iptables", "-A", self.CHAIN, "-o", "lo", "-j", "ACCEPT"),
                  await _run("iptables", "-A", self.CHAIN, "-i", "lo", "-j", "ACCEPT")]
            for a in self.allow:
                rc += [await _run("iptables", "-A", self.CHAIN, "-d", a, "-j", "ACCEPT"),
                       await _run("iptables", "-A", self.CHAIN, "-s", a, "-j", "ACCEPT")]
            rc.append(await _run("iptables", "-A", self.CHAIN, "-j", "DROP"))
            for hook in ("INPUT", "OUTPUT", "FORWARD"):
                if await _run("iptables", "-C", hook, "-j", self.CHAIN) != 0:
                    rc.append(await _run("iptables", "-I", hook, "1", "-j", self.CHAIN))
            return all(r == 0 for r in rc)
        if OS == "windows":
            ok = await _run("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound") == 0
            for a in self.allow:
                for d in ("in", "out"):
                    await _run("netsh", "advfirewall", "firewall", "add", "rule", f"name=IronSentinel_Allow_{d}_{a}",
                               f"dir={d}", "action=allow", f"remoteip={a}")
            return ok
        if OS == "darwin":
            rules = "block drop all\npass quick on lo0 all\n" + "".join(f"pass quick from {a} to any\npass quick from any to {a}\n" for a in self.allow)
            Path("/var/run/ironsentinel_pf.conf").write_text(rules)
            ok = await _run("pfctl", "-a", "ironsentinel", "-f", "/var/run/ironsentinel_pf.conf") == 0
            await _run("pfctl", "-e")      # requires `anchor "ironsentinel"` in /etc/pf.conf
            return ok
        return False

    async def release(self) -> bool:
        if OS == "linux":
            for hook in ("INPUT", "OUTPUT", "FORWARD"):
                await _run("iptables", "-D", hook, "-j", self.CHAIN)
            await _run("iptables", "-F", self.CHAIN)
            return await _run("iptables", "-X", self.CHAIN) == 0
        if OS == "windows":
            for a in self.allow:
                for d in ("in", "out"):
                    await _run("netsh", "advfirewall", "firewall", "delete", "rule", f"name=IronSentinel_Allow_{d}_{a}")
            return await _run("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound") == 0
        if OS == "darwin":
            return await _run("pfctl", "-a", "ironsentinel", "-F", "all") == 0
        return False


class FortiGate:
    def __init__(self, c):
        self.base, self.tok, self.vdom, self.grp, self.verify = f"https://{c['host']}/api/v2", c["api_token"], c["vdom"], c["quarantine_group"], c["verify_tls"]

    async def quarantine(self, ip: str, why: str) -> bool:
        name = f"IS_{ip.replace('.', '_')}"
        h = {"Authorization": f"Bearer {self.tok}"}
        q = {"vdom": self.vdom}
        try:
            async with aiohttp.ClientSession(headers=h, timeout=aiohttp.ClientTimeout(total=15)) as s:
                ssl = None if self.verify else False
                r = await s.post(f"{self.base}/cmdb/firewall/address", params=q, ssl=ssl,
                                 json={"name": name, "type": "ipmask", "subnet": f"{ip} 255.255.255.255", "comment": f"IronSentinel: {why}"[:255]})
                if r.status not in (200, 424):               # 424 / 500 => already exists
                    log.warning("fortigate address create: %s", r.status)
                r2 = await s.post(f"{self.base}/cmdb/firewall/addrgrp/{self.grp}/member", params=q, ssl=ssl, json={"name": name})
                return r2.status == 200
        except Exception as exc:
            log.error("fortigate error: %s", exc); return False


class Sophos:
    def __init__(self, c): self.id, self.secret, self.tok, self.tenant, self.api = c["client_id"], c["client_secret"], None, None, None

    async def _auth(self, s: aiohttp.ClientSession) -> bool:
        r = await s.post("https://id.sophos.com/api/v2/oauth2/token", data={"grant_type": "client_credentials", "client_id": self.id,
                         "client_secret": self.secret, "scope": "token"})
        if r.status != 200: return False
        self.tok = (await r.json())["access_token"]
        w = await (await s.get("https://api.central.sophos.com/whoami/v1", headers={"Authorization": f"Bearer {self.tok}"})).json()
        self.tenant, self.api = w["id"], w["apiHosts"]["dataRegion"]
        return True

    async def isolate(self, hostname: str) -> bool:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
                if not await self._auth(s): return False
                h = {"Authorization": f"Bearer {self.tok}", "X-Tenant-ID": self.tenant}
                items = (await (await s.get(f"{self.api}/endpoint/v1/endpoints", params={"hostnameContains": hostname}, headers=h)).json()).get("items", [])
                ids = [i["id"] for i in items if i.get("hostname", "").lower() == hostname.lower()] or [i["id"] for i in items[:1]]
                if not ids: return False
                r = await s.post(f"{self.api}/endpoint/v1/endpoints/isolation", headers=h,
                                 json={"enabled": True, "ids": ids, "comment": "IronSentinel automated containment"})
                return r.status in (200, 202)
        except Exception as exc:
            log.error("sophos error: %s", exc); return False


class ContainmentEngine:
    def __init__(self, cfg, baseline: Optional[BaselineStore], state_dir: str):
        self.cfg, self.baseline = cfg, baseline
        r = cfg.get("response", default={})
        self.dry = r.get("dry_run", True)
        self.vault = Path(state_dir) / "quarantine"
        allow = list(r.get("management_subnets", []))
        for u in (cfg.get("integrations", "elk", "url"), ):
            if u and cfg.get("integrations", "elk", "enabled"): allow.append(urlparse(u).hostname)
        for h in (cfg.get("integrations", "fortigate", "host"), cfg.get("integrations", "syslog", "host"), cfg.get("integrations", "wazuh", "syslog_host")):
            if h: allow.append(h)
        self.isolator = NetworkIsolator(sorted({a for a in allow if a}))
        i = cfg.get("integrations", default={})
        self.forti = FortiGate(i["fortigate"]) if i["fortigate"]["enabled"] else None
        self.sophos = Sophos(i["sophos"]) if i["sophos"]["enabled"] else None
        self.isolated = False

    async def terminate_tree(self, pid: int) -> str:
        import psutil
        if pid in (0, 1, os.getpid()):
            return f"terminate({pid}): refused (protected)"
        try:
            p = psutil.Process(pid)
            if p.name().lower() in PROTECTED_NAMES:
                return f"terminate({pid}:{p.name()}): refused (protected)"
            procs = p.children(recursive=True) + [p]
            for x in procs:
                try: x.kill()
                except psutil.Error: pass
            return f"terminate({pid}:{p.name()}): killed {len(procs)} process(es)"
        except psutil.NoSuchProcess:
            return f"terminate({pid}): already gone"
        except psutil.AccessDenied:
            return f"terminate({pid}): access denied"

    def quarantine(self, path: str, sha: Optional[str]) -> str:
        if not os.path.isfile(path): return f"quarantine({path}): missing"
        self.vault.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest = self.vault / f"{time.strftime('%Y%m%dT%H%M%S')}_{(sha or 'nohash')[:16]}_{os.path.basename(path)}.quar"
        shutil.move(path, dest); os.chmod(dest, 0o000)
        with open(self.vault / "manifest.jsonl", "a") as f:
            f.write(json.dumps({"original": path, "vault": str(dest), "sha256": sha, "ts": time.time()}) + "\n")
        return f"quarantine: {path} -> {dest}"

    async def run_playbooks(self, ev: FileEvent) -> List[str]:
        d = Path(self.cfg.get("response", "playbooks_dir", default=""))
        if not d.is_dir(): return []
        env = {**os.environ, "IS_PATH": ev.path, "IS_SHA256": ev.sha256_after or "", "IS_PID": str(ev.pid or ""), "IS_USER": ev.user or "",
               "IS_HOST": ev.hostname, "IS_EVENT": ev.event_type.value, "IS_LEVEL": ev.threat_level.name}
        out = []
        for pb in sorted(d.iterdir()):
            if pb.is_file() and os.access(pb, os.X_OK):
                p = await asyncio.create_subprocess_exec(str(pb), env=env, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                try: rc = await asyncio.wait_for(p.wait(), 60)
                except asyncio.TimeoutError: p.kill(); rc = -1
                out.append(f"playbook {pb.name}: rc={rc}")
        return out

    async def respond(self, ev: FileEvent, intel_malicious=False) -> List[str]:
        r = self.cfg.get("response", default={})
        t = ev.event_type
        plan = []
        if t == EventType.RANSOMWARE:               plan = ["terminate", "isolate", "rollback", "playbook"]
        elif t == EventType.DECEPTION_HIT:          plan = ["terminate", "isolate", "playbook"]
        elif t in (EventType.IMMUTABLE_VIOLATION, EventType.BASELINE_DRIFT): plan = ["rollback", "playbook"]
        elif intel_malicious:                       plan = ["terminate", "quarantine", "playbook"]
        if t.value not in r.get("isolate_on", []) and "isolate" in plan: plan.remove("isolate")
        if not r.get("terminate", True) and "terminate" in plan: plan.remove("terminate")
        if not r.get("quarantine", True) and "quarantine" in plan: plan.remove("quarantine")
        if not plan: return []
        if self.dry:
            return [f"DRY-RUN would execute: {', '.join(plan)}"]
        log_ = []
        if "terminate" in plan and ev.pid: log_.append(await self.terminate_tree(ev.pid))
        if "quarantine" in plan: log_.append(self.quarantine(ev.path, ev.sha256_after))
        if "rollback" in plan and self.baseline and ev.path in self.baseline.index:
            log_.append(f"rollback({ev.path}): {'OK' if await asyncio.to_thread(self.baseline.restore, ev.path) else 'FAILED'}")
        if "isolate" in plan and not self.isolated:
            self.isolated = await self.isolator.isolate()
            log_.append(f"isolate_endpoint: {'OK' if self.isolated else 'FAILED'} (allow={self.isolator.allow})")
            if self.forti: log_.append(f"fortigate_quarantine: {'OK' if await self.forti.quarantine(local_ip(), t.value) else 'FAILED'}")
            if self.sophos: log_.append(f"sophos_isolate: {'OK' if await self.sophos.isolate(ev.hostname) else 'FAILED'}")
        if "playbook" in plan: log_ += await self.run_playbooks(ev)
        return log_
