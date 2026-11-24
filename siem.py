"""SIEM sinks. Wazuh: JSONL file read by the Wazuh agent's <localfile> (log_format json) and/or syslog to the manager.
ELK/OpenSearch: batched _bulk. Generic: syslog (CEF or JSON) over UDP/TCP — covers FortiAnalyzer/FortiSIEM, Splunk, QRadar, etc."""
from __future__ import annotations
import asyncio, json, logging, os, socket, time
from datetime import datetime, timezone
from typing import List

import aiohttp

from .models import Alert

log = logging.getLogger("ironsentinel.siem")


class JsonlSink:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    async def send(self, a: Alert):
        line = json.dumps(a.to_json(), default=str) + "\n"
        await asyncio.to_thread(self._write, line)

    def _write(self, line):
        with open(self.path, "a") as f:
            f.write(line)


class SyslogSink:
    def __init__(self, host, port=514, proto="udp", fmt="cef"):
        self.host, self.port, self.tcp, self.fmt = host, port, proto.lower() == "tcp", fmt.lower()

    def _frame(self, a: Alert) -> bytes:
        body = a.to_cef() if self.fmt == "cef" else json.dumps(a.to_json(), default=str)
        pri = 8 + (2 if a.threat_level >= 3 else 5)              # facility user, severity crit/notice
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        return f"<{pri}>{ts} {socket.gethostname()} ironsentinel: {body}\n".encode("utf-8", "replace")

    def _send(self, data: bytes):
        if self.tcp:
            with socket.create_connection((self.host, self.port), timeout=5) as s:
                s.sendall(data)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data[:8192], (self.host, self.port))

    async def send(self, a: Alert):
        await asyncio.to_thread(self._send, self._frame(a))


class ElasticSink:
    def __init__(self, url, index, user="", password="", verify=True, flush_s=5, batch=200):
        self.url, self.index, self.verify = url.rstrip("/"), index, verify
        self.auth = aiohttp.BasicAuth(user, password) if user else None
        self.buf: List[dict] = []; self.flush_s, self.batch, self.last = flush_s, batch, time.time()

    async def send(self, a: Alert):
        self.buf.append(a.to_json())
        if len(self.buf) >= self.batch or time.time() - self.last >= self.flush_s:
            await self.flush()

    async def flush(self):
        if not self.buf:
            return
        docs, self.buf, self.last = self.buf, [], time.time()
        idx = f"{self.index}-{datetime.now(timezone.utc):%Y.%m.%d}"
        body = "".join(json.dumps({"index": {"_index": idx}}) + "\n" + json.dumps(d, default=str) + "\n" for d in docs)
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                r = await s.post(f"{self.url}/_bulk", data=body, auth=self.auth, ssl=None if self.verify else False,
                                 headers={"Content-Type": "application/x-ndjson"})
                if r.status >= 300:
                    log.error("elastic bulk failed: %s %s", r.status, (await r.text())[:200])
        except Exception as exc:
            log.error("elastic unreachable: %s", exc)


class SiemDispatcher:
    def __init__(self, cfg):
        i = cfg.get("integrations", default={})
        self.sinks, self.audit_all = [], i.get("audit_all", True)
        w = i["wazuh"]
        if w["enabled"]:
            if w.get("jsonl_path"): self.sinks.append(JsonlSink(w["jsonl_path"]))
            if w.get("syslog_host"): self.sinks.append(SyslogSink(w["syslog_host"], w["syslog_port"], "udp", "json"))
        e = i["elk"]
        if e["enabled"]: self.sinks.append(ElasticSink(e["url"], e["index"], e["username"], e["password"], e["verify_tls"]))
        s = i["syslog"]
        if s["enabled"]: self.sinks.append(SyslogSink(s["host"], s["port"], s["protocol"], s["format"]))

    async def send(self, a: Alert):
        res = await asyncio.gather(*(s.send(a) for s in self.sinks), return_exceptions=True)
        for r in res:
            if isinstance(r, Exception): log.error("siem sink error: %s", r)

    async def close(self):
        for s in self.sinks:
            if hasattr(s, "flush"): await s.flush()
