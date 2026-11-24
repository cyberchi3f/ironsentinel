"""Threat-intel enrichment: VirusTotal, MISP, OpenCTI (hashes) and AbuseIPDB (remote IPs). TTL-cached, parallel."""
from __future__ import annotations
import asyncio, logging, time
from typing import Any, Dict, List, Optional

import aiohttp

from .models import FileEvent
from .util import remote_ips_for_pid

log = logging.getLogger("ironsentinel.intel")
TIMEOUT = aiohttp.ClientTimeout(total=10)


class _Cache:
    def __init__(self, ttl=3600): self.ttl, self.d = ttl, {}
    def get(self, k):
        v = self.d.get(k); return v[1] if v and time.time() - v[0] < self.ttl else None
    def put(self, k, v): self.d[k] = (time.time(), v)


class VirusTotal:
    def __init__(self, key): self.key, self.c = key, _Cache(7200)
    async def hash(self, sha: str) -> Optional[Dict]:
        if (c := self.c.get(sha)) is not None: return c
        async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
            r = await s.get(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": self.key})
            if r.status == 404: out = {"source": "virustotal", "found": False, "malicious": False}
            elif r.status != 200: return None
            else:
                a = (await r.json())["data"]["attributes"]; st = a.get("last_analysis_stats", {})
                out = {"source": "virustotal", "found": True, "malicious": st.get("malicious", 0) >= 3,
                       "detections": st.get("malicious", 0), "engines": sum(st.values()),
                       "name": a.get("meaningful_name"), "family": (a.get("popular_threat_classification") or {}).get("suggested_threat_label")}
        self.c.put(sha, out); return out


class MISP:
    def __init__(self, url, key, verify=True): self.url, self.key, self.verify, self.c = url.rstrip("/"), key, verify, _Cache()
    async def hash(self, sha: str) -> Optional[Dict]:
        if (c := self.c.get(sha)) is not None: return c
        async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
            r = await s.post(f"{self.url}/attributes/restSearch", ssl=None if self.verify else False,
                             headers={"Authorization": self.key, "Accept": "application/json"},
                             json={"returnFormat": "json", "value": sha, "limit": 5, "to_ids": 1})
            if r.status != 200: return None
            attrs = (await r.json()).get("response", {}).get("Attribute", [])
        out = {"source": "misp", "found": bool(attrs), "malicious": bool(attrs)}
        if attrs: out.update(event_id=attrs[0].get("event_id"), category=attrs[0].get("category"),
                             tags=[t["name"] for t in attrs[0].get("Tag", [])])
        self.c.put(sha, out); return out


class OpenCTI:
    """Queries observables/indicators by SHA-256 over GraphQL. Filter syntax follows OpenCTI ≥6; adjust for older schemas."""
    Q = """query($f: FilterGroup){ stixCyberObservables(filters:$f, first:3){ edges{ node{ id observable_value
           x_opencti_score ... on StixFile { hashes{ algorithm hash } } } } } }"""
    def __init__(self, url, key, verify=True): self.url, self.key, self.verify, self.c = url.rstrip("/"), key, verify, _Cache()
    async def hash(self, sha: str) -> Optional[Dict]:
        if (c := self.c.get(sha)) is not None: return c
        flt = {"mode": "and", "filters": [{"key": "hashes.SHA-256", "values": [sha]}], "filterGroups": []}
        async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
            r = await s.post(f"{self.url}/graphql", ssl=None if self.verify else False,
                             headers={"Authorization": f"Bearer {self.key}"}, json={"query": self.Q, "variables": {"f": flt}})
            if r.status != 200: return None
            edges = ((await r.json()).get("data") or {}).get("stixCyberObservables", {}).get("edges", [])
        score = max([(e["node"].get("x_opencti_score") or 0) for e in edges], default=0)
        out = {"source": "opencti", "found": bool(edges), "malicious": score >= 70, "score": score}
        self.c.put(sha, out); return out


class AbuseIPDB:
    def __init__(self, key): self.key, self.c = key, _Cache()
    async def ip(self, ip: str) -> Optional[Dict]:
        if (c := self.c.get(ip)) is not None: return c
        async with aiohttp.ClientSession(timeout=TIMEOUT) as s:
            r = await s.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                            headers={"Key": self.key, "Accept": "application/json"})
            if r.status != 200: return None
            d = (await r.json())["data"]
        out = {"source": "abuseipdb", "found": d["totalReports"] > 0, "malicious": d["abuseConfidenceScore"] >= 75,
               "ip": ip, "score": d["abuseConfidenceScore"], "country": d.get("countryCode")}
        self.c.put(ip, out); return out


class IntelAggregator:
    def __init__(self, cfg):
        t = cfg.get("threat_intel", default={})
        self.hash_clients, self.ip_client = [], None
        if t["virustotal"]["enabled"]: self.hash_clients.append(VirusTotal(t["virustotal"]["api_key"]))
        if t["misp"]["enabled"]: self.hash_clients.append(MISP(t["misp"]["url"], t["misp"]["api_key"], t["misp"]["verify_tls"]))
        if t["opencti"]["enabled"]: self.hash_clients.append(OpenCTI(t["opencti"]["url"], t["opencti"]["api_key"], t["opencti"]["verify_tls"]))
        if t["abuseipdb"]["enabled"]: self.ip_client = AbuseIPDB(t["abuseipdb"]["api_key"])

    @property
    def active(self) -> bool: return bool(self.hash_clients or self.ip_client)

    async def enrich(self, ev: FileEvent) -> List[Dict[str, Any]]:
        jobs = []
        if ev.sha256_after: jobs += [c.hash(ev.sha256_after) for c in self.hash_clients]
        if self.ip_client and ev.pid:
            jobs += [self.ip_client.ip(ip) for ip in remote_ips_for_pid(ev.pid)[:5]]
        res = await asyncio.gather(*jobs, return_exceptions=True)
        for r in res:
            if isinstance(r, Exception): log.debug("intel lookup error: %s", r)
        return [r for r in res if isinstance(r, dict) and r.get("found")]
