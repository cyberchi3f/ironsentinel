# 🛡️ IronSentinel

**Threat-aware File Integrity Monitoring and EDR agent for Windows, Linux, macOS and cloud.**

IronSentinel treats a file change as *evidence in an attack chain*, not a line in a log. It combines signed baselines with auto-rollback, ransomware and behavioural detection, threat-intelligence enrichment and automated containment. It also includes **PADIE**, a predictive deception engine that works out where an attacker is heading next and plants a decoy there.

![Python](https://img.shields.io/badge/python-3.11%2B-blue) ![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey) ![Response](https://img.shields.io/badge/response-dry--run%20by%20default-green)

> Developed by **Simon Etim (Cyb3rchi3f)**

---

## Table of contents

- [Features](#features)
- [PADIE: the differentiator](#padie-the-differentiator)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Integrations](#integrations)
- [Automated response and safety](#automated-response-and-safety)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Responsible use](#responsible-use)
- [License](#license)

---

## Features

| Capability | What it does |
|---|---|
| **Contextual monitoring** | Tracks create, modify, delete, rename and permission changes with user, PID, process path, command line, before/after SHA-256, entropy delta, size and mode. Also covers Windows registry keys and AWS S3, Azure Blob and GCS inventories. |
| **Immutable protection** | Paths that must never change raise a CRITICAL alert on any change outside an approved maintenance window (overnight and per-path windows supported). |
| **Signed baselines and rollback** | HMAC-signed, content-addressed baseline. Drifted or deleted files are restored atomically and re-verified by hash. A tampered baseline index is refused. |
| **Ransomware detection** | Combines entropy jumps, modification bursts per PID or directory, known ransom extensions and ransom-note drops. Compressed formats (zip, jpg, docx and so on) are excluded from entropy checks to avoid false positives. |
| **Behavioural anomaly detection** | Per user and directory profile (first-seen, rare hour, off-hours, bulk operations) fused with an Isolation Forest that trains itself on your environment. |
| **Threat intelligence** | VirusTotal, MISP and OpenCTI hash lookups, plus AbuseIPDB checks on the remote peers of the writing process. TTL-cached to respect rate limits. |
| **Automated containment** | Kill process tree, quarantine, rollback, reversible network isolation, FortiGate quarantine group, Sophos Central isolation and custom playbooks. |
| **SIEM integration** | Wazuh, ELK / OpenSearch, and syslog in CEF or JSON (FortiAnalyzer, FortiSIEM, Splunk, QRadar, ArcSight). |

## PADIE: the differentiator

**Predictive Attack-chain Deception Injection Engine.**

Existing FIM and EDR tools react after the damage. Existing deception tools are static honeypots that don't know what the attacker is doing. PADIE uses the live attack sequence to decide *where to put the trap*:

1. **Build the session.** Events are mapped to MITRE ATT&CK techniques (for example `.aws/credentials`, `ntds.dit` or PowerShell activity) and grouped per actor, with a kill-chain score.
2. **Predict.** A Markov model over technique transitions predicts the next move. A built-in prior is blended online with transitions observed on your own hosts.
3. **Inject.** Once an actor reaches credential-access depth, PADIE plants decoys for the top predicted techniques: fake AWS keys, SSH keys, SAM/NTDS/LSASS artefacts, database configs and finance exports. Each decoy carries a unique canary ID and only random, inert secrets.
4. **Trip.** Any open, modify, rename or delete of a decoy becomes a `DECEPTION_HIT` (CRITICAL) with the actor's technique history attached, and triggers containment.

Safety rails: decoys never overwrite real files, are capped per session, expire with the session and are removed on shutdown. See [ARCHITECTURE.md](ARCHITECTURE.md) for details and limits.

## Architecture

```
 SENSORS                       PIPELINE (per event, async)                  OUTPUTS
┌──────────────────┐   ┌──────────────────────────────────────────┐   ┌───────────────────┐
│ File (watchdog)  │   │ 0 maintenance-window guard               │   │ SIEM              │
│ Registry (winreg)│   │ 1 immutable-path zero tolerance          │   │  Wazuh · ELK      │
│ Cloud inventory  │──►│ 2 signed-baseline drift ─► rollback      │──►│  Syslog CEF/JSON  │
│ External sensors │   │ 3 ransomware detector                    │   ├───────────────────┤
│  (auditd, Sysmon,│   │ 4 behaviour + Isolation Forest           │   │ CONTAINMENT       │
│   ETW, EndpointS)│   │ 5 threat intel                           │──►│  kill · quarantine│
└──────────────────┘   │ 6 PADIE: session → predict → decoy       │   │  restore · isolate│
                       │ 7 response engine (dry-run by default)   │   │  FortiGate/Sophos │
                       └──────────────────────────────────────────┘   └───────────────────┘
```

## Quick start

**Requirements:** Python 3.11+. Root/Administrator is needed only for live containment (isolation, killing other users' processes) and for watching protected paths.

```bash
git clone https://github.com/cyberchi3f/ironsentinel.git
cd ironsentinel
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python tests/smoke_test.py                              # verify everything works on your machine
python -m ironsentinel -c config/ironsentinel.yaml      # run in dry-run mode
```

Run for real only after reviewing the "would execute" log lines:

```bash
sudo python -m ironsentinel -c /etc/ironsentinel/ironsentinel.yaml --live
```

Optional dependencies: `scikit-learn` (Isolation Forest), `boto3`, `azure-storage-blob`, `google-cloud-storage` (cloud monitors), `pywin32` (Windows).

### Run as a service (Linux, systemd)

```ini
# /etc/systemd/system/ironsentinel.service
[Unit]
Description=IronSentinel integrity agent
After=network-online.target

[Service]
ExecStart=/opt/ironsentinel/.venv/bin/python -m ironsentinel -c /etc/ironsentinel/ironsentinel.yaml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

## Configuration

All settings live in one YAML file. See [`config/ironsentinel.yaml`](config/ironsentinel.yaml) for a complete example. The key sections:

```yaml
monitors:
  file:
    paths: [/etc, /var/www]
    immutable_paths: [/usr/bin, /usr/sbin]      # zero tolerance outside windows
maintenance_windows:                             # UTC
  - {start: "22:00", end: "02:00", days: [5, 6], paths: [/usr/bin]}
baseline: {paths: [/etc/ssh, /etc/sudoers.d], auto_rollback: true}
response:
  dry_run: true                                  # keep true until validated
  isolate_on: [ransomware, deception_hit]
  management_subnets: [10.10.0.0/24]             # always reachable during isolation
padie: {enabled: true, plant_roots: [/home/svc-backup, /var/backups]}
```

Keep API keys and passwords out of version control. Use environment-specific config files that are listed in `.gitignore`.

## Integrations

**Wazuh.** IronSentinel writes JSON lines to `/var/log/ironsentinel/alerts.json`. Add this to the Wazuh agent's `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/ironsentinel/alerts.json</location>
</localfile>
```

**ELK / OpenSearch.** Direct batched `_bulk` indexing into `ironsentinel-YYYY.MM.DD`, or ship the JSONL with Filebeat. Fields are namespaced as `ironsentinel.*`, `file.*`, `process.*`, `user.*`, `host.*`, `mitre.*`.

**Any SIEM (Splunk, QRadar, ArcSight, FortiSIEM, FortiAnalyzer).** Enable `integrations.syslog` with `format: cef` or `json` over UDP or TCP.

**FortiGate.** Create a REST API admin with a token, an address group `IronSentinel_Quarantine` and a top-priority deny policy that sources from that group. On isolation IronSentinel adds the host to the group via the FortiOS REST API.

**Sophos Central.** Create API credentials (client ID and secret). The agent authenticates, resolves your regional API host and isolates the endpoint by hostname.

**Threat intel.** Enable VirusTotal, MISP, OpenCTI and AbuseIPDB under `threat_intel` with your keys.

## Automated response and safety

| Detected event | Automatic actions |
|---|---|
| Ransomware behaviour | Kill process tree, isolate endpoint, restore from baseline, run playbooks |
| Decoy touched (PADIE) | Kill process tree, isolate endpoint, run playbooks |
| Immutable path or baseline drift | Restore from baseline, run playbooks |
| Threat-intel IOC match | Kill process tree, quarantine file, run playbooks |

Safety design:

- **Dry-run by default.** Nothing is killed, moved or blocked until you pass `--live`.
- **Reversible isolation.** Uses a dedicated firewall chain or rule set, never a flush of your rules. `management_subnets` and your SIEM and firewall hosts stay reachable.
- **Protected processes.** PID 1, the agent itself and core OS processes are never terminated.
- **Playbooks** are executables in `response.playbooks_dir` that receive `IS_PATH`, `IS_SHA256`, `IS_PID`, `IS_USER`, `IS_HOST`, `IS_EVENT` and `IS_LEVEL` as environment variables.

## Testing

```bash
python tests/smoke_test.py
```

The smoke test runs a real file watcher through the whole pipeline in a temporary sandbox and checks 11 behaviours: baseline drift and auto-rollback, immutable-path violation, ransomware burst detection, PADIE decoy planting and deception hit, maintenance-window suppression, CEF output, the Wazuh JSON sink, baseline signature validity and decoy cleanup.

## Project structure

```
ironsentinel/
├── ironsentinel/
│   ├── agent.py        orchestrator and pipeline
│   ├── monitors.py     file, registry and cloud sensors
│   ├── detection.py    ransomware, behaviour and anomaly scoring
│   ├── baseline.py     signed baseline and rollback
│   ├── intel.py        VirusTotal, MISP, OpenCTI, AbuseIPDB
│   ├── padie.py        predictive deception engine
│   ├── response.py     containment, FortiGate, Sophos
│   ├── siem.py         Wazuh, ELK, syslog sinks
│   ├── models.py       events, alerts, CEF/JSON serialisation
│   ├── config.py       YAML config with safe defaults
│   └── util.py         hashing, entropy, process attribution
├── config/ironsentinel.yaml
├── tests/smoke_test.py
├── ARCHITECTURE.md
└── requirements.txt
```

## Known limitations

- Process attribution polls open handles and is best-effort. For exact PIDs and read visibility, feed events from fanotify or auditd (Linux), Sysmon or ETW (Windows) or EndpointSecurity (macOS) using the same `FileEvent` format.
- The agent's own signing key lives on the host. A root-level attacker could re-sign the baseline, so for stronger guarantees keep the key in a TPM, HSM or KMS and ship the baseline digest to your SIEM.
- The PADIE transition prior is a starting point and improves as it learns from your environment.
- The FortiGate, Sophos and OpenCTI integrations follow the vendors' documented APIs but should be validated against your versions before production use.
- Single-host agent today. Fleet management is on the roadmap.

## Roadmap

- Native kernel-level sensors (fanotify, ETW, EndpointSecurity)
- Central manager with mTLS for fleet policy and pooled model training
- GNN-based attack-chain prediction and an LSTM sequence model
- Hardened service packaging (Windows PPL, signed binaries)
- Web dashboard and REST API

## Responsible use

IronSentinel is a defensive tool. Deploy it only on systems you own or are authorised to protect. Live containment actions can disrupt services, so validate in dry-run first and roll out in stages.

## License

Copyright © Simon Etim (Cyb3rchi3f). All rights reserved until a license is added to this repository.

---

**Author:** Simon Etim (Cyb3rchi3f) · [GitHub](https://github.com/cyberchi3f)
