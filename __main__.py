import argparse, asyncio
from .agent import IronSentinel
from .config import Config

def main():
    ap = argparse.ArgumentParser(prog="ironsentinel", description="IronSentinel — Threat-Aware Integrity Platform (Simon Etim / Cyb3rchi3f)")
    ap.add_argument("-c", "--config", default="/etc/ironsentinel/ironsentinel.yaml")
    ap.add_argument("--live", action="store_true", help="disable dry-run: execute containment actions for real")
    a = ap.parse_args()
    cfg = Config(a.config, {"response": {"dry_run": False}} if a.live else None)
    asyncio.run(IronSentinel(cfg).run())

if __name__ == "__main__":
    main()
