"""
Monitor top PyPI packages for new releases using changelog_since_serial.

Workflow:
  1. Fetch the top N packages from hugovk's dataset (watchlist).
  2. Get the current PyPI serial number.
  3. Poll changelog_since_serial() periodically.
  4. Filter events to only those matching the watchlist.
  5. Print new releases in real time.

Usage:
  python pypi_monitor.py                 # monitor top 1000, poll every 120s
  python pypi_monitor.py --top 5000      # monitor top 5000
  python pypi_monitor.py --interval 60   # poll every 60s
  python pypi_monitor.py --once          # single check (last 10 min), then exit
"""

import argparse
import json
import time
import urllib.request
import xmlrpc.client
from datetime import datetime, timezone

PYPI_XMLRPC = "https://pypi.org/pypi"
TOP_PACKAGES_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
)

RELEASE_ACTIONS = {"new release", "add source file", "add py2 file", "add py3 file"}


def load_watchlist(top_n: int) -> set[str]:
    print(f"[*] Fetching top {top_n:,} packages from hugovk dataset...")
    with urllib.request.urlopen(TOP_PACKAGES_URL) as resp:
        data = json.loads(resp.read())
    names = {row["project"].lower() for row in data["rows"][:top_n]}
    print(f"[+] Watchlist loaded: {len(names):,} packages (dataset updated {data['last_update']})")
    return names


def get_client() -> xmlrpc.client.ServerProxy:
    return xmlrpc.client.ServerProxy(PYPI_XMLRPC)


def fmt_time(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def check_updates(client, since_serial: int, watchlist: set[str]) -> int:
    events = client.changelog_since_serial(since_serial)
    if not events:
        return since_serial

    max_serial = since_serial
    seen = set()

    for name, version, timestamp, action, serial_id in events:
        max_serial = max(max_serial, serial_id)

        if not any(kw in action for kw in ("new release", "add ", "create")):
            continue

        key = (name.lower(), version, action)
        if key in seen:
            continue
        seen.add(key)

        if name.lower() in watchlist:
            print(f"  [{fmt_time(timestamp)}] {name} {version} — {action} (serial {serial_id})")

    return max_serial


def run_once(client, watchlist: set[str], lookback_seconds: int = 600):
    """Single check: get events from the last `lookback_seconds`."""
    current_serial = client.changelog_last_serial()
    # Estimate a serial from ~lookback_seconds ago. PyPI averages ~5-10 events/sec.
    estimated_start = max(0, current_serial - lookback_seconds * 15)

    print(f"[*] Checking events from serial {estimated_start:,} to {current_serial:,} (~last {lookback_seconds // 60} min)...")
    events = client.changelog_since_serial(estimated_start)

    if not events:
        print("[+] No events found.")
        return

    matches = []
    seen = set()
    for name, version, timestamp, action, serial_id in events:
        if not any(kw in action for kw in ("new release", "add ", "create")):
            continue
        key = (name.lower(), version, action)
        if key in seen:
            continue
        seen.add(key)
        if name.lower() in watchlist:
            matches.append((timestamp, name, version, action, serial_id))

    print(f"[+] {len(events):,} total events, {len(matches)} matched watchlist:\n")
    if matches:
        print(f"  {'Time':<24} {'Package':<30} {'Version':<16} {'Action'}")
        print(f"  {'-'*24} {'-'*30} {'-'*16} {'-'*30}")
        for ts, name, ver, action, sid in sorted(matches):
            print(f"  {fmt_time(ts):<24} {name:<30} {ver:<16} {action}")
    else:
        print("  (no watchlist packages updated)")


def monitor(watchlist: set[str], interval: int):
    client = get_client()
    serial = client.changelog_last_serial()
    print(f"[*] Starting serial: {serial:,}")
    print(f"[*] Polling every {interval}s. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(interval)
            now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            print(f"[{now}] Checking since serial {serial:,}...")
            new_serial = check_updates(client, serial, watchlist)
            if new_serial == serial:
                print("  (no new watchlist releases)")
            serial = new_serial
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Last serial: {serial:,}")


def main():
    parser = argparse.ArgumentParser(description="Monitor top PyPI packages for new releases")
    parser.add_argument("--top", type=int, default=1000, help="Number of top packages to watch (default: 1000)")
    parser.add_argument("--interval", type=int, default=120, help="Poll interval in seconds (default: 120)")
    parser.add_argument("--once", action="store_true", help="Single check (last ~10 min), then exit")
    args = parser.parse_args()

    watchlist = load_watchlist(args.top)
    client = get_client()

    if args.once:
        run_once(client, watchlist)
    else:
        monitor(watchlist, args.interval)


if __name__ == "__main__":
    main()
