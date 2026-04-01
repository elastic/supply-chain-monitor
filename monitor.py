"""
Supply chain monitor for top PyPI and npm packages.

Polls PyPI and npm for new releases of the top N packages, diffs each new
release against its previous version, analyzes the diff with Cursor Agent
for signs of compromise, and alerts Slack if anything malicious is found.

Both ecosystems are monitored by default. Use --no-pypi or --no-npm to
disable one.

Usage:
    python monitor.py                          # monitor both PyPI and npm
    python monitor.py --top 15000              # top 15000 for each ecosystem
    python monitor.py --interval 120           # poll every 2 min
    python monitor.py --once                    # one-shot scan (no Slack by default)
    python monitor.py --slack                    # continuous, with Slack alerts
    python monitor.py --no-npm                 # PyPI only
    python monitor.py --no-pypi               # npm only
    python monitor.py --no-pypi --npm-top 5000 # npm only, top 5000
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import tempfile
import threading
import time
import traceback
import urllib.parse
import urllib.request
import xmlrpc.client
from datetime import datetime, timezone
from pathlib import Path

from analyze_diff import parse_verdict, run_cursor_agent
from package_diff import (
    collect_files,
    download_npm_package,
    download_package,
    extract_archive,
    generate_report,
    _label_from_archive,
)
from slack import Slack

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"monitor_{datetime.now().strftime('%Y%m%d')}.log"

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger("monitor")

PYPI_XMLRPC = "https://pypi.org/pypi"
PYPI_JSON = "https://pypi.org/pypi/{package}/json"
TOP_PACKAGES_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
)
LAST_SERIAL_PATH = Path(__file__).resolve().parent / "last_serial.yaml"

NPM_REPLICATE = "https://replicate.npmjs.com"
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_MAX_CHANGES_PER_CYCLE = 10000

_state_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_state_file(path: Path) -> dict[str, dict[str, str]]:
    """Parse the sectioned YAML state file into {section: {key: value}}."""
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    state: dict[str, dict[str, str]] = {}
    current_section: str | None = None
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped:
            continue
        if not stripped[0].isspace() and stripped.endswith(":"):
            current_section = stripped[:-1].strip()
            state.setdefault(current_section, {})
        elif current_section and ":" in stripped:
            key, _, value = stripped.partition(":")
            state[current_section][key.strip()] = value.strip()
    return state


def _save_state_section(path: Path, section: str, values: dict[str, str]) -> None:
    """Update one section of the state file, preserving other sections."""
    with _state_lock:
        state = _load_state_file(path)
        state[section] = values
        lines: list[str] = []
        for sec in state:
            lines.append(f"{sec}:")
            for k, v in state[sec].items():
                lines.append(f"  {k}: {v}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_last_serial(path: Path = LAST_SERIAL_PATH) -> int | None:
    """Read saved PyPI changelog serial from the state file."""
    state = _load_state_file(path)
    pypi = state.get("pypi", {})
    try:
        return int(pypi["serial"])
    except (KeyError, ValueError):
        return None


def save_last_serial(serial: int, path: Path = LAST_SERIAL_PATH) -> None:
    """Persist PyPI serial so the next run can resume."""
    _save_state_section(path, "pypi", {"serial": str(serial)})


def load_watchlist(top_n: int) -> dict[str, int]:
    """Return {package_name_lower: rank} for the top N packages."""
    log.info("Fetching top %s packages from hugovk dataset...", f"{top_n:,}")
    with urllib.request.urlopen(TOP_PACKAGES_URL) as resp:
        data = json.loads(resp.read())
    watchlist = {}
    for i, row in enumerate(data["rows"][:top_n], 1):
        watchlist[row["project"].lower()] = i
    log.info(
        "Watchlist loaded: %s packages (dataset updated %s)",
        f"{len(watchlist):,}",
        data["last_update"],
    )
    return watchlist


def get_previous_version(package: str, new_version: str) -> str | None:
    """Query PyPI JSON API to find the version released just before `new_version`."""
    url = PYPI_JSON.format(package=package)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception:
        log.warning("Failed to fetch version list for %s", package)
        return None

    releases = data.get("releases", {})
    # Filter to versions that have at least one file uploaded
    versions_with_files = [v for v, files in releases.items() if files]
    if new_version not in versions_with_files:
        versions_with_files.append(new_version)

    # Sort by upload time of earliest file in each release.
    # Versions missing from the releases dict (e.g. due to CDN cache lag)
    # get a max-value key so they sort last instead of first.
    def upload_time(v):
        files = releases.get(v, [])
        if not files:
            return "9999-12-31T23:59:59"
        timestamps = [f.get("upload_time_iso_8601", "") for f in files]
        return min(t for t in timestamps if t) if any(timestamps) else "9999-12-31T23:59:59"

    versions_with_files.sort(key=upload_time)

    try:
        idx = versions_with_files.index(new_version)
    except ValueError:
        return None

    if idx == 0:
        return None
    return versions_with_files[idx - 1]


def _diff_one_artifact(
    package: str, old_version: str, new_version: str,
    tmp: Path, packagetype: str,
) -> str | None:
    """Download, extract, and diff a single artifact type. Returns report or None."""
    tag = packagetype.replace("bdist_", "")
    try:
        archive_old = download_package(package, old_version, tmp / f"dl_old_{tag}", packagetype=packagetype)
        archive_new = download_package(package, new_version, tmp / f"dl_new_{tag}", packagetype=packagetype)
    except RuntimeError:
        return None

    root_old = extract_archive(archive_old, tmp / f"ext_old_{tag}")
    root_new = extract_archive(archive_new, tmp / f"ext_new_{tag}")

    files_old = collect_files(root_old)
    files_new = collect_files(root_new)

    label_old = _label_from_archive(archive_old)
    label_new = _label_from_archive(archive_new)

    return generate_report(package, label_old, label_new, files_old, files_new)


def diff_package(package: str, old_version: str, new_version: str) -> tuple[str | None, Path | None]:
    """Download, extract, and diff two versions. Returns (report_text, temp_dir) or (None, None).

    Diffs both wheel and sdist when both are available for the old and new
    version, so attacks hidden in only one artifact type are still caught.
    """
    safe_name = package.replace("/", "_").replace("@", "")
    tmp = Path(tempfile.mkdtemp(prefix=f"scm_{safe_name}_"))
    try:
        reports: list[str] = []
        for ptype in ("bdist_wheel", "sdist"):
            report = _diff_one_artifact(package, old_version, new_version, tmp, ptype)
            if report:
                reports.append(report)

        if not reports:
            raise RuntimeError(f"No common artifact types for {package} {old_version} / {new_version}")

        if len(reports) > 1:
            log.info("Diffed both wheel and sdist for %s", package)

        combined = "\n\n---\n\n".join(reports)
        return combined, tmp
    except Exception:
        log.error("Diff failed for %s %s->%s:\n%s", package, old_version, new_version, traceback.format_exc())
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None


def analyze_report(report: str, package: str, new_version: str) -> tuple[str, str]:
    """Write report to a temp workspace, run Cursor Agent, return (verdict, analysis)."""
    safe_name = package.replace("/", "_").replace("@", "")
    workspace = Path(tempfile.mkdtemp(prefix=f"scm_analyze_{safe_name}_"))
    diff_file = workspace / f"{safe_name}_diff.md"
    diff_file.write_text(report, encoding="utf-8")
    log.info("Diff written to %s", diff_file)
    try:
        raw_output = run_cursor_agent(diff_file)
        verdict, analysis = parse_verdict(raw_output)
    except Exception:
        log.error("Analysis failed for %s %s:\n%s", package, new_version, traceback.format_exc())
        log.error("Diff preserved at %s", diff_file)
        return "error", traceback.format_exc()
    else:
        shutil.rmtree(workspace, ignore_errors=True)
        return verdict, analysis


def send_slack_alert(
    package: str,
    version: str,
    rank: int,
    verdict: str,
    analysis: str,
    slack: bool = False,
    ecosystem: str = "pypi",
):
    """Send a Slack alert for a malicious package (only if slack=True)."""
    if ecosystem == "npm":
        eco_label = "npm"
        pkg_url = f"https://www.npmjs.com/package/{package}/v/{version}"
    else:
        eco_label = "PyPI"
        pkg_url = f"https://pypi.org/project/{package}/{version}/"

    header = f":rotating_light: *Supply Chain Alert: {package} {version}*"
    body = (
        f"{header}\n\n"
        f"*Rank:* #{rank:,} of top {eco_label} packages\n"
        f"*Verdict:* `{verdict.upper()}`\n"
        f"*{eco_label}:* {pkg_url}\n\n"
        f"*Analysis summary (truncated):*\n"
        f"```\n{analysis[:2800]}\n```"
    )

    if not slack:
        log.info("Slack disabled — alert not sent:\n%s", body)
        return

    try:
        s = Slack()
        s.SendMessage(s.channel, body)
        log.info("Slack alert sent for %s %s", package, version)
    except Exception:
        log.error("Failed to send Slack alert:\n%s", traceback.format_exc())


# ---------------------------------------------------------------------------
# npm registry helpers
# ---------------------------------------------------------------------------

def load_npm_state(path: Path = LAST_SERIAL_PATH) -> tuple[int | None, float | None]:
    """Read saved npm sequence and poll epoch from the state file."""
    state = _load_state_file(path)
    npm = state.get("npm", {})
    seq, epoch = None, None
    try:
        seq = int(npm["seq"])
    except (KeyError, ValueError):
        pass
    try:
        epoch = float(npm["epoch"])
    except (KeyError, ValueError):
        pass
    return seq, epoch


def save_npm_state(seq: int, epoch: float, path: Path = LAST_SERIAL_PATH) -> None:
    """Persist npm sequence and poll epoch so the next run can resume."""
    _save_state_section(path, "npm", {"seq": str(seq), "epoch": str(epoch)})


def load_npm_watchlist(top_n: int) -> dict[str, int]:
    """Return {package_name_lower: rank} for top N npm packages by download count.

    Downloads the ``download-counts`` npm package (nice-registry) which
    ships a ``counts.json`` mapping every npm package name to its monthly
    download count — analogous to hugovk/top-pypi-packages for PyPI.
    """
    log.info("Fetching top %s npm packages from download-counts dataset...", f"{top_n:,}")
    tmp = Path(tempfile.mkdtemp(prefix="npm_watchlist_"))
    try:
        meta_url = f"{NPM_REGISTRY}/download-counts/latest"
        with urllib.request.urlopen(meta_url, timeout=30) as resp:
            meta = json.loads(resp.read())
        tarball_url = meta["dist"]["tarball"]
        dataset_version = meta.get("version", "unknown")

        tarball_path = tmp / "download-counts.tgz"
        log.info("Downloading download-counts %s dataset...", dataset_version)
        urllib.request.urlretrieve(tarball_url, tarball_path)

        root = extract_archive(tarball_path, tmp / "ext")
        counts_file = root / "counts.json"
        if not counts_file.exists():
            raise FileNotFoundError(f"counts.json not found in {root}")

        log.info("Parsing counts.json...")
        counts: dict[str, int] = json.loads(counts_file.read_text(encoding="utf-8"))

        sorted_packages = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
        watchlist: dict[str, int] = {}
        for rank, (name, _count) in enumerate(sorted_packages, 1):
            watchlist[name.lower()] = rank

        log.info(
            "npm watchlist loaded: %s packages (download-counts %s)",
            f"{len(watchlist):,}", dataset_version,
        )
        return watchlist
    except Exception:
        log.error(
            "Failed to load download-counts dataset, falling back to search API:\n%s",
            traceback.format_exc(),
        )
        return _load_npm_watchlist_search(top_n)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _load_npm_watchlist_search(top_n: int) -> dict[str, int]:
    """Fallback: build watchlist from the npm search API (capped at ~5000)."""
    log.info("Fetching npm packages from registry search API (fallback)...")
    watchlist: dict[str, int] = {}
    page_size = 250
    for offset in range(0, top_n, page_size):
        remaining = min(page_size, top_n - offset)
        params = urllib.parse.urlencode({
            "text": "boost-exact:false",
            "popularity": "1.0",
            "quality": "0.0",
            "maintenance": "0.0",
            "size": str(remaining),
            "from": str(offset),
        })
        url = f"{NPM_SEARCH}?{params}"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception:
            log.warning("npm search API failed at offset %d, stopping", offset)
            break
        objects = data.get("objects", [])
        for i, obj in enumerate(objects, start=offset + 1):
            name = obj["package"]["name"]
            watchlist[name.lower()] = i
        if len(objects) < remaining:
            break
    log.info("npm watchlist loaded: %s packages (search API fallback)", f"{len(watchlist):,}")
    return watchlist


def npm_get_current_seq() -> int:
    """Get the current update_seq from the npm replication endpoint."""
    with urllib.request.urlopen(NPM_REPLICATE, timeout=15) as resp:
        data = json.loads(resp.read())
    return data["update_seq"]


def npm_poll_changes(since: int, limit: int = 500) -> tuple[list[dict], int]:
    """Fetch npm registry changes since a sequence number.

    Returns (results_list, last_seq).
    """
    url = f"{NPM_REPLICATE}/_changes?since={since}&limit={limit}"
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = json.loads(resp.read())
    return data.get("results", []), data.get("last_seq", since)


def npm_get_package_info(package: str) -> dict | None:
    """Fetch full package metadata (packument) from the npm registry."""
    encoded = urllib.parse.quote(package, safe="@")
    url = f"{NPM_REGISTRY}/{encoded}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception:
        log.warning("Failed to fetch npm info for %s", package)
        return None


def npm_detect_new_releases(package: str, since_epoch: float) -> list[str]:
    """Return versions of *package* published after *since_epoch*, oldest first."""
    info = npm_get_package_info(package)
    if not info:
        return []
    since_iso = datetime.fromtimestamp(since_epoch, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    time_map = info.get("time", {})
    new_versions = []
    for version, ts in time_map.items():
        if version in ("created", "modified"):
            continue
        if not isinstance(ts, str):
            continue
        if ts > since_iso:
            new_versions.append((version, ts))
    new_versions.sort(key=lambda x: x[1])
    return [v for v, _ in new_versions]


def npm_get_previous_version(package: str, new_version: str) -> str | None:
    """Query npm registry for the version published just before *new_version*."""
    info = npm_get_package_info(package)
    if not info:
        return None
    time_map = info.get("time", {})
    version_times = {
        v: t for v, t in time_map.items()
        if v not in ("created", "modified") and isinstance(t, str)
    }
    sorted_versions = sorted(version_times, key=lambda v: version_times[v])
    try:
        idx = sorted_versions.index(new_version)
    except ValueError:
        return None
    return sorted_versions[idx - 1] if idx > 0 else None


def npm_diff_package(
    package: str, old_version: str, new_version: str
) -> tuple[str | None, Path | None]:
    """Download, extract, and diff two npm package versions."""
    safe_name = package.replace("/", "_").replace("@", "")
    tmp = Path(tempfile.mkdtemp(prefix=f"scm_npm_{safe_name}_"))
    try:
        archive_old = download_npm_package(package, old_version, tmp / "dl_old")
        archive_new = download_npm_package(package, new_version, tmp / "dl_new")

        root_old = extract_archive(archive_old, tmp / "ext_old")
        root_new = extract_archive(archive_new, tmp / "ext_new")

        files_old = collect_files(root_old)
        files_new = collect_files(root_new)

        label_old = _label_from_archive(archive_old)
        label_new = _label_from_archive(archive_new)

        report = generate_report(package, label_old, label_new, files_old, files_new)
        return report, tmp
    except Exception:
        log.error(
            "npm diff failed for %s %s->%s:\n%s",
            package, old_version, new_version, traceback.format_exc(),
        )
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None


def process_npm_release(
    package: str, new_version: str, rank: int, slack: bool = False
) -> str:
    """Full pipeline for one npm release: diff -> analyze -> alert. Returns verdict."""
    log.info("[npm] Processing %s %s (rank #%s)...", package, new_version, f"{rank:,}")

    old_version = npm_get_previous_version(package, new_version)
    if not old_version:
        log.warning("[npm] No previous version found for %s, skipping diff", package)
        return "skipped"

    log.info("[npm] Diffing %s %s -> %s", package, old_version, new_version)
    report, tmp_dir = npm_diff_package(package, old_version, new_version)
    if not report:
        return "error"

    try:
        log.info("[npm] Analyzing diff for %s...", package)
        verdict, analysis = analyze_report(report, package, new_version)
        log.info("[npm] Verdict for %s %s: %s", package, new_version, verdict.upper())

        if verdict == "malicious":
            send_slack_alert(
                package, new_version, rank, verdict, analysis,
                slack=slack, ecosystem="npm",
            )

        return verdict
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Core loop — PyPI
# ---------------------------------------------------------------------------

def extract_new_releases(events: list, watchlist: dict[str, int]) -> list[tuple[str, str, int]]:
    """Return deduplicated [(package, version, timestamp)] for 'new release' events in the watchlist."""
    seen = set()
    releases = []
    for name, version, timestamp, action, serial_id in events:
        if action != "new release":
            continue
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        if name.lower() in watchlist:
            releases.append((name, version, timestamp))
    return releases


def process_release(package: str, new_version: str, rank: int, slack: bool = False) -> str:
    """Full pipeline for one release: diff -> analyze -> alert. Returns verdict."""
    log.info("[pypi] Processing %s %s (rank #%s)...", package, new_version, f"{rank:,}")

    old_version = get_previous_version(package, new_version)
    if not old_version:
        log.warning("[pypi] No previous version found for %s, skipping diff", package)
        return "skipped"

    log.info("[pypi] Diffing %s %s -> %s", package, old_version, new_version)
    report, tmp_dir = diff_package(package, old_version, new_version)
    if not report:
        return "error"

    try:
        log.info("[pypi] Analyzing diff for %s...", package)
        verdict, analysis = analyze_report(report, package, new_version)
        log.info("[pypi] Verdict for %s %s: %s", package, new_version, verdict.upper())

        if verdict == "malicious":
            send_slack_alert(package, new_version, rank, verdict, analysis, slack=slack)

        return verdict
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def poll_loop(
    watchlist: dict[str, int],
    interval: int,
    slack: bool = False,
    *,
    initial_serial: int | None = None,
    state_path: Path | None = None,
):
    state_path = state_path or LAST_SERIAL_PATH
    client = xmlrpc.client.ServerProxy(PYPI_XMLRPC)
    if initial_serial is not None:
        serial = initial_serial
        log.info("[pypi] Starting serial: %s (from --serial) — polling every %ss", f"{serial:,}", interval)
    else:
        loaded = load_last_serial(state_path)
        if loaded is not None:
            serial = loaded
            log.info(
                "[pypi] Starting serial: %s (from %s) — polling every %ss",
                f"{serial:,}",
                state_path.name,
                interval,
            )
        else:
            serial = client.changelog_last_serial()
            log.info(
                "[pypi] Starting serial: %s (PyPI head, no %s) — polling every %ss",
                f"{serial:,}",
                state_path.name,
                interval,
            )
    save_last_serial(serial, state_path)

    stats = {"checked": 0, "benign": 0, "malicious": 0, "error": 0, "skipped": 0}

    try:
        while True:
            try:
                events = client.changelog_since_serial(serial)
            except Exception:
                log.error("[pypi] Failed to fetch changelog:\n%s", traceback.format_exc())
                time.sleep(interval)
                continue

            if not events:
                time.sleep(interval)
                continue

            new_serial = max(e[4] for e in events)
            releases = extract_new_releases(events, watchlist)

            if releases:
                log.info(
                    "[pypi] %s new watchlist releases detected (serial %s -> %s)",
                    len(releases), f"{serial:,}", f"{new_serial:,}",
                )

            for package, version, ts in releases:
                rank = watchlist.get(package.lower(), 0)
                verdict = process_release(package, version, rank, slack=slack)
                stats["checked"] += 1
                stats[verdict] = stats.get(verdict, 0) + 1
                log.info("[pypi] Stats: %s", stats)

            serial = new_serial
            save_last_serial(serial, state_path)
            time.sleep(interval)

    except KeyboardInterrupt:
        log.info("[pypi] Stopped. Last serial: %s | Stats: %s", f"{serial:,}", stats)


def run_once(watchlist: dict[str, int], slack: bool = False, lookback_seconds: int = 600):
    client = xmlrpc.client.ServerProxy(PYPI_XMLRPC)
    current_serial = client.changelog_last_serial()
    estimated_start = max(0, current_serial - lookback_seconds * 15)

    log.info("[pypi] One-shot: checking events from serial %s to %s (~last %s min)",
             f"{estimated_start:,}", f"{current_serial:,}", lookback_seconds // 60)

    events = client.changelog_since_serial(estimated_start)
    if not events:
        log.info("[pypi] No events found.")
        return

    releases = extract_new_releases(events, watchlist)
    log.info("[pypi] %s new watchlist releases in window", len(releases))

    for package, version, ts in releases:
        rank = watchlist.get(package.lower(), 0)
        process_release(package, version, rank, slack=slack)


# ---------------------------------------------------------------------------
# Core loop — npm
# ---------------------------------------------------------------------------

def npm_poll_loop(
    watchlist: dict[str, int],
    interval: int,
    slack: bool = False,
    *,
    initial_seq: int | None = None,
    state_path: Path | None = None,
):
    state_path = state_path or LAST_SERIAL_PATH

    if initial_seq is not None:
        seq = initial_seq
        poll_epoch = time.time()
        log.info(
            "[npm] Starting seq: %s (from --npm-seq) — polling every %ss",
            f"{seq:,}", interval,
        )
    else:
        loaded_seq, loaded_epoch = load_npm_state(state_path)
        head_seq = npm_get_current_seq()
        if loaded_seq and head_seq - loaded_seq < NPM_MAX_CHANGES_PER_CYCLE:
            seq = loaded_seq
            poll_epoch = loaded_epoch or time.time()
            log.info(
                "[npm] Starting seq: %s (from %s) — polling every %ss",
                f"{seq:,}", state_path.name, interval,
            )
        else:
            if loaded_seq:
                log.warning(
                    "[npm] Saved seq %s is %s behind head — resetting to head",
                    f"{loaded_seq:,}", f"{head_seq - loaded_seq:,}",
                )
            seq = head_seq
            poll_epoch = time.time()
            log.info(
                "[npm] Starting seq: %s (registry head) — polling every %ss",
                f"{seq:,}", interval,
            )

    save_npm_state(seq, poll_epoch, state_path)
    stats = {"checked": 0, "benign": 0, "malicious": 0, "error": 0, "skipped": 0}

    try:
        while True:
            cycle_start = time.time()

            try:
                changed_packages: set[str] = set()
                current_seq = seq
                total_fetched = 0
                while total_fetched < NPM_MAX_CHANGES_PER_CYCLE:
                    results, new_seq = npm_poll_changes(current_seq)
                    for r in results:
                        pkg_id = r.get("id", "")
                        if not pkg_id.startswith("_design/") and pkg_id.lower() in watchlist:
                            changed_packages.add(pkg_id)
                    total_fetched += len(results)
                    if not results or new_seq == current_seq:
                        break
                    current_seq = new_seq
                seq = current_seq
            except Exception:
                log.error("[npm] Failed to fetch changes:\n%s", traceback.format_exc())
                time.sleep(interval)
                continue

            releases: list[tuple[str, str]] = []
            for pkg in changed_packages:
                try:
                    new_versions = npm_detect_new_releases(pkg, poll_epoch)
                    for ver in new_versions:
                        releases.append((pkg, ver))
                except Exception:
                    log.error("[npm] Error checking %s:\n%s", pkg, traceback.format_exc())

            if releases:
                log.info(
                    "[npm] %d new watchlist releases detected (seq -> %s)",
                    len(releases), f"{seq:,}",
                )

            for pkg, version in releases:
                rank = watchlist.get(pkg.lower(), 0)
                verdict = process_npm_release(pkg, version, rank, slack=slack)
                stats["checked"] += 1
                stats[verdict] = stats.get(verdict, 0) + 1
                log.info("[npm] Stats: %s", stats)

            poll_epoch = cycle_start
            save_npm_state(seq, poll_epoch, state_path)
            time.sleep(interval)

    except KeyboardInterrupt:
        log.info("[npm] Stopped. Last seq: %s | Stats: %s", f"{seq:,}", stats)


def npm_run_once(
    watchlist: dict[str, int],
    slack: bool = False,
    lookback_seconds: int = 600,
):
    """One-shot: check for npm releases published in the last *lookback_seconds*."""
    cutoff_epoch = time.time() - lookback_seconds
    current_seq = npm_get_current_seq()
    estimated_start = max(0, current_seq - lookback_seconds * 50)

    log.info(
        "[npm] One-shot: checking changes from seq %s to %s (~last %d min)",
        f"{estimated_start:,}", f"{current_seq:,}", lookback_seconds // 60,
    )

    changed_packages: set[str] = set()
    seq = estimated_start
    while True:
        results, new_seq = npm_poll_changes(seq)
        for r in results:
            pkg_id = r.get("id", "")
            if not pkg_id.startswith("_design/") and pkg_id.lower() in watchlist:
                changed_packages.add(pkg_id)
        if not results or new_seq == seq:
            break
        seq = new_seq

    log.info("[npm] %d watchlist packages changed in window", len(changed_packages))

    releases: list[tuple[str, str]] = []
    for pkg in changed_packages:
        try:
            new_versions = npm_detect_new_releases(pkg, cutoff_epoch)
            releases.extend((pkg, ver) for ver in new_versions)
        except Exception:
            log.error("[npm] Error checking %s:\n%s", pkg, traceback.format_exc())

    log.info("[npm] %d new watchlist releases to process", len(releases))

    for pkg, version in releases:
        rank = watchlist.get(pkg.lower(), 0)
        process_npm_release(pkg, version, rank, slack=slack)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Supply chain monitor (PyPI + npm)")
    parser.add_argument("--top", type=int, default=15000, help="Top N packages to watch per ecosystem (default: 15000)")
    parser.add_argument("--interval", type=int, default=300, help="Poll interval in seconds (default: 300)")
    parser.add_argument("--once", action="store_true", help="Single pass over recent events, then exit")
    parser.add_argument("--slack", action="store_true", help="Enable Slack alerts for malicious findings")
    parser.add_argument("--model", help="Override model for Cursor Agent analysis")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG logging (includes agent raw output)")

    pypi_group = parser.add_argument_group("PyPI options")
    pypi_group.add_argument("--no-pypi", action="store_true", help="Disable PyPI monitoring")
    pypi_group.add_argument("--serial", type=int, default=None, metavar="N",
                            help="PyPI changelog serial to start from")

    npm_group = parser.add_argument_group("npm options")
    npm_group.add_argument("--no-npm", action="store_true", help="Disable npm monitoring")
    npm_group.add_argument("--npm-top", type=int, default=None, metavar="N",
                           help="Top N npm packages to watch (default: same as --top)")
    npm_group.add_argument("--npm-seq", type=int, default=None, metavar="N",
                           help="npm replication sequence to start from")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    enable_pypi = not args.no_pypi
    enable_npm = not args.no_npm

    if not enable_pypi and not enable_npm:
        parser.error("Cannot disable both --no-pypi and --no-npm")

    if args.once:
        if enable_pypi:
            pypi_watchlist = load_watchlist(args.top)
            run_once(pypi_watchlist, slack=args.slack)
        if enable_npm:
            npm_top = args.npm_top or args.top
            npm_watchlist = load_npm_watchlist(npm_top)
            npm_run_once(npm_watchlist, slack=args.slack)
    else:
        threads: list[threading.Thread] = []

        if enable_pypi:
            pypi_watchlist = load_watchlist(args.top)
            t = threading.Thread(
                target=poll_loop,
                args=(pypi_watchlist, args.interval),
                kwargs={"slack": args.slack, "initial_serial": args.serial},
                daemon=True,
                name="pypi-poll",
            )
            threads.append(t)

        if enable_npm:
            npm_top = args.npm_top or args.top
            npm_watchlist = load_npm_watchlist(npm_top)
            t = threading.Thread(
                target=npm_poll_loop,
                args=(npm_watchlist, args.interval),
                kwargs={"slack": args.slack, "initial_seq": args.npm_seq},
                daemon=True,
                name="npm-poll",
            )
            threads.append(t)

        for t in threads:
            t.start()

        try:
            while any(t.is_alive() for t in threads):
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down (Ctrl+C)...")
            # Daemon threads will be cleaned up on exit


if __name__ == "__main__":
    main()
