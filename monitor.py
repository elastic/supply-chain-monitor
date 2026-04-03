# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Supply chain monitor for top PyPI and npm packages, and Chrome extensions.

Polls PyPI and npm for new releases of the top N packages, diffs each new
release against its previous version, analyzes the diff with Cursor Agent
for signs of compromise, and alerts Slack if anything malicious is found.

Chrome extension monitoring uses a YAML watchlist file (chrome_extensions.yaml)
that maps extension IDs to their last known versions. Extensions are cached
locally so that old versions are available for diffing when updates arrive.

All ecosystems are monitored by default when their configuration exists.
Use --no-pypi, --no-npm, or --no-chrome-extensions to disable individual ones.
Chrome extension monitoring is enabled automatically when chrome_extensions.yaml exists.

Usage:
    python monitor.py                              # monitor all available ecosystems
    python monitor.py --top 15000                  # top 15000 packages for PyPI/npm
    python monitor.py --interval 120               # poll every 2 min
    python monitor.py --once                       # one-shot scan, then exit
    python monitor.py --slack                      # enable Slack alerts
    python monitor.py --model claude-4-opus        # override LLM model
    python monitor.py -v                           # verbose: show diffs + agent info
    python monitor.py --debug                      # full debug logging

    python monitor.py --no-pypi                    # npm + Chrome extensions only
    python monitor.py --no-npm                     # PyPI + Chrome extensions only
    python monitor.py --no-chrome-extensions        # PyPI + npm only
    python monitor.py --serial 35542000            # PyPI: start from specific serial
    python monitor.py --npm-top 5000               # npm: watch top 5000 only
    python monitor.py --npm-seq 42817000           # npm: start from specific sequence

    python monitor.py --chrome-extensions-init     # seed the extension cache (one-time)
    python monitor.py --chrome-extensions-file f.yaml  # custom watchlist path
    python monitor.py --chrome-extensions-cache /tmp/c # custom cache directory
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

import yaml

from analyze_diff import parse_verdict, run_cursor_agent
from chrome_diff import check_extension_version, download_crx, extract_crx
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

# Custom VERBOSE level between DEBUG(10) and INFO(20)
logging.VERBOSE = 15  # type: ignore[attr-defined]
logging.addLevelName(logging.VERBOSE, "VERBOSE")  # type: ignore[attr-defined]

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

EXTENSIONS_FILE_DEFAULT = Path(__file__).resolve().parent / "chrome_extensions.yaml"
EXTENSIONS_CACHE_DIR = Path(__file__).resolve().parent / "extensions_cache"

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


def analyze_report(
    report: str,
    package: str,
    new_version: str,
    *,
    model: str | None = None,
) -> tuple[str, str]:
    """Write report to a temp workspace, run Cursor Agent, return (verdict, analysis)."""
    effective_model = model or "composer-2-fast"
    safe_name = package.replace("/", "_").replace("@", "")
    workspace = Path(tempfile.mkdtemp(prefix=f"scm_analyze_{safe_name}_"))
    diff_file = workspace / f"{safe_name}_diff.md"
    diff_file.write_text(report, encoding="utf-8")
    log.info("Diff written to %s (%d bytes)", diff_file, len(report))

    if log.isEnabledFor(logging.VERBOSE):  # type: ignore[attr-defined]
        log.log(logging.VERBOSE, "Diff report for %s %s:\n%s", package, new_version, report[:5000])  # type: ignore[attr-defined]

    try:
        raw_output, stderr = run_cursor_agent(diff_file, model=effective_model)
        verdict, analysis = parse_verdict(raw_output)

        if log.isEnabledFor(logging.VERBOSE):  # type: ignore[attr-defined]
            log.log(logging.VERBOSE, "Agent model: %s", effective_model)  # type: ignore[attr-defined]
            if stderr:
                log.log(logging.VERBOSE, "Agent stderr:\n%s", stderr.strip())  # type: ignore[attr-defined]
            log.log(logging.VERBOSE, "Agent output for %s %s:\n%s", package, new_version, analysis[:5000])  # type: ignore[attr-defined]

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
    elif ecosystem == "chrome":
        eco_label = "Chrome Extension"
        pkg_url = f"https://chromewebstore.google.com/detail/{package}"
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
    package: str,
    new_version: str,
    rank: int,
    slack: bool = False,
    *,
    model: str | None = None,
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
        verdict, analysis = analyze_report(report, package, new_version, model=model)
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


def process_release(
    package: str,
    new_version: str,
    rank: int,
    slack: bool = False,
    *,
    model: str | None = None,
) -> str:
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
        verdict, analysis = analyze_report(report, package, new_version, model=model)
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
    model: str | None = None,
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
                verdict = process_release(
                    package, version, rank, slack=slack, model=model,
                )
                stats["checked"] += 1
                stats[verdict] = stats.get(verdict, 0) + 1
                log.info("[pypi] Stats: %s", stats)

            serial = new_serial
            save_last_serial(serial, state_path)
            time.sleep(interval)

    except KeyboardInterrupt:
        log.info("[pypi] Stopped. Last serial: %s | Stats: %s", f"{serial:,}", stats)


def run_once(
    watchlist: dict[str, int],
    slack: bool = False,
    lookback_seconds: int = 600,
    *,
    since_serial: int | None = None,
    model: str | None = None,
):
    client = xmlrpc.client.ServerProxy(PYPI_XMLRPC)
    current_serial = client.changelog_last_serial()
    if since_serial is not None:
        estimated_start = max(0, since_serial)
        log.info(
            "[pypi] One-shot: checking events from serial %s to %s (from --serial)",
            f"{estimated_start:,}", f"{current_serial:,}",
        )
    else:
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
        process_release(package, version, rank, slack=slack, model=model)


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
    model: str | None = None,
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
                verdict = process_npm_release(
                    pkg, version, rank, slack=slack, model=model,
                )
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
    *,
    model: str | None = None,
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
        process_npm_release(pkg, version, rank, slack=slack, model=model)


# ---------------------------------------------------------------------------
# Chrome extension helpers
# ---------------------------------------------------------------------------

def load_extensions_watchlist(path: Path) -> list[dict]:
    """Load the Chrome extensions watchlist from a YAML file.

    Each entry must have at least an 'id' key.  'version' and 'name' are
    optional (version defaults to "" which triggers a first-run cache).
    """
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"extensions watchlist must be a YAML list, got {type(data).__name__}")
    for entry in data:
        if "id" not in entry:
            raise ValueError(f"Extension entry missing 'id': {entry}")
        entry.setdefault("version", "")
        entry.setdefault("name", entry["id"])
    return data


def save_extensions_watchlist(path: Path, extensions: list[dict]) -> None:
    """Write the extensions watchlist back to YAML, preserving the header comment."""
    # Preserve leading comment lines from the original file
    header_lines: list[str] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("#"):
                header_lines.append(line)
            else:
                break

    with _state_lock:
        body = yaml.dump(extensions, default_flow_style=False, allow_unicode=True, sort_keys=False)
        content = "\n".join(header_lines) + "\n" + body if header_lines else body
        path.write_text(content, encoding="utf-8")


def update_extension_version(path: Path, ext_id: str, new_version: str) -> None:
    """Update the version of a single extension in the watchlist file."""
    extensions = load_extensions_watchlist(path)
    for entry in extensions:
        if entry["id"] == ext_id:
            entry["version"] = new_version
            break
    save_extensions_watchlist(path, extensions)


def process_extension_update(
    ext_id: str,
    name: str,
    old_version: str,
    new_version: str,
    codebase_url: str,
    cache_dir: Path,
    slack: bool = False,
    *,
    model: str | None = None,
) -> str:
    """Full pipeline for one extension update: download -> diff -> analyze -> alert."""
    log.info("[chrome] Processing %s (%s) %s -> %s...", name, ext_id, old_version, new_version)

    old_root = cache_dir / ext_id / old_version
    if not old_root.exists() or not any(old_root.iterdir()):
        log.warning("[chrome] Cached version %s not found for %s, treating as first run", old_version, name)
        return "skipped"

    safe_name = ext_id[:16]
    tmp = Path(tempfile.mkdtemp(prefix=f"scm_chrome_{safe_name}_"))
    try:
        crx_path = download_crx(codebase_url, tmp / "dl")
        new_root = extract_crx(crx_path, tmp / "ext_new")

        files_old = collect_files(old_root)
        files_new = collect_files(new_root)

        report = generate_report(name, old_version, new_version, files_old, files_new)

        log.info("[chrome] Analyzing diff for %s...", name)
        verdict, analysis = analyze_report(report, name, new_version, model=model)
        log.info("[chrome] Verdict for %s %s: %s", name, new_version, verdict.upper())

        if verdict == "malicious":
            send_slack_alert(
                name, new_version, 0, verdict, analysis,
                slack=slack, ecosystem="chrome",
            )

        # Update cache: store new version, remove old
        new_cache = cache_dir / ext_id / new_version
        if new_cache.exists():
            shutil.rmtree(new_cache)
        shutil.copytree(new_root, new_cache)
        shutil.rmtree(old_root, ignore_errors=True)

        return verdict
    except Exception:
        log.error(
            "[chrome] Failed to process %s %s->%s:\n%s",
            name, old_version, new_version, traceback.format_exc(),
        )
        return "error"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _cache_extension(
    ext_id: str, name: str, version: str, codebase_url: str, cache_dir: Path,
) -> bool:
    """Download and cache an extension version for future diffing. Returns True on success."""
    log.info("[chrome] First run for %s — caching version %s (no diff)", name, version)
    tmp = Path(tempfile.mkdtemp(prefix=f"scm_chrome_cache_{ext_id[:16]}_"))
    try:
        crx_path = download_crx(codebase_url, tmp / "dl")
        extracted = extract_crx(crx_path, tmp / "ext")
        dest = cache_dir / ext_id / version
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(extracted, dest)
        return True
    except Exception:
        log.error("[chrome] Failed to cache %s %s:\n%s", name, version, traceback.format_exc())
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def chrome_poll_loop(
    extensions_file: Path,
    cache_dir: Path,
    interval: int,
    slack: bool = False,
    *,
    model: str | None = None,
):
    """Continuously poll Chrome Web Store for extension updates."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    log.info("[chrome] Starting Chrome extension monitor — polling every %ss", interval)

    stats = {"checked": 0, "benign": 0, "malicious": 0, "error": 0, "skipped": 0, "first_run": 0}

    try:
        while True:
            try:
                extensions = load_extensions_watchlist(extensions_file)
            except Exception:
                log.error("[chrome] Failed to load watchlist:\n%s", traceback.format_exc())
                time.sleep(interval)
                continue

            if not extensions:
                log.debug("[chrome] Watchlist is empty, sleeping")
                time.sleep(interval)
                continue

            for ext in extensions:
                ext_id = ext["id"]
                name = ext.get("name", ext_id)
                stored_version = ext.get("version", "")

                try:
                    latest_version, codebase_url = check_extension_version(ext_id)
                except Exception:
                    log.error("[chrome] Failed to check %s:\n%s", name, traceback.format_exc())
                    stats["error"] += 1
                    time.sleep(0.5)
                    continue

                if stored_version == latest_version:
                    log.debug("[chrome] %s is up to date (%s)", name, latest_version)
                    time.sleep(0.5)
                    continue

                stats["checked"] += 1
                cached_old = cache_dir / ext_id / stored_version

                if not stored_version or not cached_old.exists():
                    # First run or missing cache — cache inline but suggest --chrome-extensions-init
                    log.warning(
                        "[chrome] %s not cached — caching now (use --chrome-extensions-init for bulk setup)",
                        name,
                    )
                    if _cache_extension(ext_id, name, latest_version, codebase_url, cache_dir):
                        update_extension_version(extensions_file, ext_id, latest_version)
                        stats["first_run"] += 1
                    else:
                        stats["error"] += 1
                else:
                    verdict = process_extension_update(
                        ext_id, name, stored_version, latest_version,
                        codebase_url, cache_dir, slack=slack, model=model,
                    )
                    stats[verdict] = stats.get(verdict, 0) + 1
                    update_extension_version(extensions_file, ext_id, latest_version)

                log.info("[chrome] Stats: %s", stats)
                time.sleep(0.5)

            time.sleep(interval)

    except KeyboardInterrupt:
        log.info("[chrome] Stopped. Stats: %s", stats)


def chrome_run_once(
    extensions_file: Path,
    cache_dir: Path,
    slack: bool = False,
    *,
    model: str | None = None,
):
    """One-shot: check all watched extensions for updates."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    extensions = load_extensions_watchlist(extensions_file)

    if not extensions:
        log.info("[chrome] Watchlist is empty, nothing to check")
        return

    log.info("[chrome] One-shot: checking %d extensions", len(extensions))

    for ext in extensions:
        ext_id = ext["id"]
        name = ext.get("name", ext_id)
        stored_version = ext.get("version", "")

        try:
            latest_version, codebase_url = check_extension_version(ext_id)
        except Exception:
            log.error("[chrome] Failed to check %s:\n%s", name, traceback.format_exc())
            continue

        if stored_version == latest_version:
            log.info("[chrome] %s is up to date (%s)", name, latest_version)
            continue

        cached_old = cache_dir / ext_id / stored_version

        if not stored_version or not cached_old.exists():
            log.warning(
                "[chrome] %s not cached — caching now (use --chrome-extensions-init for bulk setup)",
                name,
            )
            if _cache_extension(ext_id, name, latest_version, codebase_url, cache_dir):
                update_extension_version(extensions_file, ext_id, latest_version)
        else:
            process_extension_update(
                ext_id, name, stored_version, latest_version,
                codebase_url, cache_dir, slack=slack, model=model,
            )
            update_extension_version(extensions_file, ext_id, latest_version)

        time.sleep(0.5)


def chrome_init(extensions_file: Path, cache_dir: Path) -> None:
    """Download and cache current versions of all watched extensions (one-time setup)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    extensions = load_extensions_watchlist(extensions_file)

    if not extensions:
        log.info("[chrome-init] Watchlist is empty, nothing to cache")
        return

    log.info("[chrome-init] Seeding cache for %d extensions...", len(extensions))
    cached, skipped, failed = 0, 0, 0
    failed_extensions: list[tuple[str, str, str]] = []  # (id, name, reason)

    for i, ext in enumerate(extensions, 1):
        ext_id = ext["id"]
        name = ext.get("name", ext_id)
        stored_version = ext.get("version", "")

        try:
            latest_version, codebase_url = check_extension_version(ext_id)
        except Exception as e:
            reason = str(e).split("\n", 1)[0]
            log.error("[chrome-init] %d/%d Failed to check %s (%s): %s", i, len(extensions), name, ext_id, reason)
            failed_extensions.append((ext_id, name, reason))
            failed += 1
            time.sleep(0.5)
            continue

        existing_cache = cache_dir / ext_id / latest_version
        if existing_cache.exists() and any(existing_cache.iterdir()):
            log.debug("[chrome-init] %d/%d %s %s already cached", i, len(extensions), name, latest_version)
            if stored_version != latest_version:
                update_extension_version(extensions_file, ext_id, latest_version)
            skipped += 1
        else:
            log.info("[chrome-init] %d/%d Caching %s %s...", i, len(extensions), name, latest_version)
            if _cache_extension(ext_id, name, latest_version, codebase_url, cache_dir):
                update_extension_version(extensions_file, ext_id, latest_version)
                cached += 1
            else:
                failed_extensions.append((ext_id, name, "download/extraction failed"))
                failed += 1

        time.sleep(0.5)

    log.info("[chrome-init] Done. Cached: %d | Already cached: %d | Failed: %d", cached, skipped, failed)
    if failed_extensions:
        log.warning("[chrome-init] The following %d extensions failed (may not exist in the Web Store):", len(failed_extensions))
        for ext_id, name, reason in failed_extensions:
            log.warning("[chrome-init]   %s (%s): %s", name, ext_id, reason)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Supply chain monitor (PyPI + npm + Chrome extensions)")
    parser.add_argument("--top", type=int, default=15000, help="Top N packages to watch per ecosystem (default: 15000)")
    parser.add_argument("--interval", type=int, default=300, help="Poll interval in seconds (default: 300)")
    parser.add_argument("--once", action="store_true", help="Single pass over recent events, then exit")
    parser.add_argument("--slack", action="store_true", help="Enable Slack alerts for malicious findings")
    parser.add_argument("--model", help="Override model for Cursor Agent analysis")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output: show diff reports, agent model, and agent stderr (token usage)")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG logging (includes full agent raw output)")

    pypi_group = parser.add_argument_group("PyPI options")
    pypi_group.add_argument("--no-pypi", action="store_true", help="Disable PyPI monitoring")
    pypi_group.add_argument("--serial", type=int, default=None, metavar="N",
                            help="PyPI changelog start serial (poll mode and --once)")

    npm_group = parser.add_argument_group("npm options")
    npm_group.add_argument("--no-npm", action="store_true", help="Disable npm monitoring")
    npm_group.add_argument("--npm-top", type=int, default=None, metavar="N",
                           help="Top N npm packages to watch (default: same as --top)")
    npm_group.add_argument("--npm-seq", type=int, default=None, metavar="N",
                           help="npm replication sequence to start from")

    chrome_group = parser.add_argument_group("Chrome extension options")
    chrome_group.add_argument("--no-chrome-extensions", action="store_true",
                              help="Disable Chrome extension monitoring")
    chrome_group.add_argument("--chrome-extensions-init", action="store_true",
                              help="Download and cache current versions of all watched extensions, then exit")
    chrome_group.add_argument("--chrome-extensions-file", type=Path, default=None, metavar="PATH",
                              help="Path to extensions watchlist YAML (default: chrome_extensions.yaml)")
    chrome_group.add_argument("--chrome-extensions-cache", type=Path, default=None, metavar="DIR",
                              help="Cache directory for extension versions (default: extensions_cache/)")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.VERBOSE)  # type: ignore[attr-defined]

    enable_pypi = not args.no_pypi
    enable_npm = not args.no_npm

    extensions_file = args.chrome_extensions_file or EXTENSIONS_FILE_DEFAULT
    cache_dir = args.chrome_extensions_cache or EXTENSIONS_CACHE_DIR
    enable_chrome = not args.no_chrome_extensions and extensions_file.exists()

    if args.chrome_extensions_init:
        if not extensions_file.exists():
            parser.error(f"Chrome extension watchlist not found: {extensions_file}")
        chrome_init(extensions_file, cache_dir)
        if not enable_chrome and not enable_pypi and not enable_npm:
            return

    if not enable_pypi and not enable_npm and not enable_chrome:
        parser.error("All ecosystems disabled (check --no-pypi/--no-npm/--no-chrome-extensions, or that chrome_extensions.yaml exists)")

    if args.once:
        if enable_pypi:
            pypi_watchlist = load_watchlist(args.top)
            run_once(
                pypi_watchlist,
                slack=args.slack,
                since_serial=args.serial,
                model=args.model,
            )
        if enable_npm:
            npm_top = args.npm_top or args.top
            npm_watchlist = load_npm_watchlist(npm_top)
            npm_run_once(npm_watchlist, slack=args.slack, model=args.model)
        if enable_chrome:
            chrome_run_once(extensions_file, cache_dir, slack=args.slack, model=args.model)
    else:
        threads: list[threading.Thread] = []

        if enable_pypi:
            pypi_watchlist = load_watchlist(args.top)
            t = threading.Thread(
                target=poll_loop,
                args=(pypi_watchlist, args.interval),
                kwargs={
                    "slack": args.slack,
                    "initial_serial": args.serial,
                    "model": args.model,
                },
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
                kwargs={
                    "slack": args.slack,
                    "initial_seq": args.npm_seq,
                    "model": args.model,
                },
                daemon=True,
                name="npm-poll",
            )
            threads.append(t)

        if enable_chrome:
            t = threading.Thread(
                target=chrome_poll_loop,
                args=(extensions_file, cache_dir, args.interval),
                kwargs={
                    "slack": args.slack,
                    "model": args.model,
                },
                daemon=True,
                name="chrome-poll",
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
