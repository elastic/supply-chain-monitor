# Supply Chain Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Automated monitoring of the top **PyPI** and **npm** packages, and **Chrome extensions**, for supply chain compromise. Polls registries for new releases, diffs each release against its predecessor, and uses an LLM (via [Cursor Agent CLI](https://cursor.com/docs/cli/overview)) to classify diffs as **benign** or **malicious**. Malicious findings trigger a Slack alert.

All ecosystems are monitored by default when their configuration exists. Use `--no-pypi`, `--no-npm`, or `--no-chrome-extensions` to disable individual ones. Chrome extension monitoring is enabled automatically when `chrome_extensions.yaml` is present.

## How It Works

Each ecosystem runs its own polling thread but shares the analysis and alerting pipeline.

```
  ┌─── PyPI ─────────────────┐  ┌─── npm ──────────────────┐  ┌─── Chrome Extensions ─────┐
  │                          │  │                          │  │                           │
  │ changelog_since_serial() │  │ CouchDB _changes feed    │  │ CRX update check API      │
  │       │                  │  │       │                  │  │       │                   │
  │       ▼                  │  │       ▼                  │  │       ▼                   │
  │  ┌──────────┐            │  │  ┌──────────┐            │  │  ┌──────────┐              │
  │  │ All PyPI │─┐          │  │  │ All npm  │─┐          │  │  │ Version  │              │
  │  │ events   │ │          │  │  │ changes  │ │          │  │  │ changed? │              │
  │  └──────────┘ ▼          │  │  └──────────┘ ▼          │  │  └──────────┘              │
  │ hugovk ─► Watchlist      │  │ download-counts ─► WL    │  │ chrome_extensions.yaml ─► WL     │
  │       │                  │  │       │                  │  │       │                   │
  │ "new release" events     │  │ new versions since epoch │  │ version != stored version │
  └──────────┬───────────────┘  └──────────┬───────────────┘  └───────────┬───────────────┘
             │                             │                              │
             ▼                             ▼                              ▼
   ┌───────────────────┐         ┌───────────────────┐          ┌───────────────────┐
   │ Download old + new│         │ Download old + new│          │ Cached old + new  │
   │ (sdist + wheel)   │         │ (tarball)         │          │ (CRX → ZIP)       │
   └───────────────────┘         └───────────────────┘          └───────────────────┘
             │                             │                              │
             └─────────────────┬───────────┴──────────────────────────────┘
                               ▼
                       ┌───────────────┐
                       │ Unified diff  │
                       │ report (.md)  │
                       └───────┬───────┘
                               ▼
                       ┌───────────────┐  ◄── LLM analysis
                       │ Cursor Agent  │      (read-only)
                       │ CLI (ask mode)│
                       └───────┬───────┘
                               │
                           verdict?
                               │
                     malicious │
                               ▼
                       ┌───────────────┐
                       │ Slack alert   │
                       └───────────────┘
```

### Detection Targets

The LLM analysis is prompted to look for:

- Obfuscated code (base64, exec, eval, XOR, encoded strings)
- Network calls to unexpected hosts
- File system writes to startup/persistence locations
- Process spawning and shell commands
- Steganography or data hiding in media files
- Credential and token exfiltration
- Typosquatting indicators

## Prerequisites

- **Python 3.9+** — install runtime dependencies with `pip install -r requirements.txt` (stdlib covers most of the tool; `requests` is used for Slack uploads, `pyyaml` for the Chrome extensions watchlist)
- **Cursor Agent CLI** — the standalone `agent` binary, not the IDE

### Installing Cursor Agent CLI

**Windows (PowerShell):**
```powershell
irm 'https://cursor.com/install?win32=true' | iex
```

**macOS / Linux:**
```bash
curl https://cursor.com/install -fsS | bash
```

Verify with:
```bash
agent --version
```

You must be authenticated with Cursor (`agent login` or set `CURSOR_API_KEY`).

### Slack Configuration

Place your Slack bot token in `etc/slack.json`:

```json
{
    "url": "https://hooks.slack.com/services/...",
    "bot_token": "xoxb-...",
    "channel": "C01XXXXXXXX"
}
```

The bot needs `chat:write` scope on the target channel. The `channel` field is the Slack channel ID where alerts are posted.

### Chrome Extensions Watchlist

To monitor Chrome extensions, create an `chrome_extensions.yaml` file in the project root:

```yaml
# Chrome extension watchlist
- id: "cjpalhdlnbpafiamejdnhcphjbkeiagm"
  name: "uBlock Origin"
  version: ""
- id: "aeblfdkhhhdcdjpifhhbdiojplfjncoa"
  name: "1Password"
  version: ""
```

Each entry has:
- `id` — the 32-character Chrome extension ID (from the Web Store URL)
- `name` — human-readable name (optional, defaults to the ID)
- `version` — last known version. Set to `""` for first run; the monitor will download and cache the current version without diffing. Updated automatically on subsequent runs.

Before monitoring, seed the cache with current versions using `--chrome-extensions-init`:

```bash
# One-time setup: download and cache all extensions
python monitor.py --chrome-extensions-init

# Monitoring starts automatically (chrome_extensions.yaml must exist)
python monitor.py
```

When a new version is detected on subsequent polls, the monitor diffs the cached version against the new one, analyzes the diff, and alerts if malicious. The cache is stored in `extensions_cache/`.

## Quick Start

```bash
# One-shot: analyze releases from the last ~10 minutes
python monitor.py --once

# Continuous: monitor top 1000 packages (both ecosystems), poll every 5 min
python monitor.py --top 1000 --interval 300

# Production: monitor top 15000, alert to Slack
python monitor.py --top 15000 --interval 300 --slack

# npm only, top 5000
python monitor.py --no-pypi --npm-top 5000

# PyPI only
python monitor.py --no-npm

# Seed the Chrome extension cache (one-time setup)
python monitor.py --chrome-extensions-init

# All ecosystems (Chrome extensions enabled automatically if chrome_extensions.yaml exists)
python monitor.py

# Chrome extensions only
python monitor.py --no-pypi --no-npm

# Disable Chrome extension monitoring
python monitor.py --no-chrome-extensions

# Custom extensions watchlist path
python monitor.py --chrome-extensions-file /path/to/my-watchlist.yaml
```

## File Overview

| File | Purpose |
|------|---------|
| `monitor.py` | **Main orchestrator** — poll PyPI + npm + Chrome extensions, diff, analyze, alert (parallel threads) |
| `chrome_diff.py` | Chrome Web Store interaction — version check, CRX download, header stripping, extraction |
| `pypi_monitor.py` | Standalone PyPI changelog poller (used for exploration) |
| `package_diff.py` | Download and diff two versions of any PyPI or npm package |
| `analyze_diff.py` | Send a diff to Cursor Agent CLI, parse verdict |
| `top_pypi_packages.py` | Fetch and list top N PyPI packages by download count |
| `slack.py` | Slack API client (SendMessage, PostFile) |
| `chrome_extensions.yaml` | Chrome extensions watchlist (extension IDs + last known versions) |
| `extensions_cache/` | Cached extracted extension files for diffing (auto-managed) |
| `etc/slack.json` | Slack bot credentials |
| `last_serial.yaml` | Persisted polling state (PyPI serial + npm sequence/epoch) |
| `logs/` | Daily log files (`monitor_YYYYMMDD.log`) |

## Usage Details

### monitor.py — Main Orchestrator

```
python monitor.py [OPTIONS]

Options:
  --top N               Number of top packages to watch per ecosystem (default: 15000)
  --interval SECS       Poll interval in seconds (default: 300)
  --once                Single pass over recent events, then exit
  --slack               Enable Slack alerts for malicious findings
  --model MODEL         Override LLM model (default: composer-2-fast)
  --debug               Enable DEBUG logging (includes agent raw output)

PyPI options:
  --no-pypi             Disable PyPI monitoring
  --serial N            PyPI changelog serial to start from

npm options:
  --no-npm              Disable npm monitoring
  --npm-top N           Top N npm packages to watch (default: same as --top)
  --npm-seq N           npm replication sequence to start from

Chrome extension options:
  --no-chrome-extensions       Disable Chrome extension monitoring
  --chrome-extensions-init     Download and cache current versions of all watched extensions, then exit
  --chrome-extensions-file P   Path to extensions watchlist YAML (default: chrome_extensions.yaml)
  --chrome-extensions-cache D  Cache directory for extension versions (default: extensions_cache/)
```

Each ecosystem runs in its own polling thread. PyPI and npm polling state (serial, sequence + epoch) is persisted to `last_serial.yaml` so the monitor resumes where it left off after a restart. Chrome extension versions are tracked in the `chrome_extensions.yaml` watchlist file itself.

**PyPI pipeline:**
1. Loads the top N packages from the [hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/) dataset as a watchlist
2. Connects to PyPI's XML-RPC API and gets the current serial number
3. Every `--interval` seconds, calls `changelog_since_serial()` — a single API call that returns all events since the last check
4. Filters for `"new release"` events matching the watchlist
5. For each new release: downloads old + new versions (sdist and wheel when both exist), diffs, analyzes via LLM, and alerts Slack if malicious

**npm pipeline:**
1. Loads the top N packages from the [download-counts](https://www.npmjs.com/package/download-counts) dataset (falls back to npm search API)
2. Reads the current CouchDB replication sequence from `replicate.npmjs.com`
3. Every `--interval` seconds, fetches the `_changes` feed for all registry changes since the last sequence
4. Filters changed packages against the watchlist and checks for versions published after the last poll epoch
5. For each new release: downloads old + new tarballs from the npm registry, diffs, analyzes via LLM, and alerts Slack if malicious

**Chrome extension pipeline:**
1. Loads the watchlist from `chrome_extensions.yaml` (reloaded each cycle, so you can add/remove extensions while running)
2. For each extension, queries the Chrome Web Store update API for the current version
3. Compares against the stored version in the watchlist
4. **First run** (version is `""` or no cache exists): downloads the current CRX, strips the CRX3 header, extracts the ZIP, and caches the files in `extensions_cache/{id}/{version}/` — no diff is performed
5. **Update detected**: diffs the cached old version against the newly downloaded version, analyzes via LLM, and alerts Slack if malicious. Updates the cache and watchlist file with the new version

Unlike PyPI/npm where both old and new versions can be downloaded from the registry at any time, the Chrome Web Store only serves the latest version. This is why extensions must be cached locally.

All output is logged to both the console and `logs/monitor_YYYYMMDD.log`.

### package_diff.py — Package Differ

```bash
# Compare two versions from PyPI
python package_diff.py requests 2.31.0 2.32.0

# Compare two versions from npm
python package_diff.py --npm express 4.18.2 4.19.0

# Save to file
python package_diff.py telnyx 2.0.0 2.1.0 -o telnyx_diff.md

# Compare local archives
python package_diff.py --local old.tar.gz new.tar.gz -n mypackage
```

Downloads are done directly via registry APIs (PyPI JSON API / npm registry), not pip or npm. This means:
- **No pip/npm dependency** for downloads
- **Platform-agnostic** — can download and diff Linux-only packages from Windows
- PyPI: prefers wheel (pure-Python when available), falls back to sdist
- npm: downloads tarballs directly from the registry

### analyze_diff.py — LLM Verdict

```bash
# Analyze a diff file
python analyze_diff.py telnyx_diff.md

# JSON output
python analyze_diff.py telnyx_diff.md --json

# Use a specific model
python analyze_diff.py telnyx_diff.md --model claude-4-opus
```

Runs Cursor Agent CLI in `--mode ask` (read-only) with `--trust`. The agent reads the diff file and returns a structured verdict.

Exit codes: `0` = benign, `1` = malicious, `2` = unknown/error.

### pypi_monitor.py — Standalone Poller

```bash
# See what's being released right now (last ~10 min)
python pypi_monitor.py --once --top 15000

# Continuous monitoring (console output only, no analysis)
python pypi_monitor.py --top 1000 --interval 120
```

Useful for exploring PyPI release velocity or debugging the changelog API without running the full analysis pipeline.

### top_pypi_packages.py — Package Rankings

```bash
# Print top 1000 packages
python top_pypi_packages.py
```

```python
# Use as a library
from top_pypi_packages import fetch_top_packages
packages = fetch_top_packages(top_n=500)
# [{"project": "boto3", "download_count": 1577565199}, ...]
```

## Data Sources

| Source | What | Rate Limits |
|--------|------|-------------|
| [hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/) | Top 15,000 PyPI packages by 30-day downloads (monthly JSON) | None (static file) |
| [PyPI XML-RPC](https://warehouse.pypa.io/api-reference/xml-rpc.html) `changelog_since_serial()` | Real-time PyPI event firehose | Deprecated but functional; 1 call per poll is fine |
| [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html) | Package metadata, version history, download URLs | Generous; used sparingly (1 call per release) |
| [download-counts](https://www.npmjs.com/package/download-counts) (nice-registry) | Monthly download counts for every npm package (`counts.json`) | None (npm tarball) |
| [npm CouchDB replication](https://replicate.npmjs.com) `_changes` feed | Real-time npm registry change stream | Public; paginated reads |
| [npm registry API](https://registry.npmjs.org) | Package packuments, tarball downloads | Generous; used sparingly |
| [Chrome CRX update API](https://developer.chrome.com/docs/extensions/how-to/distribute/host-on-linux#update_url) | Extension version check + CRX download | 1 call per extension per poll cycle; add 0.5s delay between checks |

The monitor makes **1 API call per poll interval per ecosystem** (PyPI changelog / npm `_changes`), plus **2-3 calls per new release** (version history + downloads). Chrome extension monitoring makes **1 call per watched extension per poll cycle** to check for version changes, plus **1 download per update**.

## Example Alerts

When the monitor detects a malicious release, it posts to Slack:

**PyPI:**
```
🚨 Supply Chain Alert: telnyx 4.87.2

Rank: #5,481 of top PyPI packages
Verdict: MALICIOUS
PyPI: https://pypi.org/project/telnyx/4.87.2/

Analysis summary (truncated):
The changes to src/telnyx/_client.py implement obfuscated
download-decrypt-execute behavior and module-import side effects.
A _d() function decodes base64 strings, a massive _p blob contains
an exfiltration script that downloads a .wav file from
http://83.142.209.203:8080/ringtone.wav and extracts a hidden
payload via steganography...
```

**npm:**
```
🚨 Supply Chain Alert: axios 0.30.4

Rank: #42 of top npm packages
Verdict: MALICIOUS
npm: https://www.npmjs.com/package/axios/v/0.30.4

Analysis summary (truncated):
1. **Non-standard dependency** — The `dependencies` block includes `plain-crypto-js`. Published axios only depends on `follow-redirects`, `form-data`, and `proxy-from-env`. A fourth package whose name looks like a **`crypto-js`–style typosquat** is a classic sign of a tampered or fake package, not a normal axios release.
```

**Chrome Extension:**
```
🚨 Supply Chain Alert: uBlock Origin 1.58.0

Rank: #0 of top Chrome Extension packages
Verdict: MALICIOUS
Chrome Extension: https://chromewebstore.google.com/detail/cjpalhdlnbpafiamejdnhcphjbkeiagm

Analysis summary (truncated):
New background script injects obfuscated fetch() calls to an external
endpoint on every page load. The payload collects browsing history
and exfiltrates it via POST to a hardcoded IP address...
```

## Limitations

- Releases are analyzed sequentially within each ecosystem thread. During high release volume, there will be a processing backlog.
- **Cursor Agent CLI required** — analysis depends on an active Cursor subscription and the `agent` CLI being authenticated.
- **Sandbox mode** (filesystem isolation) is only available on macOS/Linux. On Windows, the agent runs in read-only `ask` mode but without OS-level sandboxing.
- **PyPI/npm watchlists are static** — loaded once at startup from the hugovk (PyPI) and download-counts (npm) datasets. Restart to refresh. The Chrome extensions watchlist is reloaded each poll cycle.
- **npm _changes gap protection** — if the saved npm sequence falls more than 10,000 changes behind the registry head, the monitor resets to head to avoid a long catch-up. Releases during the gap are missed.
- **Chrome extension cache** — the Chrome Web Store only serves the latest version of an extension. Old versions are cached locally in `extensions_cache/`. If the cache is deleted, the next poll will re-cache the current version without diffing (treated as a first run).

## Logging

Logs are written to both stdout and `logs/monitor_YYYYMMDD.log`. A new file is created each day. All ecosystems log to the same file, prefixed with `[pypi]`, `[npm]`, or `[chrome]`. Example:

```
2026-03-27 12:01:15 [INFO] Fetching top 15,000 packages from hugovk dataset...
2026-03-27 12:01:16 [INFO] Watchlist loaded: 15,000 packages (dataset updated 2026-03-01 07:34:08)
2026-03-27 12:01:16 [INFO] Fetching top 15,000 npm packages from download-counts dataset...
2026-03-27 12:01:18 [INFO] npm watchlist loaded: 15,000 packages (download-counts 1.0.52)
2026-03-27 12:01:19 [INFO] [pypi] Starting serial: 35,542,068 (from last_serial.yaml) — polling every 300s
2026-03-27 12:01:19 [INFO] [npm] Starting seq: 42,817,503 (from last_serial.yaml) — polling every 300s
2026-03-27 12:06:18 [INFO] [pypi] 2 new watchlist releases detected (serial 35,542,068 -> 35,542,190)
2026-03-27 12:06:18 [INFO] [pypi] Processing fast-array-utils 1.4 (rank #8,231)...
2026-03-27 12:06:18 [INFO] [pypi] Diffing fast-array-utils 1.3 -> 1.4
2026-03-27 12:06:50 [INFO] [pypi] Analyzing diff for fast-array-utils...
2026-03-27 12:07:35 [INFO] [pypi] Verdict for fast-array-utils 1.4: BENIGN
2026-03-27 12:06:20 [INFO] [npm] 1 new watchlist releases detected (seq -> 42,817,612)
2026-03-27 12:06:20 [INFO] [npm] Processing axios 0.30.4 (rank #42)...
2026-03-27 12:06:21 [INFO] [npm] Diffing axios 0.30.3 -> 0.30.4
2026-03-27 12:07:01 [INFO] [npm] Analyzing diff for axios...
2026-03-27 12:07:45 [INFO] [npm] Verdict for axios 0.30.4: MALICIOUS
2026-03-27 12:01:20 [INFO] [chrome] Starting Chrome extension monitor — polling every 300s
2026-03-27 12:01:21 [INFO] [chrome] First run for uBlock Origin — caching version 1.57.2 (no diff)
2026-03-27 12:06:22 [INFO] [chrome] Processing uBlock Origin (cjpalhdlnbpafiamejdnhcphjbkeiagm) 1.57.2 -> 1.58.0...
2026-03-27 12:06:55 [INFO] [chrome] Analyzing diff for uBlock Origin...
2026-03-27 12:07:40 [INFO] [chrome] Verdict for uBlock Origin 1.58.0: BENIGN
```

## Contributing, community, and license

This project is licensed under the [MIT License](LICENSE). Third-party data sources and notices are summarized in [NOTICE.txt](NOTICE.txt).

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). This repository follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Report security issues through [SECURITY.md](SECURITY.md), not public issues.

Questions and discussion: [Elastic community Slack](https://ela.st/slack).
