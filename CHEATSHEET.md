# Supply Chain Monitor — Command Cheatsheet

## package_diff.py — Generate a diff report

Compare two published versions of a package and produce a markdown diff report.

```bash
# PyPI (default)
python package_diff.py requests 2.31.0 2.32.0

# npm
python package_diff.py express 4.18.0 4.18.2 --npm

# Save report to file instead of stdout
python package_diff.py requests 2.31.0 2.32.0 -o diff.md

# Compare local archives (no download)
python package_diff.py --local old.tar.gz new.tar.gz
python package_diff.py --local old.whl new.whl -n mypackage

# Keep downloaded/extracted files for inspection
python package_diff.py requests 2.31.0 2.32.0 --keep
```

---

## analyze_diff.py — Analyze a diff for supply chain compromise

Takes the markdown file produced by `package_diff.py` and returns `malicious` or `benign`.

### Backends

| Flag | Backend | Default model |
|------|---------|---------------|
| *(omit)* | Cursor Agent | `composer-2-fast` |
| `--backend claude` | Claude Code CLI | `claude-sonnet-4-6` |

```bash
# Cursor Agent (default)
python analyze_diff.py diff.md

# Claude Code
python analyze_diff.py diff.md --backend claude

# Override model
python analyze_diff.py diff.md --backend claude --model claude-opus-4-6
python analyze_diff.py diff.md --model composer-2-fast   # cursor with specific model

# Output as JSON (useful for scripting/CI)
python analyze_diff.py diff.md --backend claude --json
python analyze_diff.py diff.md --json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Benign |
| `1` | Malicious |
| `2` | Unknown / backend error |

---

## Full pipeline — diff then analyze in one line

```bash
# PyPI + Claude Code
python package_diff.py requests 2.31.0 2.32.0 -o diff.md && \
  python analyze_diff.py diff.md --backend claude

# PyPI + Claude Opus (more thorough)
python package_diff.py cryptography 41.0.0 41.0.1 -o diff.md && \
  python analyze_diff.py diff.md --backend claude --model claude-opus-4-6

# npm + Claude Code
python package_diff.py express 4.18.0 4.18.2 --npm -o diff.md && \
  python analyze_diff.py diff.md --backend claude

# PyPI + Cursor Agent
python package_diff.py requests 2.31.0 2.32.0 -o diff.md && \
  python analyze_diff.py diff.md

# JSON verdict for CI/scripting
python package_diff.py requests 2.31.0 2.32.0 -o diff.md && \
  python analyze_diff.py diff.md --backend claude --json
```

---

## monitor.py — Continuous supply chain monitor

Polls PyPI and npm for new releases of the top N packages, diffs each new release,
analyzes it with Cursor Agent or Claude Code, and alerts Slack on malicious findings.

### Backends

| Flag | Backend | Default model |
|------|---------|---------------|
| *(omit)* | Cursor Agent | `composer-2-fast` |
| `--backend claude` | Claude Code CLI | `claude-sonnet-4-6` |

```bash
# Monitor both PyPI and npm (default: top 15000, poll every 300s, Cursor backend)
python monitor.py

# Use Claude Code as the analysis backend
python monitor.py --backend claude

# Override model
python monitor.py --backend claude --model claude-opus-4-6
python monitor.py --model composer-2-fast   # cursor with specific model

# Monitor top N packages per ecosystem
python monitor.py --top 5000

# Change poll interval (seconds)
python monitor.py --interval 120

# One-shot scan — check recent events once, then exit
python monitor.py --once
python monitor.py --once --backend claude

# Enable Slack alerts for malicious findings
python monitor.py --slack
python monitor.py --slack --backend claude

# PyPI only
python monitor.py --no-npm

# npm only
python monitor.py --no-pypi

# npm only, custom top count
python monitor.py --no-pypi --npm-top 5000

# Start PyPI polling from a specific serial
python monitor.py --serial 12345678

# Start npm polling from a specific sequence number
python monitor.py --npm-seq 987654

# Debug logging (shows raw AI output)
python monitor.py --debug --backend claude
```

---

## pypi_monitor.py — Lightweight PyPI-only watcher

Polls PyPI changelog directly — prints new releases only, no diff or AI analysis.

```bash
# Monitor top 1000 packages, poll every 120s (default)
python pypi_monitor.py

# Monitor top 5000
python pypi_monitor.py --top 5000

# Custom poll interval
python pypi_monitor.py --interval 60

# Single check (last ~10 min of activity), then exit
python pypi_monitor.py --once
```

---

## Slack setup

Create `etc/slack.json`:

```json
{
  "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
  "bot_token": "xoxb-your-bot-token",
  "channel": "C0123456789"
}
```
