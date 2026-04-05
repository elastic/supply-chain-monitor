# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Analyze a package diff report for supply chain compromise using Cursor Agent CLI or Claude Code CLI.

Takes a diff markdown file (output of package_diff.py) and returns a verdict
of "malicious" or "benign" with supporting analysis.

Usage:
    python analyze_diff.py <diff_file>
    python analyze_diff.py telnyx_diff.md
    python analyze_diff.py telnyx_diff.md --model claude-sonnet-4-6
    python analyze_diff.py telnyx_diff.md --backend claude
    python analyze_diff.py telnyx_diff.md --json

Can also be chained with package_diff.py:
    python package_diff.py requests 2.31.0 2.32.0 -o diff.md && python analyze_diff.py diff.md
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("monitor.analyze")

INSTRUCTIONS_TEMPLATE = """\
# Supply Chain Diff Review

Review the diff in `{diff_file}` and determine if the changes are highly likely
to show evidence of a supply chain compromise.

## Response format

Start your response with exactly one of these lines:

    Verdict: malicious
    Verdict: benign

Then explain your reasoning briefly.

## What to look for

- Obfuscated code (base64, exec, eval, XOR, encoded strings)
- Network calls to unexpected hosts (non-package-related URLs)
- File system writes to startup/persistence locations
- Process spawning, shell commands
- Steganography or data hiding in media files
- Credential/token exfiltration
- Typosquatting indicators
- Suspicious npm lifecycle scripts (preinstall, install, postinstall) in package.json
- Dynamic require() or import() of obfuscated or encoded URLs
- Minified or bundled payloads added outside normal build artifacts

Only report "malicious" if you are highly confident malicious code has been added.
"""

CLAUDE_INSTRUCTIONS_TEMPLATE = """\
# Supply Chain Diff Review

Review the diff below and determine if the changes are highly likely
to show evidence of a supply chain compromise.

## Response format

Start your response with exactly one of these lines:

    Verdict: malicious
    Verdict: benign

Then explain your reasoning briefly.

## What to look for

- Obfuscated code (base64, exec, eval, XOR, encoded strings)
- Network calls to unexpected hosts (non-package-related URLs)
- File system writes to startup/persistence locations
- Process spawning, shell commands
- Steganography or data hiding in media files
- Credential/token exfiltration
- Typosquatting indicators
- Suspicious npm lifecycle scripts (preinstall, install, postinstall) in package.json
- Dynamic require() or import() of obfuscated or encoded URLs
- Minified or bundled payloads added outside normal build artifacts

Only report "malicious" if you are highly confident malicious code has been added.

## Diff to review

{diff_content}
"""


def _find_agent() -> str:
    agent = shutil.which("agent")
    if agent:
        return agent
    if platform.system() == "Windows":
        candidate = Path.home() / "AppData/Local/cursor-agent/agent.cmd"
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError(
        "Cursor Agent CLI not found. Install with: "
        "irm 'https://cursor.com/install?win32=true' | iex"
    )


def run_cursor_agent(diff_file: Path, model: str = "composer-2-fast") -> str:
    agent_bin = _find_agent()
    workspace = diff_file.parent.resolve()

    instructions = workspace / "instructions.md"
    instructions.write_text(
        INSTRUCTIONS_TEMPLATE.format(diff_file=diff_file.name),
        encoding="utf-8",
    )

    cmd_parts = [
        agent_bin,
        "Follow instructions.md",
        "-p",
        "--mode", "ask",
        "--trust",
        "--workspace", str(workspace),
    ]
    if model:
        cmd_parts.extend(["--model", model])

    result = subprocess.run(
        cmd_parts,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )

    log.debug("Agent stdout:\n%s", result.stdout or "(empty)")
    log.debug("Agent stderr:\n%s", result.stderr or "(empty)")

    if result.returncode != 0:
        log.error("Cursor agent exited %d: %s", result.returncode, result.stderr)
        return ""

    return result.stdout or ""


def _find_claude() -> str:
    claude = shutil.which("claude")
    if claude:
        return claude
    raise FileNotFoundError(
        "Claude Code CLI not found. Install with: "
        "npm install -g @anthropic-ai/claude-code"
    )


def run_claude_code(diff_file: Path, model: str = "claude-sonnet-4-6") -> str:
    claude_bin = _find_claude()
    diff_content = diff_file.read_text(encoding="utf-8", errors="replace")
    prompt = CLAUDE_INSTRUCTIONS_TEMPLATE.format(diff_content=diff_content)

    cmd_parts = [claude_bin, "--print"]
    if model:
        cmd_parts.extend(["--model", model])

    # Pass prompt via stdin to avoid OS "argument list too long" on large diffs
    result = subprocess.run(
        cmd_parts,
        input=prompt,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )

    log.debug("Claude stdout:\n%s", result.stdout or "(empty)")
    log.debug("Claude stderr:\n%s", result.stderr or "(empty)")

    if result.returncode != 0:
        log.error("Claude Code exited %d: %s", result.returncode, result.stderr)
        return ""

    return result.stdout or ""


def parse_verdict(output: str) -> tuple[str, str]:
    """Extract verdict and reasoning from agent output."""
    matches = re.findall(r"[Vv]erdict:\s*(malicious|benign)", output, re.IGNORECASE)
    verdict = matches[-1].lower() if matches else "unknown"
    return verdict, output.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a package diff for supply chain compromise via Cursor Agent or Claude Code",
    )
    parser.add_argument("diff_file", type=Path, help="Path to diff markdown file (from package_diff.py)")
    parser.add_argument("--model", help="Model to use (default: composer-2-fast for cursor, claude-sonnet-4-6 for claude)")
    parser.add_argument("--backend", choices=["cursor", "claude"], default="cursor", help="AI backend to use (default: cursor)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    args = parser.parse_args()

    if not args.diff_file.exists():
        parser.error(f"File not found: {args.diff_file}")

    if args.backend == "claude":
        print(f"[*] Analyzing {args.diff_file.name} with Claude Code...", file=sys.stderr)
        raw_output = run_claude_code(args.diff_file, model=args.model or "claude-sonnet-4-6")
    else:
        print(f"[*] Analyzing {args.diff_file.name} with Cursor Agent...", file=sys.stderr)
        raw_output = run_cursor_agent(args.diff_file, model=args.model or "composer-2-fast")

    if not raw_output:
        print("[!] Backend returned no output — check logs for errors.", file=sys.stderr)
        sys.exit(2)

    verdict, analysis = parse_verdict(raw_output)

    if args.json_output:
        print(json.dumps({
            "file": str(args.diff_file),
            "verdict": verdict,
            "analysis": analysis,
        }, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  FILE:    {args.diff_file.name}")
        print(f"  VERDICT: {verdict.upper()}")
        print(f"{'='*60}")
        print(f"\n{analysis}")

    sys.exit(0 if verdict == "benign" else 1 if verdict == "malicious" else 2)


if __name__ == "__main__":
    main()
