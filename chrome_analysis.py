# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Chrome extension pre-analysis: permission diffing, rename detection, and
suspicious-pattern scanning.  All logic is pure Python (no LLM calls) so that
the markdown report sent to the model already contains a pre-digested summary,
keeping token usage low.

Public entry point:
    generate_chrome_report(name, v1, v2, files_v1, files_v2) -> str
"""

from __future__ import annotations

import difflib
import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from package_diff import file_hash, unified_diff

log = logging.getLogger("monitor.chrome_analysis")

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PermissionAnalysis:
    added_permissions: list[str] = field(default_factory=list)
    removed_permissions: list[str] = field(default_factory=list)
    added_host_permissions: list[str] = field(default_factory=list)
    removed_host_permissions: list[str] = field(default_factory=list)
    added_optional_permissions: list[str] = field(default_factory=list)
    removed_optional_permissions: list[str] = field(default_factory=list)
    content_script_changes: list[dict] = field(default_factory=list)
    csp_changes: dict | None = None
    externally_connectable_changes: dict | None = None
    dangerous_combinations: list[str] = field(default_factory=list)
    risk_score: int = 0


@dataclass
class RenameDetection:
    old_path: str
    new_path: str
    similarity: float


@dataclass
class ScriptFinding:
    pattern_name: str
    severity: str  # "high", "medium", "low"
    description: str
    evidence: str
    line_number: int | None = None


# ---------------------------------------------------------------------------
# Constants — dangerous permission combos (from real attacks)
# ---------------------------------------------------------------------------

# Each entry: (required_permissions, required_host_pattern, description)
# A host pattern of None means no host_permissions check is needed.
DANGEROUS_PERMISSION_COMBOS: list[tuple[set[str], str | None, str]] = [
    (
        {"declarativeNetRequest", "scripting"},
        "<all_urls>",
        "CSP stripping + arbitrary code injection into any page",
    ),
    (
        {"declarativeNetRequest", "webRequest"},
        "<all_urls>",
        "CSP stripping + full traffic interception on all sites",
    ),
    (
        {"scripting", "storage"},
        "<all_urls>",
        "Code injection on any page with persistent storage (Cyberhaven pattern)",
    ),
    (
        {"cookies"},
        "<all_urls>",
        "Cookie access on all sites — credential theft risk",
    ),
    (
        {"webRequest", "webRequestBlocking"},
        None,
        "Synchronous traffic interception — can modify/block requests",
    ),
    (
        {"debugger"},
        None,
        "Full Chrome DevTools protocol access — can read/modify any page",
    ),
]

# ---------------------------------------------------------------------------
# Constants — suspicious code patterns
# ---------------------------------------------------------------------------

# (pattern_name, compiled_regex, severity, description)
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "eval",
        re.compile(r"\beval\s*\("),
        "high",
        "Dynamic code execution via eval()",
    ),
    (
        "Function_constructor",
        re.compile(r"\bFunction\s*\("),
        "high",
        "Dynamic code execution via Function() constructor",
    ),
    (
        "atob_decode",
        re.compile(r"\batob\s*\("),
        "high",
        "Base64 decoding — often used to hide payloads",
    ),
    (
        "csp_stripping",
        re.compile(
            r"updateSessionRules|updateDynamicRules",
            re.IGNORECASE,
        ),
        "high",
        "declarativeNetRequest rule update — may strip CSP headers",
    ),
    (
        "document_cookie",
        re.compile(r"\bdocument\.cookie\b"),
        "high",
        "Direct cookie access — credential theft indicator",
    ),
    (
        "targeted_domain",
        re.compile(
            r"facebook\.com|chatgpt\.com|chat\.openai\.com|coinbase\.com"
            r"|binance\.com|metamask\.io|paypal\.com|blockchain\.com"
            r"|kraken\.com|crypto\.com",
            re.IGNORECASE,
        ),
        "high",
        "Reference to high-value credential-harvesting target domain",
    ),
    (
        "fetch_call",
        re.compile(r"\bfetch\s*\("),
        "medium",
        "Network request via fetch()",
    ),
    (
        "xhr",
        re.compile(r"\bXMLHttpRequest\b"),
        "medium",
        "Network request via XMLHttpRequest",
    ),
    (
        "websocket",
        re.compile(r"\bnew\s+WebSocket\s*\("),
        "medium",
        "WebSocket connection — potential C2 channel",
    ),
    (
        "chrome_cookies",
        re.compile(r"\bchrome\.cookies\b"),
        "medium",
        "Chrome cookies API access",
    ),
    (
        "chrome_storage",
        re.compile(r"\bchrome\.storage\b"),
        "medium",
        "Chrome storage API access",
    ),
    (
        "chrome_webrequest",
        re.compile(r"\bchrome\.webRequest\b"),
        "medium",
        "Chrome webRequest API — traffic interception",
    ),
    (
        "chrome_declarativeNetRequest",
        re.compile(r"\bchrome\.declarativeNetRequest\b"),
        "medium",
        "Chrome declarativeNetRequest API — header/CSP manipulation",
    ),
    (
        "chrome_debugger",
        re.compile(r"\bchrome\.debugger\b"),
        "high",
        "Chrome debugger API — full DevTools protocol access",
    ),
    (
        "string_setTimeout",
        re.compile(r"\bsetTimeout\s*\(\s*[\"']"),
        "low",
        "setTimeout with string argument — implicit eval",
    ),
    (
        "string_setInterval",
        re.compile(r"\bsetInterval\s*\(\s*[\"']"),
        "low",
        "setInterval with string argument — implicit eval",
    ),
    (
        "runtime_sendMessage",
        re.compile(r"\bchrome\.runtime\.sendMessage\b"),
        "low",
        "Inter-component messaging (used in two-file exfiltration architecture)",
    ),
]

# Composite patterns: if BOTH keys are found in the same file, elevate severity.
COMPOSITE_ESCALATIONS: list[tuple[set[str], str, str]] = [
    (
        {"atob_decode", "eval"},
        "high",
        "Base64-decode + eval: hidden payload execution",
    ),
    (
        {"atob_decode", "Function_constructor"},
        "high",
        "Base64-decode + Function(): hidden payload execution",
    ),
    (
        {"document_cookie", "fetch_call"},
        "high",
        "Cookie access + fetch: likely credential exfiltration",
    ),
    (
        {"document_cookie", "xhr"},
        "high",
        "Cookie access + XHR: likely credential exfiltration",
    ),
    (
        {"chrome_cookies", "fetch_call"},
        "high",
        "Chrome cookies API + fetch: likely credential exfiltration",
    ),
    (
        {"csp_stripping", "chrome_declarativeNetRequest"},
        "high",
        "CSP stripping via declarativeNetRequest — TamperedChef pattern",
    ),
]

TARGETED_DOMAINS = {
    "facebook.com", "chatgpt.com", "chat.openai.com", "coinbase.com",
    "binance.com", "metamask.io", "paypal.com", "blockchain.com",
    "kraken.com", "crypto.com",
}

# Host permission patterns considered "broad".
_BROAD_HOST_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}

_TEXT_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".json", ".html", ".css", ".mjs", ".cjs"}

_SCRIPT_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

MAX_DIFF_LINES_PER_FILE = 200

# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

_HOST_PATTERN_RE = re.compile(
    r"^(<all_urls>|(\*|https?|ftp)://.*)"
)


def parse_manifest(files: dict[str, Path]) -> dict | None:
    """Find and parse manifest.json, returning the parsed dict or None."""
    for key in ("manifest.json", "Manifest.json"):
        if key in files:
            try:
                return json.loads(files[key].read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                return None
    return None


def _normalize_permissions(manifest: dict) -> tuple[set[str], set[str]]:
    """Return (api_permissions, host_permissions) normalised for MV2/MV3.

    MV2 mixes host patterns into 'permissions'; MV3 uses separate
    'host_permissions'.  We split them apart so comparison is uniform.
    """
    raw_perms = set(manifest.get("permissions", []))
    raw_hosts = set(manifest.get("host_permissions", []))

    # Move host-like entries out of permissions (MV2 compat).
    api_perms: set[str] = set()
    for p in raw_perms:
        if isinstance(p, str) and _HOST_PATTERN_RE.match(p):
            raw_hosts.add(p)
        else:
            api_perms.add(p if isinstance(p, str) else str(p))

    return api_perms, raw_hosts


def analyze_permissions(
    old_manifest: dict | None,
    new_manifest: dict | None,
) -> PermissionAnalysis:
    """Compare permissions between two manifest versions."""
    result = PermissionAnalysis()

    if new_manifest is None:
        return result

    old_api, old_hosts = _normalize_permissions(old_manifest or {})
    new_api, new_hosts = _normalize_permissions(new_manifest)

    old_optional = set((old_manifest or {}).get("optional_permissions", []))
    new_optional = set(new_manifest.get("optional_permissions", []))

    result.added_permissions = sorted(new_api - old_api)
    result.removed_permissions = sorted(old_api - new_api)
    result.added_host_permissions = sorted(new_hosts - old_hosts)
    result.removed_host_permissions = sorted(old_hosts - new_hosts)
    result.added_optional_permissions = sorted(new_optional - old_optional)
    result.removed_optional_permissions = sorted(old_optional - new_optional)

    # Content script changes
    old_cs = (old_manifest or {}).get("content_scripts", [])
    new_cs = new_manifest.get("content_scripts", [])
    if json.dumps(old_cs, sort_keys=True) != json.dumps(new_cs, sort_keys=True):
        old_matches = {m for cs in old_cs for m in cs.get("matches", [])}
        new_matches = {m for cs in new_cs for m in cs.get("matches", [])}
        old_js = {f for cs in old_cs for f in cs.get("js", [])}
        new_js = {f for cs in new_cs for f in cs.get("js", [])}
        result.content_script_changes.append({
            "added_matches": sorted(new_matches - old_matches),
            "removed_matches": sorted(old_matches - new_matches),
            "added_js": sorted(new_js - old_js),
            "removed_js": sorted(old_js - new_js),
        })

    # CSP changes
    old_csp = (old_manifest or {}).get("content_security_policy", "")
    new_csp = new_manifest.get("content_security_policy", "")
    if old_csp != new_csp:
        result.csp_changes = {"old": old_csp, "new": new_csp}

    # Externally connectable changes
    old_ec = (old_manifest or {}).get("externally_connectable")
    new_ec = new_manifest.get("externally_connectable")
    if old_ec != new_ec:
        result.externally_connectable_changes = {"old": old_ec, "new": new_ec}

    # Check dangerous combos in the NEW manifest
    for required, host_pat, desc in DANGEROUS_PERMISSION_COMBOS:
        if not required.issubset(new_api | new_hosts):
            continue
        if host_pat is not None and host_pat not in new_hosts:
            # Also check broad patterns
            if not (new_hosts & _BROAD_HOST_PATTERNS):
                continue
        result.dangerous_combinations.append(desc)

    # Risk score (0-10)
    score = 0
    score += min(len(result.added_permissions) * 1, 3)
    if result.added_host_permissions:
        if new_hosts & _BROAD_HOST_PATTERNS:
            score += 3
        else:
            score += 1
    score += min(len(result.dangerous_combinations) * 2, 4)
    if result.content_script_changes:
        score += 1
    if result.csp_changes:
        score += 1
    result.risk_score = min(score, 10)

    return result


# ---------------------------------------------------------------------------
# Rename / move detection
# ---------------------------------------------------------------------------


def detect_renames(
    added: list[str],
    deleted: list[str],
    files_v1: dict[str, Path],
    files_v2: dict[str, Path],
    threshold: float = 0.6,
) -> list[RenameDetection]:
    """Detect likely renames among added/deleted files using content similarity."""
    # Filter to text files where rename detection is meaningful.
    added_txt = [f for f in added if Path(f).suffix.lower() in _TEXT_EXTENSIONS]
    deleted_txt = [f for f in deleted if Path(f).suffix.lower() in _TEXT_EXTENSIONS]

    if not added_txt or not deleted_txt:
        return []

    # Read contents (skip files that can't be read as text).
    def _read_safe(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    added_content: dict[str, str] = {}
    for f in added_txt:
        c = _read_safe(files_v2[f])
        if c is not None:
            added_content[f] = c

    deleted_content: dict[str, str] = {}
    for f in deleted_txt:
        c = _read_safe(files_v1[f])
        if c is not None:
            deleted_content[f] = c

    if not added_content or not deleted_content:
        return []

    # Build candidate pairs with pre-filtering for performance.
    candidates: list[tuple[str, str, float]] = []

    # Phase 1: same basename
    added_by_basename: dict[str, list[str]] = {}
    for f in added_content:
        added_by_basename.setdefault(Path(f).name, []).append(f)

    matched_added: set[str] = set()
    matched_deleted: set[str] = set()

    for d in deleted_content:
        basename = Path(d).name
        for a in added_by_basename.get(basename, []):
            ratio = _similarity(deleted_content[d], added_content[a])
            if ratio >= threshold:
                candidates.append((d, a, ratio))

    # Phase 2: same extension + similar size (skip already-good matches)
    if len(added_content) * len(deleted_content) <= 500:
        for d, d_content in deleted_content.items():
            for a, a_content in added_content.items():
                if Path(d).suffix != Path(a).suffix:
                    continue
                # Skip if already a candidate from phase 1
                if any(c[0] == d and c[1] == a for c in candidates):
                    continue
                # Size filter: within 3x
                if not _size_compatible(d_content, a_content):
                    continue
                ratio = _similarity(d_content, a_content)
                if ratio >= threshold:
                    candidates.append((d, a, ratio))

    # Greedy best-match assignment
    candidates.sort(key=lambda x: x[2], reverse=True)
    renames: list[RenameDetection] = []
    for d, a, ratio in candidates:
        if d in matched_deleted or a in matched_added:
            continue
        matched_deleted.add(d)
        matched_added.add(a)
        renames.append(RenameDetection(old_path=d, new_path=a, similarity=ratio))

    return renames


def _similarity(a: str, b: str) -> float:
    """Content similarity ratio using SequenceMatcher with performance guards."""
    if len(a) > 50_000 or len(b) > 50_000:
        ratio = difflib.SequenceMatcher(None, a, b).quick_ratio()
        if ratio < 0.5:
            return ratio
    return difflib.SequenceMatcher(None, a, b).ratio()


def _size_compatible(a: str, b: str) -> bool:
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return False
    return max(la, lb) / max(min(la, lb), 1) <= 3.0


# ---------------------------------------------------------------------------
# Script analysis — suspicious pattern scanning
# ---------------------------------------------------------------------------


def compute_entropy(s: str) -> float:
    """Shannon entropy (bits) over the character distribution of *s*."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


_IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]{7,}\b")


def _check_obfuscation(content: str) -> ScriptFinding | None:
    """Flag files with high-entropy identifiers (obfuscated variable names)."""
    identifiers = _IDENT_RE.findall(content)
    if len(identifiers) < 10:
        return None
    high_entropy = [ident for ident in identifiers if compute_entropy(ident) > 4.0]
    ratio = len(high_entropy) / len(identifiers)
    if ratio > 0.3:
        sample = ", ".join(high_entropy[:5])
        return ScriptFinding(
            pattern_name="obfuscated_identifiers",
            severity="medium",
            description=f"High-entropy identifiers ({ratio:.0%} of identifiers) — possible obfuscation",
            evidence=f"Examples: {sample}",
        )
    return None


def analyze_script(path: str, content: str) -> list[ScriptFinding]:
    """Scan a script's content for suspicious patterns. Returns findings."""
    findings: list[ScriptFinding] = []
    found_patterns: set[str] = set()
    lines = content.splitlines()

    for pat_name, regex, severity, description in SUSPICIOUS_PATTERNS:
        for i, line in enumerate(lines, 1):
            m = regex.search(line)
            if m:
                findings.append(ScriptFinding(
                    pattern_name=pat_name,
                    severity=severity,
                    description=description,
                    evidence=line.strip()[:120],
                    line_number=i,
                ))
                found_patterns.add(pat_name)
                break  # one match per pattern per file is enough

    # Composite escalations
    for required_pats, severity, description in COMPOSITE_ESCALATIONS:
        if required_pats.issubset(found_patterns):
            findings.append(ScriptFinding(
                pattern_name="composite",
                severity=severity,
                description=description,
                evidence="(combination of individual findings above)",
            ))

    # Obfuscation check
    obf = _check_obfuscation(content)
    if obf:
        findings.append(obf)

    return findings


def analyze_new_and_changed_scripts(
    added: list[str],
    changed: list[str],
    files_v1: dict[str, Path],
    files_v2: dict[str, Path],
    renames: list[RenameDetection],
) -> dict[str, list[ScriptFinding]]:
    """Scan new and changed script files for suspicious patterns.

    For truly-new files: scans the full content.
    For changed files: scans only the added lines from the diff.
    """
    rename_new_paths = {r.new_path for r in renames}
    truly_new = [f for f in added if f not in rename_new_paths]

    results: dict[str, list[ScriptFinding]] = {}

    # New files — full scan
    for f in truly_new:
        if Path(f).suffix.lower() not in _SCRIPT_EXTENSIONS:
            continue
        try:
            content = files_v2[f].read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings = analyze_script(f, content)
        if findings:
            results[f"{f} (NEW)"] = findings

    # Changed files — scan only added lines
    for f in changed:
        if Path(f).suffix.lower() not in _SCRIPT_EXTENSIONS:
            continue
        if f not in files_v1 or f not in files_v2:
            continue
        diff_text = unified_diff(
            files_v1[f], files_v2[f],
            label_a=f"old/{f}", label_b=f"new/{f}",
        )
        if not diff_text:
            continue
        # Extract only added lines (lines starting with '+' but not '+++')
        added_lines = [
            line[1:]  # strip the leading '+'
            for line in diff_text.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        if not added_lines:
            continue
        added_content = "\n".join(added_lines)
        findings = analyze_script(f, added_content)
        if findings:
            results[f"{f} (CHANGED)"] = findings

    # Renamed files — scan the diff of old→new
    for r in renames:
        if Path(r.new_path).suffix.lower() not in _SCRIPT_EXTENSIONS:
            continue
        if r.old_path not in files_v1 or r.new_path not in files_v2:
            continue
        diff_text = unified_diff(
            files_v1[r.old_path], files_v2[r.new_path],
            label_a=f"old/{r.old_path}", label_b=f"new/{r.new_path}",
        )
        if not diff_text:
            continue
        added_lines = [
            line[1:]
            for line in diff_text.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        if not added_lines:
            continue
        added_content = "\n".join(added_lines)
        findings = analyze_script(r.new_path, added_content)
        if findings:
            results[f"{r.old_path} -> {r.new_path} (RENAMED)"] = findings

    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _format_permission_section(perm: PermissionAnalysis) -> list[str]:
    """Format the permission analysis as markdown lines."""
    lines: list[str] = []
    if not any([
        perm.added_permissions, perm.removed_permissions,
        perm.added_host_permissions, perm.removed_host_permissions,
        perm.added_optional_permissions, perm.removed_optional_permissions,
        perm.content_script_changes, perm.csp_changes,
        perm.externally_connectable_changes, perm.dangerous_combinations,
    ]):
        lines.append("No permission changes detected.")
        return lines

    if perm.added_permissions:
        lines.append(f"- **ADDED permissions**: `{'`, `'.join(perm.added_permissions)}`")
    if perm.removed_permissions:
        lines.append(f"- Removed permissions: `{'`, `'.join(perm.removed_permissions)}`")
    if perm.added_host_permissions:
        lines.append(f"- **ADDED host_permissions**: `{'`, `'.join(perm.added_host_permissions)}`")
    if perm.removed_host_permissions:
        lines.append(f"- Removed host_permissions: `{'`, `'.join(perm.removed_host_permissions)}`")
    if perm.added_optional_permissions:
        lines.append(f"- ADDED optional_permissions: `{'`, `'.join(perm.added_optional_permissions)}`")
    if perm.removed_optional_permissions:
        lines.append(f"- Removed optional_permissions: `{'`, `'.join(perm.removed_optional_permissions)}`")

    for cs_change in perm.content_script_changes:
        if cs_change.get("added_matches"):
            lines.append(f"- Content scripts — added match patterns: `{'`, `'.join(cs_change['added_matches'])}`")
        if cs_change.get("removed_matches"):
            lines.append(f"- Content scripts — removed match patterns: `{'`, `'.join(cs_change['removed_matches'])}`")
        if cs_change.get("added_js"):
            lines.append(f"- Content scripts — **new JS files injected**: `{'`, `'.join(cs_change['added_js'])}`")
        if cs_change.get("removed_js"):
            lines.append(f"- Content scripts — JS files removed: `{'`, `'.join(cs_change['removed_js'])}`")

    if perm.csp_changes:
        lines.append(f"- **CSP changed**: `{perm.csp_changes.get('old', '(none)')}` → `{perm.csp_changes.get('new', '(none)')}`")

    if perm.externally_connectable_changes:
        lines.append(f"- Externally connectable changed: `{perm.externally_connectable_changes.get('old')}` → `{perm.externally_connectable_changes.get('new')}`")

    if perm.dangerous_combinations:
        lines.append("")
        lines.append("**Dangerous permission combinations detected:**")
        for combo in perm.dangerous_combinations:
            lines.append(f"- ⚠ {combo}")

    return lines


def _format_findings_section(
    script_findings: dict[str, list[ScriptFinding]],
) -> list[str]:
    """Format script findings as markdown lines."""
    if not script_findings:
        return ["No suspicious patterns detected in new or changed scripts."]

    lines: list[str] = []
    severity_order = {"high": 0, "medium": 1, "low": 2}

    for file_label, findings in sorted(script_findings.items()):
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 9))
        lines.append(f"**{file_label}**:")
        for f in sorted_findings:
            loc = f"line {f.line_number}" if f.line_number else ""
            lines.append(
                f"- [{f.severity.upper()}] {f.description}"
                + (f" ({loc})" if loc else "")
            )
            if f.evidence and f.evidence != "(combination of individual findings above)":
                lines.append(f"  `{f.evidence}`")
        lines.append("")

    return lines


def generate_chrome_report(
    name: str,
    v1: str,
    v2: str,
    files_v1: dict[str, Path],
    files_v2: dict[str, Path],
) -> str:
    """Build an enhanced diff report for a Chrome extension update.

    Includes a pre-analysis summary (permissions, renames, suspicious patterns)
    followed by the file-level diffs.
    """
    keys_v1 = set(files_v1)
    keys_v2 = set(files_v2)

    added = sorted(keys_v2 - keys_v1)
    deleted = sorted(keys_v1 - keys_v2)
    common = sorted(keys_v1 & keys_v2)

    changed: list[str] = []
    unchanged: list[str] = []
    for key in common:
        if file_hash(files_v1[key]) != file_hash(files_v2[key]):
            changed.append(key)
        else:
            unchanged.append(key)

    # --- Pre-analysis ---
    old_manifest = parse_manifest(files_v1)
    new_manifest = parse_manifest(files_v2)
    perm_analysis = analyze_permissions(old_manifest, new_manifest)

    renames = detect_renames(added, deleted, files_v1, files_v2)
    rename_old = {r.old_path for r in renames}
    rename_new = {r.new_path for r in renames}

    truly_added = [f for f in added if f not in rename_new]
    truly_deleted = [f for f in deleted if f not in rename_old]

    script_findings = analyze_new_and_changed_scripts(
        added, changed, files_v1, files_v2, renames,
    )

    # Overall risk score: combine permission risk + findings severity
    finding_risk = 0
    for findings in script_findings.values():
        for f in findings:
            if f.severity == "high":
                finding_risk += 2
            elif f.severity == "medium":
                finding_risk += 1
    overall_risk = min(perm_analysis.risk_score + min(finding_risk, 6), 10)

    # --- Build report ---
    lines: list[str] = []
    lines.append(f"# Diff Report: {name} {v1} → {v2}")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Files in {v1} | {len(files_v1)} |")
    lines.append(f"| Files in {v2} | {len(files_v2)} |")
    lines.append(f"| Added | {len(truly_added)} |")
    lines.append(f"| Deleted | {len(truly_deleted)} |")
    lines.append(f"| Renamed/Moved | {len(renames)} |")
    lines.append(f"| Changed | {len(changed)} |")
    lines.append(f"| Unchanged | {len(unchanged)} |")
    lines.append("")

    # --- Pre-Analysis Summary ---
    lines.append("## Pre-Analysis Summary")
    lines.append("")

    lines.append("### Permission Changes")
    lines.append("")
    lines.extend(_format_permission_section(perm_analysis))
    lines.append("")

    if renames:
        lines.append("### Renamed/Moved Files")
        lines.append("")
        for r in renames:
            lines.append(f"- `{r.old_path}` → `{r.new_path}` ({r.similarity:.0%} similar)")
        lines.append("")

    lines.append("### Suspicious Patterns in New/Changed Scripts")
    lines.append("")
    lines.extend(_format_findings_section(script_findings))
    lines.append("")

    lines.append(f"### Overall Risk Assessment: {overall_risk}/10")
    lines.append("")
    risk_parts: list[str] = []
    if perm_analysis.dangerous_combinations:
        risk_parts.append("dangerous permission combinations")
    if perm_analysis.added_host_permissions:
        risk_parts.append("new host permissions")
    if any(f.severity == "high" for fl in script_findings.values() for f in fl):
        risk_parts.append("high-severity code patterns")
    if renames:
        risk_parts.append(f"{len(renames)} renamed file(s)")
    if risk_parts:
        lines.append(f"Key factors: {', '.join(risk_parts)}.")
    else:
        lines.append("No significant risk factors detected.")
    lines.append("")

    lines.append("---")
    lines.append("")

    # --- File sections ---
    if truly_added:
        lines.append("## Added Files")
        lines.append("")
        for f in truly_added:
            lines.append(f"- `{f}`")
        lines.append("")

    if truly_deleted:
        lines.append("## Deleted Files")
        lines.append("")
        for f in truly_deleted:
            lines.append(f"- `{f}`")
        lines.append("")

    if renames:
        lines.append("## Renamed/Moved Files")
        lines.append("")
        for r in renames:
            lines.append(f"### `{r.old_path}` → `{r.new_path}` ({r.similarity:.0%} similar)")
            lines.append("")
            diff = unified_diff(
                files_v1[r.old_path], files_v2[r.new_path],
                label_a=f"{v1}/{r.old_path}",
                label_b=f"{v2}/{r.new_path}",
            )
            if diff is None:
                lines.append("*Binary file.*")
            elif diff == "":
                lines.append("*No content difference (identical after move).*")
            else:
                diff_lines = diff.rstrip().splitlines()
                if len(diff_lines) > MAX_DIFF_LINES_PER_FILE:
                    lines.append("```diff")
                    lines.append("\n".join(diff_lines[:MAX_DIFF_LINES_PER_FILE]))
                    lines.append("```")
                    lines.append(f"*(diff truncated — {len(diff_lines)} lines total, showing first {MAX_DIFF_LINES_PER_FILE})*")
                else:
                    lines.append("```diff")
                    lines.append("\n".join(diff_lines))
                    lines.append("```")
            lines.append("")

    if changed:
        lines.append("## Changed Files")
        lines.append("")
        for f in changed:
            lines.append(f"### `{f}`")
            lines.append("")
            diff = unified_diff(
                files_v1[f], files_v2[f],
                label_a=f"{v1}/{f}",
                label_b=f"{v2}/{f}",
            )
            if diff is None:
                lines.append("*Binary file changed.*")
            elif diff == "":
                lines.append("*Whitespace-only or encoding difference.*")
            else:
                diff_lines = diff.rstrip().splitlines()
                if len(diff_lines) > MAX_DIFF_LINES_PER_FILE:
                    lines.append("```diff")
                    lines.append("\n".join(diff_lines[:MAX_DIFF_LINES_PER_FILE]))
                    lines.append("```")
                    lines.append(f"*(diff truncated — {len(diff_lines)} lines total, showing first {MAX_DIFF_LINES_PER_FILE})*")
                else:
                    lines.append("```diff")
                    lines.append("\n".join(diff_lines))
                    lines.append("```")
            lines.append("")

    return "\n".join(lines)
