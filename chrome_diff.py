# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Chrome Web Store interaction and CRX format handling.

Downloads Chrome extensions, strips CRX3 headers, and extracts the underlying
ZIP archive for diffing.  Also provides ``fetch_top_extensions(count)`` to
discover the most popular extensions from the Chrome Web Store by scraping
category pages and extracting the server-side rendered extension metadata.

Usage (standalone test):
    python -c "from chrome_diff import check_extension_version; print(check_extension_version('cjpalhdlnbpafiamejdnhcphjbkeiagm'))"
    python -c "from chrome_diff import fetch_top_extensions; print(fetch_top_extensions(10))"
"""

from __future__ import annotations

import json
import logging
import re
import struct
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from package_diff import extract_archive

log = logging.getLogger("monitor.chrome")

CRX_UPDATE_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=updatecheck&acceptformat=crx2,crx3"
    "&prodversion={prodversion}&x={x}"
)

CRX_DOWNLOAD_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&acceptformat=crx2,crx3"
    "&prodversion={prodversion}&x={x}"
)

CRX3_MAGIC = b"Cr24"
CRX3_VERSION = 3


def check_extension_version(
    ext_id: str, prodversion: str = "130.0",
) -> tuple[str, str]:
    """Check the Chrome Web Store for the current version of an extension.

    Returns (version, codebase_url).
    Raises RuntimeError if the extension is not found or the response is invalid.
    """
    x_param = urllib.parse.quote(f"id={ext_id}&uc")
    url = CRX_UPDATE_URL.format(prodversion=prodversion, x=x_param)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
    except Exception as e:
        raise RuntimeError(f"Failed to check version for {ext_id}: {e}") from e

    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise RuntimeError(f"Invalid XML response for {ext_id}: {e}") from e

    # The response uses the Omaha protocol; namespaces vary so search by local name.
    for elem in root.iter():
        if elem.tag.split("}")[-1] == "updatecheck":
            version = elem.get("version")
            codebase = elem.get("codebase")
            status = elem.get("status", "")
            if status == "noupdate" or not version:
                raise RuntimeError(
                    f"Extension {ext_id} not found or no update available "
                    f"(status={status!r})"
                )
            if not codebase:
                # Build the download URL ourselves
                x_dl = urllib.parse.quote(
                    f"id={ext_id}&installsource=ondemand&uc"
                )
                codebase = CRX_DOWNLOAD_URL.format(
                    prodversion=prodversion, x=x_dl,
                )
            return version, codebase

    raise RuntimeError(f"No updatecheck element found in response for {ext_id}")


def download_crx(url: str, dest: Path) -> Path:
    """Download a CRX file from *url* into *dest* directory. Returns the file path."""
    dest.mkdir(parents=True, exist_ok=True)
    out_path = dest / "extension.crx"
    log.info("Downloading CRX from %s", url[:120])
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        out_path.write_bytes(resp.read())
    return out_path


def strip_crx_header(crx_path: Path) -> Path:
    """Strip the CRX3 binary header and write the ZIP payload to a .zip file.

    CRX3 format:
        4 bytes  - magic "Cr24"
        4 bytes  - format version (uint32 LE, must be 3)
        4 bytes  - header length (uint32 LE)
        N bytes  - signed header (protobuf, length = header_length)
        rest     - ZIP archive

    Returns the path to the extracted .zip file.
    """
    data = crx_path.read_bytes()

    if len(data) < 12:
        raise RuntimeError(f"CRX file too small ({len(data)} bytes): {crx_path}")

    magic = data[:4]
    if magic != CRX3_MAGIC:
        raise RuntimeError(
            f"Not a CRX file (magic={magic!r}, expected {CRX3_MAGIC!r}): {crx_path}"
        )

    version = struct.unpack("<I", data[4:8])[0]
    if version != CRX3_VERSION:
        raise RuntimeError(
            f"Unsupported CRX version {version} (only CRX3 supported): {crx_path}"
        )

    header_length = struct.unpack("<I", data[8:12])[0]
    zip_offset = 12 + header_length

    if zip_offset > len(data):
        raise RuntimeError(
            f"CRX header length ({header_length}) exceeds file size: {crx_path}"
        )

    zip_data = data[zip_offset:]
    zip_path = crx_path.with_suffix(".zip")
    zip_path.write_bytes(zip_data)
    return zip_path


def extract_crx(crx_path: Path, dest: Path) -> Path:
    """Strip the CRX header and extract the ZIP contents.

    Delegates to package_diff.extract_archive() which provides path-traversal
    protection.  Returns the root directory of extracted contents.
    """
    zip_path = strip_crx_header(crx_path)
    return extract_archive(zip_path, dest)


# ---------------------------------------------------------------------------
# Top-extensions discovery from the Chrome Web Store
# ---------------------------------------------------------------------------

# Category pages are listed on the main extensions page; each shows ~32
# popular extensions.  The main page (extensions) shows a curated set of ~50.
_CWS_CATEGORIES = [
    "extensions",
    "extensions/productivity/communication",
    "extensions/productivity/workflow",
    "extensions/productivity/tools",
    "extensions/productivity/education",
    "extensions/productivity/developer",
    "extensions/lifestyle/shopping",
    "extensions/lifestyle/news",
    "extensions/lifestyle/entertainment",
    "extensions/lifestyle/games",
    "extensions/lifestyle/social",
    "extensions/lifestyle/art",
    "extensions/lifestyle/well_being",
    "extensions/lifestyle/travel",
    "extensions/lifestyle/household",
    "extensions/lifestyle/fun",
    "extensions/make_chrome_yours/accessibility",
    "extensions/make_chrome_yours/functionality",
    "extensions/make_chrome_yours/privacy",
]

_CWS_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


def _extract_extensions_from_html(html: str) -> list[dict]:
    """Parse CWS page HTML and return extension entries.

    The Chrome Web Store embeds extension data in an ``AF_initDataCallback``
    block keyed ``ds:1``.  Each extension entry is a nested list with:

    - ``[0]`` extension ID (32-char lowercase)
    - ``[2]`` display name
    - ``[14]`` approximate user count (int)
    """
    ds1_marker = "key: 'ds:1'"
    ds1_start = html.find(ds1_marker)
    if ds1_start == -1:
        return []

    data_start = html.find("data:", ds1_start)
    if data_start == -1:
        return []
    data_start += 5  # skip past "data:"

    # Walk forward to find the balanced end of the JSON array.
    depth = 0
    pos = data_start
    while pos < len(html):
        ch = html[pos]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                break
        pos += 1

    try:
        data = json.loads(html[data_start : pos + 1])
    except (json.JSONDecodeError, ValueError):
        return []

    results: list[dict] = []
    seen: set[str] = set()

    def _walk(obj: object) -> None:
        if not isinstance(obj, list):
            return
        # Check if this list looks like an extension entry: item[0] is a
        # 32-char lowercase alpha string (extension ID).
        if (
            len(obj) > 14
            and isinstance(obj[0], str)
            and len(obj[0]) == 32
            and obj[0].isalpha()
            and obj[0].islower()
        ):
            ext_id = obj[0]
            if ext_id not in seen:
                seen.add(ext_id)
                name = obj[2] if isinstance(obj[2], str) else ext_id
                users = obj[14] if isinstance(obj[14], (int, float)) else 0
                results.append({"id": ext_id, "name": name, "users": int(users)})
            return  # don't recurse into this entry
        for item in obj:
            _walk(item)

    _walk(data)
    return results


def fetch_top_extensions(count: int) -> list[dict[str, str]]:
    """Fetch the most popular Chrome extensions from the Web Store.

    Scrapes CWS category pages, collects extension metadata, deduplicates,
    sorts by user count (descending) and returns the top *count* entries as
    ``[{"id": ..., "name": ...}, ...]``.

    Falls back to search-based discovery if category pages don't yield enough.
    """
    log.info("[chrome-top] Fetching top %d extensions from Chrome Web Store...", count)
    all_exts: dict[str, dict] = {}  # id -> {id, name, users}

    for cat in _CWS_CATEGORIES:
        url = f"https://chromewebstore.google.com/category/{cat}?hl=en"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _CWS_UA})
            with urllib.request.urlopen(req, timeout=20) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            exts = _extract_extensions_from_html(html)
            new = 0
            for e in exts:
                if e["id"] not in all_exts:
                    all_exts[e["id"]] = e
                    new += 1
            log.info("[chrome-top] %s: %d new (%d on page, %d total)", cat, new, len(exts), len(all_exts))
        except Exception as exc:
            log.warning("[chrome-top] Failed to fetch %s: %s", cat, exc)
        time.sleep(0.5)

    if len(all_exts) < count:
        # Supplement with search-based discovery
        _search_supplement(all_exts, count)

    # Sort by user count descending, return top N
    sorted_exts = sorted(all_exts.values(), key=lambda e: e.get("users", 0), reverse=True)
    return [{"id": e["id"], "name": e["name"]} for e in sorted_exts[:count]]


_SEARCH_TERMS = [
    "ad blocker", "vpn", "password manager", "dark mode", "screenshot",
    "tab manager", "productivity", "developer tools", "grammar", "email",
    "video downloader", "pdf", "translator", "bookmark manager",
    "shopping", "coupon", "note taking", "reader mode", "security",
    "proxy", "json viewer", "accessibility", "zoom", "google",
    "ai assistant", "chatgpt", "writing", "image editor", "music",
    "crypto wallet", "weather", "news reader", "social media",
    "github", "calendar", "clipboard", "privacy", "automation",
]


def _search_supplement(all_exts: dict[str, dict], target: int) -> None:
    """Use CWS search to discover additional extensions."""
    log.info("[chrome-top] Supplementing via search (%d found so far, target %d)", len(all_exts), target)
    for term in _SEARCH_TERMS:
        if len(all_exts) >= target:
            break
        encoded = urllib.parse.quote(term)
        url = f"https://chromewebstore.google.com/search/{encoded}?itemType=extensions&hl=en"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _CWS_UA})
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            exts = _extract_extensions_from_html(html)
            if not exts:
                # Fallback: extract IDs from detail links in HTML
                for match in re.finditer(r"/detail/([^/\"]+)/([a-z]{32})", html):
                    slug, ext_id = match.group(1), match.group(2)
                    if ext_id not in all_exts:
                        name = urllib.parse.unquote(slug).replace("-", " ").title()
                        all_exts[ext_id] = {"id": ext_id, "name": name, "users": 0}
            else:
                for e in exts:
                    if e["id"] not in all_exts:
                        all_exts[e["id"]] = e
        except Exception:
            pass
        time.sleep(0.5)
