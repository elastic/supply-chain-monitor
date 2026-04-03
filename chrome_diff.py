# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Chrome Web Store interaction and CRX format handling.

Downloads Chrome extensions, strips CRX3 headers, and extracts the underlying
ZIP archive for diffing.

Usage (standalone test):
    python -c "from chrome_diff import check_extension_version; print(check_extension_version('cjpalhdlnbpafiamejdnhcphjbkeiagm'))"
"""

from __future__ import annotations

import logging
import struct
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
