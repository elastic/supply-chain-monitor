# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Compare two versions of a pip package without installing them.

Usage:
    python package_diff.py <package> <version1> <version2>
    python package_diff.py --local <archive1> <archive2> [-n NAME]

Examples:
    python package_diff.py requests 2.31.0 2.32.0
    python package_diff.py --local old.tar.gz new.tar.gz -n mypackage
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

PYPI_VERSION_URL = "https://pypi.org/pypi/{package}/{version}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org"


def _pick_best_wheel(wheels: list[dict]) -> dict:
    """Pick the most diffable wheel from a list of wheel file entries.

    Prefers pure-Python universal wheels (py3-none-any) because they contain
    only text files and are consistent across platforms.  Falls back to the
    first available wheel.
    """
    for w in wheels:
        fn = w["filename"].lower()
        if "py3-none-any" in fn or "py2.py3-none-any" in fn:
            return w
    return wheels[0]


def download_package(
    package: str, version: str, dest: Path, packagetype: str | None = None,
) -> Path:
    """Download a specific version of a package directly from the PyPI JSON API.

    When *packagetype* is given (e.g. ``"bdist_wheel"`` or ``"sdist"``), only
    that type is considered — raises RuntimeError if unavailable.  Otherwise
    prefers wheel, falls back to sdist.
    """
    dest.mkdir(parents=True, exist_ok=True)
    url = PYPI_VERSION_URL.format(package=package, version=version)
    print(f"Fetching metadata for {package}=={version}...")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"Failed to fetch PyPI metadata for {package}=={version}: {e}")

    files = data.get("urls", [])
    if not files:
        raise RuntimeError(f"No files available for {package}=={version}")

    if packagetype:
        typed = [f for f in files if f["packagetype"] == packagetype]
        if not typed:
            raise RuntimeError(f"No {packagetype} for {package}=={version}")
        chosen = _pick_best_wheel(typed) if packagetype == "bdist_wheel" else typed[0]
    else:
        wheels = [f for f in files if f["packagetype"] == "bdist_wheel"]
        sdists = [f for f in files if f["packagetype"] == "sdist"]
        if wheels:
            chosen = _pick_best_wheel(wheels)
        else:
            chosen = (sdists or files)[0]

    download_url = chosen["url"]
    filename = chosen["filename"]
    out_path = dest / filename

    print(f"Downloading {filename} ({chosen['packagetype']})...")
    urllib.request.urlretrieve(download_url, out_path)
    return out_path


def download_npm_package(package: str, version: str, dest: Path) -> Path:
    """Download a specific version of an npm package tarball from the registry.

    Fetches version metadata to get the exact tarball URL, then downloads it.
    Handles scoped packages (e.g. @scope/name) transparently.
    """
    dest.mkdir(parents=True, exist_ok=True)
    encoded = package.replace("/", "%2F")
    url = f"{NPM_REGISTRY_URL}/{encoded}/{version}"
    print(f"Fetching npm metadata for {package}@{version}...")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"Failed to fetch npm metadata for {package}@{version}: {e}")

    tarball_url = data.get("dist", {}).get("tarball")
    if not tarball_url:
        raise RuntimeError(f"No tarball URL found for {package}@{version}")

    filename = tarball_url.rsplit("/", 1)[-1]
    out_path = dest / filename

    print(f"Downloading {filename}...")
    urllib.request.urlretrieve(tarball_url, out_path)
    return out_path


def _safe_tar_members(tf: tarfile.TarFile, dest: Path):
    """Filter tar members to prevent path-traversal attacks (CVE-2007-4559)."""
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        member_path = (dest / member.name).resolve()
        if not str(member_path).startswith(str(dest_resolved)):
            raise RuntimeError(
                f"Tar path traversal blocked: {member.name!r} escapes {dest}"
            )
        if member.issym() or member.islnk():
            member_dir = (dest / member.name).resolve().parent
            link_target = (member_dir / member.linkname).resolve()
            if not str(link_target).startswith(str(dest_resolved)):
                raise RuntimeError(
                    f"Tar symlink traversal blocked: {member.name!r} -> {member.linkname!r}"
                )
        yield member


def _safe_zip_members(zf: zipfile.ZipFile, dest: Path):
    """Filter zip members to prevent path-traversal attacks."""
    dest_resolved = dest.resolve()
    for info in zf.infolist():
        member_path = (dest / info.filename).resolve()
        if not str(member_path).startswith(str(dest_resolved)):
            raise RuntimeError(
                f"Zip path traversal blocked: {info.filename!r} escapes {dest}"
            )
        yield info


def extract_archive(archive: Path, dest: Path) -> Path:
    """Extract a .tar.gz, .zip, or .whl archive and return the root folder."""
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()

    if name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest, members=list(_safe_tar_members(tf, dest)))
    elif name.endswith(".tar.bz2"):
        with tarfile.open(archive, "r:bz2") as tf:
            tf.extractall(dest, members=list(_safe_tar_members(tf, dest)))
    elif name.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(dest, members=[m.filename for m in _safe_zip_members(zf, dest)])
    else:
        raise RuntimeError(f"Unsupported archive format: {archive.name}")

    children = [p for p in dest.iterdir() if not p.name.startswith(".")]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest


def collect_files(root: Path) -> dict[str, Path]:
    """Return a dict of relative-path -> absolute-path for every file under root."""
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            files[str(path.relative_to(root))] = path
    return files


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def is_text_file(path: Path) -> bool:
    try:
        path.read_text(encoding="utf-8", errors="strict")
        return True
    except (UnicodeDecodeError, ValueError):
        return False


def unified_diff(path_a: Path, path_b: Path, label_a: str, label_b: str, context: int = 3) -> str | None:
    """Return a unified diff string for two text files, or None for binary files."""
    if not is_text_file(path_a) or not is_text_file(path_b):
        return None
    lines_a = path_a.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    lines_b = path_b.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    diff = list(difflib.unified_diff(lines_a, lines_b, fromfile=label_a, tofile=label_b, n=context))
    if not diff:
        return ""
    return "".join(diff)


def generate_report(
    package: str,
    v1: str, v2: str,
    files_v1: dict[str, Path],
    files_v2: dict[str, Path],
) -> str:
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

    lines: list[str] = []
    lines.append(f"# Diff Report: {package} {v1} → {v2}")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Files in {v1} | {len(files_v1)} |")
    lines.append(f"| Files in {v2} | {len(files_v2)} |")
    lines.append(f"| Added | {len(added)} |")
    lines.append(f"| Deleted | {len(deleted)} |")
    lines.append(f"| Changed | {len(changed)} |")
    lines.append(f"| Unchanged | {len(unchanged)} |")
    lines.append("")

    if added:
        lines.append("## Added Files")
        lines.append("")
        for f in added:
            lines.append(f"- `{f}`")
        lines.append("")

    if deleted:
        lines.append("## Deleted Files")
        lines.append("")
        for f in deleted:
            lines.append(f"- `{f}`")
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
                lines.append("```diff")
                lines.append(diff.rstrip())
                lines.append("```")
            lines.append("")

    return "\n".join(lines)


def _label_from_archive(path: Path) -> str:
    """Derive a human-readable version label from an archive filename."""
    name = path.name
    for ext in (".tar.gz", ".tar.bz2", ".tgz", ".zip", ".whl"):
        if name.lower().endswith(ext):
            return name[: -len(ext)]
    return path.stem


def main():
    parser = argparse.ArgumentParser(
        description="Diff two versions of a PyPI or npm package (or local archives)",
    )
    parser.add_argument("--local", nargs=2, metavar=("ARCHIVE1", "ARCHIVE2"),
                        help="Compare two local archives instead of downloading")
    parser.add_argument("--npm", action="store_true", help="Download from npm instead of PyPI")
    parser.add_argument("-n", "--name", help="Package name for the report header (auto-detected for --local)")
    parser.add_argument("package", nargs="?", help="Package name (e.g. requests, express)")
    parser.add_argument("version1", nargs="?", help="First (older) version")
    parser.add_argument("version2", nargs="?", help="Second (newer) version")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--keep", action="store_true", help="Keep downloaded/extracted files in ./pkg_diff_tmp/")
    args = parser.parse_args()

    if args.local:
        archive1 = Path(args.local[0])
        archive2 = Path(args.local[1])
        for a in (archive1, archive2):
            if not a.exists():
                parser.error(f"File not found: {a}")
    elif not all([args.package, args.version1, args.version2]):
        parser.error("Provide <package> <version1> <version2>, or use --local <file1> <file2>")

    tmp = Path(tempfile.mkdtemp(prefix="pkg_diff_")) if not args.keep else Path("pkg_diff_tmp")

    try:
        if not args.local:
            dl1 = tmp / "dl_v1"
            dl2 = tmp / "dl_v2"
            if args.npm:
                archive1 = download_npm_package(args.package, args.version1, dl1)
                archive2 = download_npm_package(args.package, args.version2, dl2)
            else:
                archive1 = download_package(args.package, args.version1, dl1)
                archive2 = download_package(args.package, args.version2, dl2)

        label1 = _label_from_archive(archive1)
        label2 = _label_from_archive(archive2)
        pkg_name = args.name or args.package or os.path.commonprefix([label1, label2]).rstrip("-_ ")
        if not pkg_name:
            pkg_name = "package"

        print(f"Extracting {archive1.name}...")
        root1 = extract_archive(archive1, tmp / "ext_v1")
        print(f"Extracting {archive2.name}...")
        root2 = extract_archive(archive2, tmp / "ext_v2")

        files_v1 = collect_files(root1)
        files_v2 = collect_files(root2)

        report = generate_report(pkg_name, label1, label2, files_v1, files_v2)

        if args.output:
            Path(args.output).write_text(report, encoding="utf-8")
            print(f"\nReport written to {args.output}")
        else:
            print("\n" + report)
    finally:
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
