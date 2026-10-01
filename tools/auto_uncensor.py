#!/usr/bin/env python3
"""
Auto-Uncensor: downloads the official Antigravity CLI for this machine,
then exact-match patches it.

macOS archives are tar.gz and contain a binary named `antigravity`.
Windows archives are zip and contain `antigravity.exe`.
The official installer renames the macOS binary to `agy` on disk.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import zipfile
from urllib.request import Request, urlopen

OFFICIAL_REPO = "google-antigravity/antigravity-cli"
MY_REPO = "ana-joker/antigravity-uncensored"
TARGETS_URL = f"https://raw.githubusercontent.com/{MY_REPO}/main/tools/targets.json"

# Asset names match google-antigravity/antigravity-cli release uploads.
# `member` is the file inside the archive (see the official install.sh).
PLATFORMS = {
    "mac-arm64": {
        "asset": "agy_cli_mac_arm64.tar.gz",
        "member": "antigravity",
    },
    "mac-x64": {
        "asset": "agy_cli_mac_x64.tar.gz",
        "member": "antigravity",
    },
    "windows-x64": {
        "asset": "agy_cli_windows_x64.zip",
        "member": "antigravity.exe",
    },
    "windows-arm64": {
        "asset": "agy_cli_windows_arm64.zip",
        "member": "antigravity.exe",
    },
}


def host_platform():
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        arch = "x64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        return None
    if sys.platform == "darwin":
        return f"mac-{arch}"
    if sys.platform == "win32":
        return f"windows-{arch}"
    return None


def get_latest_release(repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "auto-uncensor"})
    with urlopen(req) as response:
        return json.loads(response.read())


def download_asset(url, dest):
    req = Request(url, headers={"Accept": "application/octet-stream", "User-Agent": "auto-uncensor"})
    with urlopen(req) as response, open(dest, "wb") as out:
        shutil.copyfileobj(response, out)


def find_member(names, wanted):
    hits = []
    for name in names:
        if name.endswith("/"):
            continue
        if os.path.basename(name) == wanted:
            hits.append(name)
    if not hits:
        preview = ", ".join(names[:12])
        raise SystemExit(f"ERROR: {wanted!r} not in archive (saw: {preview})")
    hits.sort(key=len)
    return hits[0]


def extract_member(archive_path, member, dest):
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            match = find_member(zf.namelist(), member)
            with zf.open(match) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
        return
    if archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as tf:
            match = find_member([m.name for m in tf.getmembers() if m.isfile()], member)
            extracted = tf.extractfile(match)
            if extracted is None:
                raise SystemExit(f"ERROR: could not read {match} from archive")
            with extracted, open(dest, "wb") as out:
                shutil.copyfileobj(extracted, out)
        return
    raise SystemExit(f"ERROR: unsupported archive: {archive_path}")


def ensure_targets(targets_path, refresh=False):
    if os.path.exists(targets_path) and not refresh:
        return
    print("[4] Downloading targets.json...")
    req = Request(TARGETS_URL, headers={"User-Agent": "auto-uncensor"})
    with urlopen(req) as response, open(targets_path, "wb") as out:
        out.write(response.read())


def output_name(version, platform_id):
    tag = version.lstrip("v")
    if platform_id.startswith("windows"):
        return f"antigravity-uncensored-{tag}-{platform_id}.exe"
    return f"antigravity-uncensored-{tag}-{platform_id}"


def main():
    parser = argparse.ArgumentParser(description="Download and patch the official Antigravity CLI")
    parser.add_argument(
        "--platform",
        choices=sorted(PLATFORMS),
        help="release to fetch (default: this machine)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="dry-run: report keyword hit/miss against the fresh download, produce no binary",
    )
    parser.add_argument(
        "--refresh-targets",
        action="store_true",
        help="re-download targets.json even if a local copy exists",
    )
    args = parser.parse_args()

    platform_id = args.platform or host_platform()
    if platform_id not in PLATFORMS:
        supported = ", ".join(sorted(PLATFORMS))
        print(f"ERROR: this host is not supported. Pass --platform. Known: {supported}")
        sys.exit(1)
    spec = PLATFORMS[platform_id]

    print("=== AGY Auto-Uncensor ===\n")
    print(f"[0] Platform: {platform_id}")

    print("[1] Fetching latest official release...")
    release = get_latest_release(OFFICIAL_REPO)
    version = release["tag_name"]
    print(f"    Found: {version}\n")

    asset_url = None
    for asset in release["assets"]:
        if asset["name"] == spec["asset"]:
            asset_url = asset["url"]
            break
    if not asset_url:
        print(f"ERROR: {spec['asset']} not found in release {version}")
        sys.exit(1)

    archive_path = os.path.join(tempfile.gettempdir(), spec["asset"])
    print(f"[2] Downloading official binary ({spec['asset']})...")
    download_asset(asset_url, archive_path)
    print(f"    Saved to: {archive_path}\n")

    binary_path = os.path.join(tempfile.gettempdir(), f"antigravity-uncensor-{platform_id}")
    # A leftover backup would make the patcher reuse yesterday's bytes.
    for stale in (binary_path, binary_path + ".original"):
        if os.path.exists(stale):
            os.remove(stale)

    print("[3] Extracting...")
    extract_member(archive_path, spec["member"], binary_path)
    os.chmod(binary_path, 0o755)
    with open(binary_path, "rb") as f:
        original_sha = hashlib.sha256(f.read()).hexdigest()
    print(f"    SHA256: {original_sha}\n")

    targets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targets.json")
    ensure_targets(targets_path, refresh=args.refresh_targets)

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from agy_domesticate import Patcher

    if args.check:
        print("[5] Checking keyword coverage (dry-run)...")
        Patcher(binary_path, targets_path, check_only=True).run()
        print("\n=== CHECK DONE — no binary produced ===")
        return

    print("[5] Patching binary (exact-match, same length)...")
    patcher = Patcher(binary_path, targets_path)
    patcher.run()
    with open(binary_path, "rb") as f:
        patched_sha = hashlib.sha256(f.read()).hexdigest()

    output_path = os.path.join(os.getcwd(), output_name(version, platform_id))
    shutil.copy2(binary_path, output_path)
    os.chmod(output_path, 0o755)
    print("\n=== DONE ===")
    print(f"Patched binary: {output_path}")
    print(f"Original SHA:   {original_sha}")
    print(f"Patched SHA:    {patched_sha}")
    print(f"Total patches:  {patcher.total_patches}")
    if platform_id.startswith("mac"):
        print("Launch with:    ./" + os.path.basename(output_path))
        print("Installed copy: ~/.local/bin/agy or $(which agy) — patch that path only if you mean to replace it.")


if __name__ == "__main__":
    main()
