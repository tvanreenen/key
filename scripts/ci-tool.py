#!/usr/bin/env python3
"""Install checksum-pinned upstream CLIs, or run an exact installed version."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = json.loads((ROOT / ".github/ci-tools.json").read_text())
BIN = ROOT / ".build/ci-tools/bin"


def install(name):
    spec = TOOLS[name]
    system = platform.system()
    asset = spec["platforms"].get(f"{system}-{platform.machine()}")
    asset = asset or spec["platforms"].get(system)
    if not asset:
        raise RuntimeError(f"No pinned {name} asset for {system}/{platform.machine()}")
    url, expected = asset
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "key-ci"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            break
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError(f"Checksum mismatch for {name}; refusing to execute download")
    # Extract only the requested executable, never arbitrary archive paths.
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [p for p in archive.namelist() if Path(p).name == name and not p.startswith("__MACOSX/")]
            if len(members) != 1:
                raise RuntimeError(f"Expected one {name} executable in {url}")
            executable = archive.read(members[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = [p for p in archive.getmembers() if p.isfile() and Path(p.name).name == name]
            if len(members) != 1:
                raise RuntimeError(f"Expected one {name} executable in {url}")
            executable = archive.extractfile(members[0]).read()
    BIN.mkdir(parents=True, exist_ok=True)
    target = BIN / name
    temporary = target.with_suffix(".tmp")
    temporary.write_bytes(executable)
    temporary.chmod(0o755)
    temporary.replace(target)
    print(f"Installed {name} {spec['version']} (SHA-256 verified)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["install", "run"])
    parser.add_argument("tool", choices=TOOLS)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == "install":
        install(args.tool)
        return
    executable = BIN / args.tool
    if not executable.is_file():
        executable = shutil.which(args.tool)
    if not executable:
        parser.error(f"Install first: python3 scripts/ci-tool.py install {args.tool}")
    version_args = ["version"] if args.tool in {"swiftlint", "gitleaks"} else ["--version"]
    if args.tool == "actionlint":
        version_args = ["-version"]
    version = subprocess.check_output([str(executable), *version_args], text=True)
    expected = TOOLS[args.tool]["version"]
    if expected not in version.split():
        parser.error(f"{args.tool} must be {expected}; run python3 scripts/ci-tool.py install {args.tool}")
    os.chdir(ROOT)
    os.execv(str(executable), [str(executable), *args.arguments])


if __name__ == "__main__":
    main()
