#!/usr/bin/env bash
# Install only the approved npm jscpd dependency graph (integrity verified by npm ci).
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: install_jscpd.sh <isolated-tool-directory>" >&2
  exit 2
fi
engine="$(cd "$(dirname "$0")/.." && pwd -P)"
target="$1"
python3 - "$engine" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
lock = root / "locks/jscpd/package-lock.json"
package = root / "locks/jscpd/package.json"
baseline = json.loads((root / "locks/engine-manifest-sha256.json").read_text())["files"]
if not lock.is_file() or lock.is_symlink() or not package.is_file() or package.is_symlink():
    raise SystemExit("missing or symlinked jscpd npm lock")
sha = hashlib.sha256(lock.read_bytes()).hexdigest()
if sha != baseline["node/package-lock.json"]:
    raise SystemExit("npm jscpd package-lock checksum differs from approved manifest")
meta = json.loads(package.read_text())
graph = json.loads(lock.read_text())
if meta.get("dependencies") != {"jscpd": "5.4.1"}:
    raise SystemExit("jscpd package.json must specify the approved exact version")
packages = graph.get("packages", {})
if graph.get("lockfileVersion") != 3 or not isinstance(packages, dict):
    raise SystemExit("jscpd lockfile must be npm v3")
target = packages.get("node_modules/jscpd")
if not isinstance(target, dict) or target.get("version") != "5.4.1":
    raise SystemExit("unexpected jscpd version")
for name, entry in packages.items():
    if name == "":
        continue
    if not isinstance(entry, dict):
        raise SystemExit("invalid locked npm entry")
    url = entry.get("resolved")
    if not isinstance(url, str) or not url.startswith("https://registry.npmjs.org/"):
        raise SystemExit("non-registry npm artifact in lock")
    integrity = entry.get("integrity")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise SystemExit("npm artifact is not SHA-512 integrity pinned")
print(f"Verified npm v3 lock and {len(packages)-1} integrity-pinned packages")
PY
if [[ -e "$target" ]]; then
  echo "refusing to overwrite an existing npm tooling directory" >&2
  exit 2
fi
mkdir -p "$target"
cp -- "$engine/locks/jscpd/package.json" "$engine/locks/jscpd/package-lock.json" "$target/"
npm ci --prefix "$target" --ignore-scripts --no-audit --no-fund --no-cache
cmp -s "$engine/locks/jscpd/package-lock.json" "$target/package-lock.json"
"$target/node_modules/.bin/jscpd" --version
