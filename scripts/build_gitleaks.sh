#!/usr/bin/env bash
# Install an immutable, pre-reviewed Gitleaks module graph before compilation.
# This script never reads or edits dependency files from the caller repository.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: build_gitleaks.sh <temporary-module-directory> <binary-directory>" >&2
  exit 2
fi
module_dir="$1"
bin_dir="$2"
engine_root="$(cd "$(dirname "$0")/.." && pwd -P)"
lock_dir="$engine_root/locks/gitleaks"

for locked in go.mod go.sum; do
  if [[ ! -f "$lock_dir/$locked" || -L "$lock_dir/$locked" ]]; then
    echo "missing or untrusted Gitleaks lock: $locked" >&2
    exit 2
  fi
done

# The baseline matches the last independently reviewed three-target Trivy audit.
python3 - "$engine_root" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
refs = json.loads((root / "locks/engine-manifest-sha256.json").read_text())["files"]
for name in ("go.mod", "go.sum"):
    path = root / "locks/gitleaks" / name
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != refs[f"go/{name}"]:
        raise SystemExit(f"Gitleaks {name} checksum differs from reviewed baseline")
PY

mkdir -p "$module_dir" "$bin_dir"
module_dir="$(cd "$module_dir" && pwd -P)"
bin_dir="$(cd "$bin_dir" && pwd -P)"
if [[ -e "$module_dir/go.mod" || -e "$module_dir/go.sum" ]]; then
  echo "refusing to overwrite any existing Go module manifest" >&2
  exit 2
fi
cp -- "$lock_dir/go.mod" "$lock_dir/go.sum" "$module_dir/"
(
  cd "$module_dir"
  export GOTOOLCHAIN=local GOWORK=off
  export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
  # The sum database and go.sum verify downloaded module checksums; build cannot
  # re-resolve module versions or write changed go.mod/go.sum (-mod=readonly).
  go mod download all
  go mod verify
  go build -mod=readonly -o "$bin_dir/gitleaks" github.com/zricethezav/gitleaks/v8
)
cmp -s "$lock_dir/go.mod" "$module_dir/go.mod" || {
  echo "Go module graph changed during build" >&2; exit 2;
}
cmp -s "$lock_dir/go.sum" "$module_dir/go.sum" || {
  echo "Go checksum lock changed during build" >&2; exit 2;
}
test -x "$bin_dir/gitleaks"
"$bin_dir/gitleaks" version
