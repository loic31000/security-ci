#!/usr/bin/env bash
# Build the pinned Gitleaks CLI from an isolated, auditable Go dependency graph.
# No changes are made to the caller repository or its dependencies.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "usage: build_gitleaks.sh <module-directory> <binary-directory>" >&2
  exit 2
fi
module_dir="$1"
bin_dir="$2"
mkdir -p "$module_dir" "$bin_dir"
module_dir="$(cd "$module_dir" && pwd -P)"
bin_dir="$(cd "$bin_dir" && pwd -P)"
if [[ -e "$module_dir/go.mod" ]]; then
  echo "refusing to reuse an existing Go module manifest" >&2
  exit 2
fi
(
  cd "$module_dir"
  go mod init example.com/security-ci-gitleaks-build
  # The published Gitleaks v8.30.1 module uses older transitive dependencies.
  # Override known vulnerable versions only after a compatibility check in CI.
  GOTOOLCHAIN=local go get \
    github.com/zricethezav/gitleaks/v8@v8.30.1 \
    golang.org/x/crypto@v0.55.0 \
    golang.org/x/text@v0.41.0
  GOTOOLCHAIN=local GOBIN="$bin_dir" go install github.com/zricethezav/gitleaks/v8
)
test -x "$bin_dir/gitleaks"
"$bin_dir/gitleaks" version
