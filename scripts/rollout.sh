#!/usr/bin/env bash
set -euo pipefail
sha="${1:-}"; mode="${2:-}"
[[ "$sha" =~ ^[a-fA-F0-9]{40}$ ]] || { echo "Supply a 40-character commit SHA"; exit 2; }
[[ -z "$mode" || "$mode" == "--apply" ]] || exit 2
command -v gh >/dev/null || exit 2
while IFS=$'\t' read -r name default_branch archived fork; do
  [[ -n "$name" ]] || continue
  [[ "$name" == "security-ci" || "$archived" == "true" || "$fork" == "true" ]] && continue
  repo="loic31000/$name"; path=".github/workflows/security.yml"
  if gh api "repos/$repo/contents/$path" --silent >/dev/null 2>&1; then
    echo "SKIP existing workflow: $repo"; continue
  fi
  echo "PLAN $repo -> pull request against $default_branch"
  [[ "$mode" == "--apply" ]] || continue
  branch="chore/security-ci-rollout"
  if gh api "repos/$repo/git/ref/heads/$branch" --silent >/dev/null 2>&1; then
    echo "SKIP existing branch $repo"; continue
  fi
  base_sha="$(gh api "repos/$repo/git/ref/heads/$default_branch" --jq '.object.sha')"
  gh api -X POST "repos/$repo/git/refs" -f "ref=refs/heads/$branch" -f "sha=$base_sha" >/dev/null
  content="$(cat <<YAML
name: Security and maintainability
on:
  pull_request:
  push:
    branches: [$default_branch]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  audit:
    uses: loic31000/security-ci/.github/workflows/security-audit.yml@$sha
    with:
      enforce: false
YAML
)"
  encoded="$(printf '%s' "$content" | base64 | tr -d '\n')"
  gh api -X PUT "repos/$repo/contents/$path" -f "message=chore: install centralized audit" -f "content=$encoded" -f "branch=$branch" >/dev/null
  gh pr create --repo "$repo" --base "$default_branch" --head "$branch" --title "chore: enable centralized security audit" --body "SHA-pinned non-blocking security and maintainability analysis. Test execution requires separate configuration."
done < <(gh api "user/repos?per_page=100&affiliation=owner" --paginate --jq '.[] | [.name,.default_branch,(.archived|tostring),(.fork|tostring)] | @tsv')
