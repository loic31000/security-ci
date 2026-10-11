#!/usr/bin/env bash
# Prepare opt-in rollout pull requests. Never push directly to default branches.
set -euo pipefail

sha="${1:-}"
mode="${2:-}"
config="${3:-}"
if (( $# > 3 )) || [[ ! "$sha" =~ ^[a-fA-F0-9]{40}$ ]] || [[ -n "$mode" && "$mode" != "--apply" ]]; then
  echo "Usage: $0 <40-char-commit-SHA> [--apply] [test-commands.json]" >&2
  exit 2
fi
command -v gh >/dev/null || { echo "GitHub CLI (gh) is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

if [[ "$mode" == "--apply" && -z "$config" ]]; then
  echo "Refusing --apply without a per-repository test command configuration" >&2
  exit 2
fi
if [[ -n "$config" ]]; then
  [[ -r "$config" ]] && jq -e 'type == "object" and all(.[]; type == "string")' "$config" >/dev/null || {
    echo "Configuration must be a readable JSON object mapping full repository names to test commands" >&2
    exit 2
  }
fi

while IFS=$'\t' read -r name default_branch archived fork; do
  [[ -n "$name" ]] || continue
  [[ "$name" == "security-ci" || "$archived" == "true" || "$fork" == "true" ]] && continue
  repo="loic31000/$name"
  path=".github/workflows/security.yml"
  test_command=""
  if [[ -n "$config" ]]; then
    test_command="$(jq -r --arg repo "$repo" '.[$repo] // empty' "$config")"
  fi
  if [[ -z "${test_command//[[:space:]]/}" ]]; then
    echo "SKIP $repo: no explicitly configured project test command"
    continue
  fi
  if [[ "$test_command" == *$'\n'* || "$test_command" == *$'\r'* ]]; then
    echo "SKIP $repo: use a single-line test command" >&2
    continue
  fi
  if gh api "repos/$repo/contents/$path" --silent >/dev/null 2>&1; then
    echo "SKIP existing workflow: $repo"
    continue
  fi
  echo "PLAN $repo -> draft pull request against $default_branch"
  [[ "$mode" == "--apply" ]] || continue
  branch="chore/security-ci-rollout"
  if gh api "repos/$repo/git/ref/heads/$branch" --silent >/dev/null 2>&1; then
    echo "SKIP existing branch $repo"
    continue
  fi
  base_sha="$(gh api "repos/$repo/git/ref/heads/$default_branch" --jq '.object.sha')"
  gh api -X POST "repos/$repo/git/refs" -f "ref=refs/heads/$branch" -f "sha=$base_sha" >/dev/null

  # YAML single-quoted scalar: escape apostrophes by doubling them.
  yaml_test_command="${test_command//\'/\'\'}"
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
      test_command: '$yaml_test_command'
YAML
)"
  encoded="$(printf '%s' "$content" | base64 | tr -d '\n')"
  gh api -X PUT "repos/$repo/contents/$path" -f "message=chore: install centralized audit" -f "content=$encoded" -f "branch=$branch" >/dev/null
  gh pr create --draft --repo "$repo" --base "$default_branch" --head "$branch" \
    --title "chore: enable centralized security audit" \
    --body "SHA-pinned security analysis and project-specific test command. Review the command and CI checks before merging. No changes to the default branch are made by this script."
done < <(gh api "user/repos?per_page=100&affiliation=owner" --paginate --jq '.[] | [.name,.default_branch,(.archived|tostring),(.fork|tostring)] | @tsv')
