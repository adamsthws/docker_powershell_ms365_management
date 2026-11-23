#!/usr/bin/env bash
# Run the endpoint triage test suite in the m365-admin container (pwsh 7 on Linux).
# No endpoint needed. Static checks also enforce Windows PowerShell 5.1 syntax compatibility.
#
#   test.sh                 everything
#   test.sh Static          syntax, lint (incl. PS 5.1 compatibility), ASCII-only, read-only and docs checks
#   test.sh Unit            parser tests with synthetic AnyDesk and Prefetch data
set -euo pipefail

triage_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$triage_dir/.." && pwd)"
modules_dir="$repo_dir/.scratch_area/ps-test-modules"
mkdir -p "$modules_dir"

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck "$triage_dir"/scripts/*.sh && echo "shellcheck: OK"
else
    echo "shellcheck not installed on the host; skipping it."
fi

if ! docker image inspect m365-admin-pwsh:local >/dev/null 2>&1; then
    docker compose -f "$repo_dir/docker-compose.yml" build
fi

tags=""
if [[ $# -gt 0 ]]; then
    tags="-Tag $(printf '%s,' "$@" | sed 's/,$//')"
fi

# shellcheck disable=SC2086 # $tags is intentionally split into pwsh arguments
docker run --rm \
    -v "$triage_dir:/triage-root:ro" \
    -v "$modules_dir:/test-modules" \
    -e HOME=/tmp \
    -e TZ=UTC \
    -w /tmp \
    -u "$(id -u):$(id -g)" \
    --entrypoint pwsh \
    m365-admin-pwsh:local -NoLogo -NoProfile -File /triage-root/tests/Invoke-TriageTests.ps1 $tags
