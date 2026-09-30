#!/usr/bin/env bash
# Run the BEC test suite. No tenant, no sign-in, nothing leaves this machine except a one-off
# download of Pester/PSScriptAnalyzer if the image does not have them yet.
#
#   test.sh                 everything
#   test.sh Static          syntax, lint, command/parameter and gating checks
#   test.sh Unit            behaviour tests with mocked Exchange/Graph cmdlets
#   test.sh Scripts         shell script tests
#   test.sh Static Unit     several tags
set -euo pipefail

bec_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$bec_dir/.." && pwd)"
modules_dir="$repo_dir/.scratch_area/ps-test-modules"
mkdir -p "$modules_dir"

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck "$bec_dir"/scripts/*.sh && echo "shellcheck: OK"
else
    echo "shellcheck not installed on the host; skipping (bash -n still runs in the Scripts tests)."
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
    -v "$bec_dir:/bec-root:ro" \
    -v "$modules_dir:/test-modules" \
    -e HOME=/tmp \
    -e TZ=UTC \
    -w /tmp \
    -u "$(id -u):$(id -g)" \
    --entrypoint pwsh \
    m365-admin-pwsh:local -NoLogo -NoProfile -File /bec-root/tests/Invoke-BecTests.ps1 $tags
