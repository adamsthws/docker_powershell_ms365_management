#!/usr/bin/env bash
# Start a BEC PowerShell session in the m365-admin container with a case folder mounted.
#
#   bec-shell.sh exo   <case-dir>    Exchange Online session (BecExchange.ps1)
#   bec-shell.sh graph <case-dir>    Microsoft Graph session (BecGraph.ps1)
#
# Exchange and Graph run in separate containers because their MSAL versions conflict in one
# pwsh process. Run both side by side in two terminals against the same case folder.
# The case folder is mounted at /case, so everything the helpers write lands on the host.
# The container runs as the host user so those files are not owned by root.
set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^(exo|graph)$ ]]; then
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

mode="$1"
case_dir="$(cd "$2" && pwd)"
bec_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$bec_dir/.." && pwd)"

if [[ ! -f "$case_dir/case.json" ]]; then
    echo "No case.json in $case_dir. Create the case with new-case.sh first." >&2
    exit 1
fi

case "$mode" in
    exo)   loader="/bec/BecExchange.ps1"; connect="Connect-BecExchange"
           purpose="Exchange Online: evidence, inbox rules, audit log, message trace, recipient list, mail recovery, tenant sweep" ;;
    graph) loader="/bec/BecGraph.ps1";    connect="Connect-BecGraph"
           purpose="Microsoft Graph: containment (block sign-in, revoke sessions), identity review, sign-in logs" ;;
esac

upn="$(sed -n 's/.*"upn": *"\([^"]*\)".*/\1/p' "$case_dir/case.json")"
echo
echo "=== Start a BEC $mode session ==="
echo "Starts a throwaway m365-admin container for $purpose."
echo "Nothing in the tenant is touched until you sign in and approve each step."
echo "  Case:     $case_dir"
echo "  Mailbox:  $upn"
read -r -p "Proceed? [y/N] " answer
if [[ ! "$answer" =~ ^[[:space:]]*([yY]|[yY][eE][sS])[[:space:]]*$ ]]; then
    echo "Skipped."
    exit 1
fi

if ! docker image inspect m365-admin-pwsh:local >/dev/null 2>&1; then
    docker compose -f "$repo_dir/docker-compose.yml" build
fi

exec docker compose -f "$repo_dir/docker-compose.yml" run --rm \
    -v "$case_dir:/case" \
    -v "$bec_dir/ps:/bec:ro" \
    -w /case \
    -e BEC_CASE_DIR=/case \
    -e TZ=UTC \
    -e HOME=/tmp \
    -u "$(id -u):$(id -g)" \
    m365-admin -NoLogo -NoExit -Command ". $loader; Show-BecHelp; Show-BecCase; Write-Host \"Run $connect to sign in.\" -ForegroundColor Yellow"
