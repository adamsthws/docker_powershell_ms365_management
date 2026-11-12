#!/usr/bin/env bash
# Create a BEC case folder.
#
#   new-case.sh [--tenant <tenant>] [--admin <admin-upn>] <client-slug> <compromised-upn> [known-good-ip-prefix ...]
#
#   --tenant  the client's tenant (contoso.onmicrosoft.com or its tenant ID); Connect-BecGraph signs in there
#   --admin   the admin account to sign in with; pre-filled at the Graph and Exchange sign-ins
#
# Cases go in <repo>/.scratch_area/bec-cases/ (gitignored; override with BEC_CASES_DIR).
# They hold client evidence and personal data, so never commit them.
set -euo pipefail

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

tenant=""
admin=""
while [[ $# -gt 0 && "$1" == --* ]]; do
    case "$1" in
        --tenant) [[ $# -ge 2 ]] || usage; tenant="$2"; shift 2 ;;
        --admin)  [[ $# -ge 2 ]] || usage; admin="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

if [[ $# -lt 2 ]]; then
    usage
fi

client="$1"
upn="$2"
shift 2

bec_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$bec_dir/.." && pwd)"
cases_dir="${BEC_CASES_DIR:-$repo_dir/.scratch_area/bec-cases}"
case_dir="$cases_dir/$(date -u +%Y%m%d)-${client}-${upn%%@*}"

if [[ -e "$case_dir" ]]; then
    echo "Case folder already exists: $case_dir" >&2
    exit 1
fi

echo
echo "=== 01 Open a BEC case ==="
echo "Creates a case folder for $upn ($client). Nothing in the tenant is touched."
echo "  Folder:          $case_dir"
echo "  Tenant:          ${tenant:-not set (Connect-BecGraph uses the home tenant of the admin account)}"
echo "  Admin account:   ${admin:-not set}"
echo "  Known-good IPs:  ${*:-none yet (add them to case.json later)}"
echo "  Creates:         case.json, intake.md, actions.log, evidence/, notification/, report/"
read -r -p "Proceed? [y/N] " answer
if [[ ! "$answer" =~ ^[[:space:]]*([yY]|[yY][eE][sS])[[:space:]]*$ ]]; then
    echo "Skipped."
    exit 1
fi

mkdir -p "$case_dir"/{evidence,notification,report}

prefixes_json="[]"
if [[ $# -gt 0 ]]; then
    prefixes_json="[$(printf '"%s",' "$@" | sed 's/,$//')]"
fi

cat > "$case_dir/case.json" <<EOF
{
  "client": "$client",
  "upn": "$upn",
  "tenant": "$tenant",
  "tenantId": "",
  "adminUpn": "$admin",
  "entraPremium": "",
  "createdUtc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "compromiseStartUtc": "",
  "containedUtc": "",
  "knownGoodIpPrefixes": $prefixes_json,
  "attackerIps": [],
  "phishingSubjects": []
}
EOF

cp "$bec_dir/templates/intake-questionnaire.md" "$case_dir/intake.md"
echo "$(date -u '+%Y-%m-%d %H:%M:%S')Z  Case opened for $upn ($client)" > "$case_dir/actions.log"

echo "Created $case_dir"
echo
echo "Next:"
echo "  1. Fill in $case_dir/intake.md with the user (procedures/01-intake.md)"
echo "  2. $bec_dir/scripts/bec-shell.sh graph \"$case_dir\"   # containment"
echo "  3. $bec_dir/scripts/bec-shell.sh exo \"$case_dir\"     # mailbox work"
