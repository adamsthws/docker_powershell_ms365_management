#!/usr/bin/env bash
# Print the one-line command to paste into an elevated Windows PowerShell on the endpoint.
# It downloads ps/setup/Set-TriageAccess.ps1 from this repository on GitHub, pinned to a published
# commit, and runs it in memory. SSH takes your keys from github.com/USER.keys; WinRM downloads your
# client certificate from your Gist, pinned to its current revision. The line carries no key material.
#
#   setup-command.sh [-m enable|status|remove] [-t auto|ssh|winrm] [-r REF] [-g OWNER/REPO]
#                    [-k GITHUB_USER | -i KEY.pub] [-n] [-G GIST_ID] [-c CERT] [-u USER]
#
#   -m  enable (default), status or remove
#   -t  enable only: auto tries SSH, then WinRM, then SSH via Windows Update (default); ssh or winrm limits it
#   -r  commit, tag or branch to download from (default: the commit origin/main points to here;
#       run "git fetch" first so that is current)
#   -g  GitHub OWNER/REPO (default: from the origin remote)
#   -k  GitHub user whose public keys SSH accepts (default: OWNER of the repository)
#   -i  put this public key in the line instead of using -k
#   -n  do not check github.com/USER.keys from here
#   -G  Gist holding winrm-client.pem (default: the ID in ~/.config/endpoint-triage/winrm-gist);
#       without one, WinRM is not offered
#   -c  your local copy of that certificate, to check the Gist against
#       (default ~/.config/endpoint-triage/winrm-client.pem)
#   -u  temporary admin name, if not temp-local-admin
#
# Publish the certificate once (a secret Gist is enough; the certificate is not a secret):
#   gh gist create ~/.config/endpoint-triage/winrm-client.pem   then save the ID it prints in
#   ~/.config/endpoint-triage/winrm-gist
# The command goes to standard output and nothing is written to disk.
set -euo pipefail

die() { echo "setup-command.sh: $*" >&2; exit 2; }
note() { echo "$*" >&2; }

config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/endpoint-triage"
mode=enable
methods=auto
ref=""
gh_repo=""
cert="$config_dir/winrm-client.pem"
gist=""
gh_user=""
pubkey=""
user=""
check_keys=1
while getopts ":m:t:r:g:k:i:nG:c:u:h" opt; do
    case "$opt" in
        m) mode="$OPTARG" ;;
        t) methods="$OPTARG" ;;
        r) ref="$OPTARG" ;;
        g) gh_repo="$OPTARG" ;;
        k) gh_user="$OPTARG" ;;
        i) pubkey="$OPTARG" ;;
        n) check_keys=0 ;;
        G) gist="$OPTARG" ;;
        c) cert="$OPTARG" ;;
        u) user="$OPTARG" ;;
        h) awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
        :) die "option -$OPTARG needs a value" ;;
        *) die "unknown option -$OPTARG (see -h)" ;;
    esac
done
[[ "$mode" =~ ^(enable|status|remove)$ ]] || die "mode must be enable, status or remove: $mode"
[[ "$methods" =~ ^(auto|winrm|ssh)$ ]] || die "-t must be auto, ssh or winrm: $methods"
[[ -z "$gh_user" || -z "$pubkey" ]] || die "give -k or -i, not both"
[[ -z "$gh_user" || "$gh_user" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]] || die "not a GitHub user name: $gh_user"
[[ -z "$user" || "$user" =~ ^[A-Za-z0-9._-]{1,20}$ ]] || die "user name must be 1-20 of A-Z a-z 0-9 . _ -: $user"

triage_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$triage_dir/.." && pwd)"
script_path="endpoint-triage/ps/setup/Set-TriageAccess.ps1"

if [[ -z "$gh_repo" ]]; then
    origin="$(git -C "$repo_dir" remote get-url origin 2>/dev/null)" || die "no origin remote; give -g OWNER/REPO"
    gh_repo="$(sed -E -n 's#^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+/[^/]+)$#\2#p' <<<"$origin")"
    gh_repo="${gh_repo%.git}"
    [[ -n "$gh_repo" ]] || die "origin is not a GitHub repository ($origin); give -g OWNER/REPO"
fi
[[ "$gh_repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "-g must be OWNER/REPO: $gh_repo"

if [[ -z "$ref" ]]; then
    ref="$(git -C "$repo_dir" rev-parse --verify -q origin/main)" || die "no origin/main here; run git fetch, or give -r"
    git -C "$repo_dir" cat-file -e "$ref:$script_path" 2>/dev/null ||
        die "origin/main does not have $script_path yet: push it first (or give -r)"
    if ! git -C "$repo_dir" diff --quiet "$ref" -- "$script_path"; then
        note "NOTE: your local $script_path differs from origin/main ($ref); the endpoint will run the published version."
    fi
fi
[[ "$ref" =~ ^[A-Za-z0-9._/-]+$ ]] || die "unexpected characters in -r: $ref"
[[ "$ref" =~ ^[0-9a-f]{40}$ ]] || note "NOTE: '$ref' is not a commit, so what the endpoint downloads can change; a commit is safer."

ps_quote() { local v="${1//\'/\'\'}"; printf "'%s'" "$v"; }

url="https://raw.githubusercontent.com/$gh_repo/$ref/$script_path"
cmd="[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('$url')))"

case "$mode" in
    status) cmd+=" -Status" ;;
    remove) cmd+=" -Remove" ;;
    enable)
        args=""
        offered=0
        if [[ "$methods" != winrm ]]; then
            if [[ -n "$pubkey" ]]; then
                [[ -f "$pubkey" ]] || die "SSH public key not found: $pubkey"
                key_line="$(head -n1 "$pubkey" | tr -d '\r')"
                [[ "$key_line" =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]+)\ [A-Za-z0-9+/=]+ ]] ||
                    die "$pubkey is not an SSH public key (give the .pub file, never the private key)"
                args+=" -PublicKey $(ps_quote "$key_line")"
                note "NOTE: this line carries your public key; do not paste it into this repository, a ticket or a chat."
            else
                [[ -n "$gh_user" ]] || gh_user="${gh_repo%%/*}"
                if [[ $check_keys -eq 0 ]]; then
                    :
                elif keys="$(curl -fsS --max-time 15 "https://github.com/$gh_user.keys")"; then
                    [[ -n "$keys" ]] || die "github.com/$gh_user.keys lists no keys; add one on GitHub or use -i"
                    note "SSH will accept the $(wc -l <<<"$keys") key(s) at github.com/$gh_user.keys."
                else
                    note "NOTE: could not check github.com/$gh_user.keys from here."
                fi
                args+=" -GitHubUser $gh_user"
            fi
            offered=1
        fi
        if [[ "$methods" != ssh ]]; then
            if [[ -z "$gist" && -f "$config_dir/winrm-gist" ]]; then gist="$(tr -d ' \r\n' <"$config_dir/winrm-gist")"; fi
            if [[ -z "$gist" ]]; then
                [[ "$methods" == winrm ]] && die "no Gist for the WinRM certificate: give -G or save its ID in $config_dir/winrm-gist (see -h)"
                note "NOTE: no Gist for the WinRM certificate, so WinRM is not offered (see -h)."
            else
                [[ "$gist" =~ ^[0-9a-f]{20,40}$ ]] || die "not a Gist ID: $gist"
                meta="$(curl -fsS --max-time 15 "https://api.github.com/gists/$gist")" || die "cannot read Gist $gist from the GitHub API"
                raw_url="$(python3 -c '
import json, sys
files = json.load(sys.stdin)["files"]
pick = [f for n, f in files.items() if n.lower().endswith((".pem", ".cer", ".crt", ".b64"))] or list(files.values())
print(pick[0]["raw_url"] if len(pick) == 1 else "")' <<<"$meta")"
                [[ "$raw_url" =~ ^https://gist\.githubusercontent\.com/[A-Za-z0-9-]+/$gist/raw/[0-9a-f]{40}/[A-Za-z0-9._-]+$ ]] ||
                    die "Gist $gist must hold exactly one certificate file (.pem)"
                remote_fp="$(curl -fsS --max-time 15 "$raw_url" | openssl x509 -noout -fingerprint -sha1 2>/dev/null)" ||
                    die "Gist $gist does not hold a PEM certificate"
                if [[ -f "$cert" ]]; then
                    local_fp="$(openssl x509 -in "$cert" -noout -fingerprint -sha1 2>/dev/null || openssl x509 -inform der -in "$cert" -noout -fingerprint -sha1)"
                    [[ "$local_fp" == "$remote_fp" ]] || die "the certificate in Gist $gist is not $cert ($remote_fp)"
                else
                    note "NOTE: no local $cert to check the Gist against."
                fi
                note "WinRM will use the certificate in Gist $gist (${remote_fp#*=})."
                args+=" -ClientCertificate $(ps_quote "$raw_url")"
                offered=1
            fi
        fi
        [[ $offered -eq 1 ]] || die "nothing to offer"
        [[ "$methods" == winrm ]] && cmd+=" -WinRM"
        [[ "$methods" == ssh ]] && cmd+=" -Ssh"
        cmd+="$args"
        ;;
esac
if [[ -n "$user" && "$mode" != status ]]; then cmd+=" -UserName $user"; fi

note "Paste this ONE line into an elevated Windows PowerShell on the endpoint (it asks before changing anything):"
note ""
echo "$cmd"
