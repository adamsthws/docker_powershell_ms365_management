#!/usr/bin/env bash
# Run the endpoint triage checks on a Windows machine over WinRM or SSH and copy the results back.
#
# Set up access on the endpoint first with ps/setup/Set-TriageAccess.ps1, and forward a local port
# to it with the remote-support tool (e.g. RustDesk: local 2222 -> 127.0.0.1:22 for SSH, or
# local 5986 -> 127.0.0.1:5986 for WinRM). See README.md.
#
#   triage.sh [-t auto|winrm|ssh] [-p PORT] [-H 127.0.0.1] [-F THUMBPRINT] [-o OUTDIR] [-- runner args]
#
#   -t  transport; auto (default) probes the port: an SSH banner means SSH, a silent port means WinRM
#   -p  local tunnel port; default: try 2222 then 5986 (auto), 5986 (winrm), 2222 (ssh)
#   -F  WinRM: expected server certificate thumbprint, as printed by Set-TriageAccess.ps1
#   -c, -k  WinRM client certificate and key (default ~/.config/endpoint-triage/winrm-client.pem/.key,
#           made by new-winrm-cert.sh)
#   -u, -i  SSH user (default temp-local-admin) and private key (default ~/.ssh/id_ed25519)
#
# Runner args go to Invoke-EndpointTriage.ps1, for example:
#   triage.sh -- -From "2026-01-15 14:00" -To "2026-01-15 16:30" -Expected "Splashtop,Syncro" -CollectAnyDesk
#   triage.sh -- -Check 11 -Time "2026-01-15 14:22:05"
#
# What it changes on the endpoint: it copies the scripts to C:\ProgramData\endpoint-triage\ps and the
# results are written under C:\ProgramData\endpoint-triage\out\. The checks themselves only read.
# Set-TriageAccess.ps1 -Remove deletes that folder at the end.
set -euo pipefail

usage() {
    awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"
    exit "${1:-0}"
}
die() { echo "triage.sh: $*" >&2; exit 2; }

config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/endpoint-triage"
transport=auto
host=127.0.0.1
port=""
user=temp-local-admin
ssh_key="$HOME/.ssh/id_ed25519"
cert="$config_dir/winrm-client.pem"
cert_key="$config_dir/winrm-client.key"
thumb=""
outdir=""
while getopts ":t:u:p:H:i:c:k:F:o:h" opt; do
    case "$opt" in
        t) transport="$OPTARG" ;;
        u) user="$OPTARG" ;;
        p) port="$OPTARG" ;;
        H) host="$OPTARG" ;;
        i) ssh_key="$OPTARG" ;;
        c) cert="$OPTARG" ;;
        k) cert_key="$OPTARG" ;;
        F) thumb="$OPTARG" ;;
        o) outdir="$OPTARG" ;;
        h) usage 0 ;;
        :) die "option -$OPTARG needs a value" ;;
        *) die "unknown option -$OPTARG (see -h)" ;;
    esac
done
shift $((OPTIND - 1))
[[ "${1:-}" == "--" ]] && shift
runner_args=("$@")

[[ "$transport" =~ ^(auto|winrm|ssh)$ ]] || die "transport must be auto, winrm or ssh: $transport"
[[ -z "$port" || "$port" =~ ^[0-9]+$ ]] || die "port must be a number: $port"
[[ "$user" =~ ^[A-Za-z0-9._@\\-]+$ ]] || die "user name has unexpected characters: $user"
[[ -z "$thumb" || "$thumb" =~ ^[0-9A-Fa-f:\ ]{40,59}$ ]] || die "thumbprint should be 40 hex characters: $thumb"
for a in "${runner_args[@]}"; do
    [[ "$a" != *'"'* && "$a" != *'%'* ]] || die "runner arguments may not contain \" or %: $a"
done
if [[ "$transport" == winrm ]]; then
    [[ -f "$cert" && -f "$cert_key" ]] || die "WinRM client certificate not found ($cert, $cert_key): make one with scripts/new-winrm-cert.sh"
elif [[ "$transport" == ssh ]]; then
    [[ -f "$ssh_key" ]] || die "private key not found: $ssh_key"
fi

triage_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$triage_dir/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# What answers on a port: SSH sends a banner straight away; WinRM over HTTPS waits for the client.
# A remote-support tunnel whose far end is down accepts and then closes at once ("none").
probe() {
    local out rc
    out="$(timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1" || exit 9; head -c 4 <&3' "$host" "$1" 2>/dev/null)" && rc=0 || rc=$?
    if [[ "$out" == SSH-* ]]; then echo ssh
    elif [[ $rc -eq 124 ]]; then echo winrm
    else echo none; fi
}

if [[ "$transport" == auto ]]; then
    for p in ${port:-2222 5986}; do
        found="$(probe "$p")"
        if [[ "$found" != none ]]; then transport="$found"; port="$p"; break; fi
    done
    [[ "$transport" != auto ]] || die "nothing answering on $host port ${port:-2222 or 5986} (is the tunnel up, and access enabled with Set-TriageAccess.ps1?)"
    echo "Found $transport on $host:$port"
    if [[ "$transport" == winrm && ! ( -f "$cert" && -f "$cert_key" ) ]]; then
        die "WinRM client certificate not found ($cert, $cert_key): make one with scripts/new-winrm-cert.sh"
    fi
    if [[ "$transport" == ssh && ! -f "$ssh_key" ]]; then die "private key not found: $ssh_key"; fi
fi
if [[ -z "$port" ]]; then
    if [[ "$transport" == winrm ]]; then port=5986; else port=2222; fi
fi

remote_root='C:\ProgramData\endpoint-triage'
stamp="$(date +%Y%m%d-%H%M%S)"
remote_out="$remote_root\\out\\$stamp"
# PowerShell that runs the runner from its text, not as a script file, so an execution policy (even one
# set by Group Policy) does not stop it. The runner loads the checks the same way.
runner_code() {
    local code="\$env:ENDPOINT_TRIAGE_ROOT = '$remote_root\\ps'; & ([scriptblock]::Create([IO.File]::ReadAllText('$remote_root\\ps\\Invoke-EndpointTriage.ps1'))) -OutputDirectory '$remote_out'"
    local a
    for a in "${runner_args[@]}"; do
        if [[ "$a" =~ ^-[A-Za-z]+$ ]]; then code+=" $a"; else code+=" '${a//\'/\'\'}'"; fi
    done
    printf '%s' "$code"
}

if [[ "$transport" == ssh ]]; then
    # A config file, not command-line options: ssh refuses a backslash (DOMAIN\user) in -l or user@host,
    # but accepts it from a config file. A fresh known_hosts per run, because every tunnelled endpoint
    # appears as 127.0.0.1:<port> and their host keys would otherwise clash.
    cat >"$tmp/ssh_config" <<EOF
Host triage
  HostName $host
  Port $port
  User $user
  IdentityFile $ssh_key
  IdentitiesOnly yes
  BatchMode yes
  ConnectTimeout 15
  ServerAliveInterval 30
  StrictHostKeyChecking accept-new
  UserKnownHostsFile $tmp/known_hosts
EOF
    ssh_t() { ssh -F "$tmp/ssh_config" triage "$@"; }
    scp_t() { scp -q -F "$tmp/ssh_config" "$@"; }
    echo "Connecting over SSH to $host:$port as $user ..."
    remote_host="$(ssh_t hostname | tr -d '\r\n')" || die "could not connect (is the key in administrators_authorized_keys?)"
    identity="ssh $user@$host:$port"
    remote_push() {
        ssh_t "if exist $remote_root\\ps rmdir /s /q $remote_root\\ps" >/dev/null
        ssh_t "if not exist $remote_root\\out mkdir $remote_root\\out" >/dev/null
        scp_t -r "$triage_dir/ps" "triage:C:/ProgramData/endpoint-triage/"
    }
    remote_run() {
        # cmd.exe runs this: PowerShell code in double quotes, its strings in single quotes.
        local ps
        ps="$(runner_code)" || return 1
        [[ "$ps" != *'"'* ]] || die "runner arguments cannot contain double quotes over SSH"
        ssh_t "powershell -NoProfile -NonInteractive -Command \"$ps\""
    }
    remote_pull() { scp_t -r "triage:C:/ProgramData/endpoint-triage/out/$stamp" "$outdir/"; }
    remote_identity() { echo "endpoint host key:"; ssh-keygen -lf "$tmp/known_hosts" 2>/dev/null || true; }
else
    venv="$repo_dir/.scratch_area/venv-winrm"
    if [[ ! -x "$venv/bin/python" ]] || ! "$venv/bin/python" -c 'import pypsrp' 2>/dev/null; then
        echo "Setting up the WinRM client (Python venv with pypsrp, first run only) ..."
        python3 -m venv "$venv"
        "$venv/bin/pip" install -q pypsrp
    fi
    w() {
        local extra=()
        [[ -n "$thumb" ]] && extra=(--thumbprint "$thumb")
        "$venv/bin/python" -I "$triage_dir/scripts/winrm_client.py" --host "$host" --port "$port" \
            --cert "$cert" --key "$cert_key" "${extra[@]}" "$@"
    }
    echo "Connecting over WinRM to $host:$port with $cert ..."
    info="$(w info 2>&1)" || { echo "$info" >&2; die "could not connect over WinRM"; }
    echo "$info"
    remote_host="$(sed -n 's/^computer: //p' <<<"$info" | tr -d '\r')"
    server_thumb="$(sed -n 's/^server certificate thumbprint: //p' <<<"$info")"
    grep -q '^elevated: True' <<<"$info" || echo "WARNING: the WinRM session is not elevated (LocalAccountTokenFilterPolicy?); results will be thin." >&2
    if [[ -z "$thumb" ]]; then echo "Server certificate thumbprint $server_thumb was not checked (pass -F to check it)."; fi
    identity="winrm $host:$port, client certificate $cert"
    remote_push() { w push "$triage_dir/ps" "$remote_root\\ps"; }
    remote_run() {
        w run "$(runner_code)"
    }
    remote_pull() { w pull "$remote_out" "$outdir/$stamp"; }
    remote_identity() { echo "endpoint server certificate thumbprint: $server_thumb${thumb:+ (checked)}"; }
fi

[[ "$remote_host" =~ ^[A-Za-z0-9._-]+$ ]] || die "unexpected computer name from the endpoint: $remote_host"
outdir="${outdir:-$repo_dir/.scratch_area/endpoint-cases/$(date +%Y%m%d)-$remote_host}"

echo
echo "Endpoint:  $remote_host ($transport)"
echo "This will: copy the triage scripts to $remote_root\\ps on the endpoint,"
echo "           run the read-only checks (writing results to $remote_out),"
echo "           and copy the results to $outdir/$stamp"
echo "Runner:    ${runner_args[*]:-(no arguments: all checks except the time-window ones)}"
read -r -p "Proceed? [y/N] " answer
[[ "$answer" =~ ^[Yy]$ ]] || { echo "Nothing done."; exit 1; }

mkdir -p "$outdir"
remote_push || die "could not copy the scripts to the endpoint"
remote_run || echo "WARNING: the runner reported errors (above); copying whatever it wrote." >&2
remote_pull || die "could not copy the results back (did the runner write any?)"
{
    echo "endpoint: $remote_host"
    echo "connected: $identity"
    echo "run: $stamp (local time on this machine: $(date '+%Y-%m-%d %H:%M:%S %Z'))"
    echo "runner args: ${runner_args[*]:-}"
    remote_identity
} >"$outdir/$stamp/run-info.txt"

echo
echo "Results: $outdir/$stamp"
echo "When finished on this endpoint, remove the access there (elevated, at the console, not over this session): Set-TriageAccess.ps1 -Remove"
