#!/usr/bin/env bash
# Make the WinRM client certificate for endpoint triage: the WinRM equivalent of an SSH key pair.
#
#   new-winrm-cert.sh [-u temp-local-admin] [-d DIR] [-n DAYS] [-f]
#
#   -u  the temporary admin it logs in as; must match Set-TriageAccess.ps1 -UserName (default temp-local-admin)
#   -d  where to write it (default ~/.config/endpoint-triage)
#   -n  days it is valid (default 365)
#   -f  overwrite an existing certificate
#
# Writes:
#   winrm-client.key  private key: keep it here, never copy it to an endpoint
#   winrm-client.pem  certificate, used by triage.sh
#   winrm-client.cer  the same certificate (DER), for copying to an endpoint by hand
#
# WinRM cannot reuse your SSH key: Windows only accepts X.509 client certificates with RSA or
# ECDSA keys, and only you can sign a certificate for your own key.
#
# The certificate is for client authentication only, cannot sign other certificates (CA:FALSE),
# and carries the UPN <user>@localhost that Windows uses to map it to the temporary admin.
set -euo pipefail

die() { echo "new-winrm-cert.sh: $*" >&2; exit 2; }
user=temp-local-admin
dir="${XDG_CONFIG_HOME:-$HOME/.config}/endpoint-triage"
days=365
force=0
while getopts ":u:d:n:fh" opt; do
    case "$opt" in
        u) user="$OPTARG" ;;
        d) dir="$OPTARG" ;;
        n) days="$OPTARG" ;;
        f) force=1 ;;
        h) awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
        :) die "option -$OPTARG needs a value" ;;
        *) die "unknown option -$OPTARG (see -h)" ;;
    esac
done
[[ "$user" =~ ^[A-Za-z0-9._-]{1,20}$ ]] || die "user name must be 1-20 of A-Z a-z 0-9 . _ -: $user"
[[ "$days" =~ ^[0-9]+$ ]] || die "days must be a number: $days"
command -v openssl >/dev/null 2>&1 || die "openssl is needed"
# Never inside a git checkout (this repo is public): keep keys and certificates out of every repo.
probe="$dir"
while [[ ! -d "$probe" ]]; do probe="$(dirname "$probe")"; done
if command -v git >/dev/null 2>&1 && git -C "$probe" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    die "$dir is inside a git repository ($(git -C "$probe" rev-parse --show-toplevel)); choose a folder outside any repository"
fi
if [[ -e "$dir/winrm-client.key" && $force -eq 0 ]]; then
    die "$dir/winrm-client.key already exists (use -f to replace it)"
fi

umask 077
mkdir -p "$dir"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/openssl.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $user
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$user@localhost
EOF
openssl req -x509 -newkey rsa:3072 -nodes -days "$days" -config "$tmp/openssl.cnf" \
    -keyout "$dir/winrm-client.key" -out "$dir/winrm-client.pem" 2>/dev/null
openssl x509 -in "$dir/winrm-client.pem" -outform der -out "$dir/winrm-client.cer"
chmod 600 "$dir/winrm-client.key"
chmod 644 "$dir/winrm-client.pem" "$dir/winrm-client.cer"

thumb="$(openssl x509 -in "$dir/winrm-client.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)"
echo "Client certificate for $user@localhost, valid $days days, thumbprint $thumb"
echo "  keep:              $dir/winrm-client.key, $dir/winrm-client.pem"
echo "  copy to endpoint:  $dir/winrm-client.cer"
