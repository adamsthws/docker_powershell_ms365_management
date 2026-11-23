#!/usr/bin/env bash
# Scan this repository for secrets (API keys, tokens, private keys, passwords) with gitleaks.
# Runs gitleaks from its Docker image, pinned to one version, so nothing needs installing.
#
#   scan-secrets.sh            the full git history (every commit on every branch)
#   scan-secrets.sh staged     only what is staged for the next commit (used by the pre-commit hook)
#   scan-secrets.sh dir        the working tree as it is now, including uncommitted files
#
# Findings are printed with the secret redacted. Exit code 1 means something was found.
# Certificate and key files (.pem, .cer, .key, .pfx, ...) are refused by name as well.
# Rules and allowlist: .gitleaks.toml at the repo root. A false positive can be silenced for one
# line with a trailing "gitleaks:allow" comment; anything real must be removed AND revoked.
set -euo pipefail

image="zricethezav/gitleaks:v8.21.2"
mode="${1:-history}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "scan-secrets.sh: docker is needed to run gitleaks ($image)." >&2
    exit 2
fi

case "$mode" in
    history) args=(git /repo) ;;
    staged) args=(git --pre-commit --staged /repo) ;;
    dir) args=(dir /repo) ;;
    -h | --help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "scan-secrets.sh: unknown mode '$mode' (history, staged or dir)" >&2; exit 2 ;;
esac

# Certificate and key files, by name. gitleaks does not look inside binary files (a DER .cer, a
# .pfx) in its git modes, so they are caught here whatever their content.
key_files_rx='\.(pem|cer|crt|der|key|pfx|p12|p8|jks|ppk)$|(^|/)id_(rsa|ecdsa|ed25519)$'
case "$mode" in
    history) names="$(git -C "$repo_dir" log --all --name-only --format= | sort -u)" ;;
    staged) names="$(git -C "$repo_dir" diff --cached --name-only --diff-filter=ACMR)" ;;
    dir) names="$(git -C "$repo_dir" ls-files --cached --others --exclude-standard)" ;;
esac
status=0
bad="$(grep -iE "$key_files_rx" <<<"$names" || true)"
if [[ -n "$bad" ]]; then
    echo "scan-secrets.sh: certificate or key files must not be in this repository:" >&2
    sed 's/^/  /' <<<"$bad" >&2
    status=1
fi

# In a git worktree, .git is a file pointing into the main repository's .git: mount that too, at
# the same path. safe.directory through the environment: the repo is owned by the host user, not
# the container's, and this avoids touching anyone's git config.
mounts=(-v "$repo_dir:/repo:ro")
common="$(git -C "$repo_dir" rev-parse --path-format=absolute --git-common-dir)"
[[ "$common" == "$repo_dir/.git" ]] || mounts+=(-v "$common:$common:ro")
docker run --rm \
    "${mounts[@]}" \
    -u "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    "$image" "${args[@]}" --config /repo/.gitleaks.toml --redact --no-banner --verbose || status=$?
exit "$status"
