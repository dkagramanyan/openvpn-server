#!/bin/bash
# Compare the versions pinned in the Dockerfile with the newest upstream
# releases and open an issue when one is behind. DRY_RUN=1 only prints.
set -euo pipefail

pinned() { sed -n "s/^ARG $1=//p" Dockerfile | head -1; }
# Newest x.y.z release of a GitHub repository (release candidates have other tag names).
newest() {
    gh api "repos/$1/releases?per_page=100" --jq '.[] | select(.draft or .prerelease | not) | .tag_name' \
        | sed 's/^v//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1
}

behind=()
check() {   # check NAME PINNED NEWEST URL
    echo "$1: pinned $2, newest $3"
    [[ -n $3 ]] || { echo "could not find the newest $1 release" >&2; exit 1; }
    [[ $(printf '%s\n%s\n' "$2" "$3" | sort -V | tail -1) == "$2" ]] || behind+=("- **$1** $2 -> $3 ($4)")
}

check OpenVPN "$(pinned OPENVPN_VERSION)" "$(newest OpenVPN/openvpn)" https://github.com/OpenVPN/openvpn/releases
check easy-rsa "$(pinned EASYRSA_VERSION)" "$(newest OpenVPN/easy-rsa)" https://github.com/OpenVPN/easy-rsa/releases
check Alpine "$(pinned ALPINE_VERSION)" \
    "$(curl -fsSL https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/latest-releases.yaml | sed -n 's/^ *version: *//p' | head -1)" \
    https://alpinelinux.org/releases/

(( ${#behind[@]} )) || { echo "Everything is current."; exit 0; }

title="Upstream releases: $(printf '%s\n' "${behind[@]}" | sed 's/^- \*\*\(.*\)\*\* .* -> \([^ ]*\) .*/\1 \2/' | paste -sd, | sed 's/,/, /g')"
body="Newer releases than the ones pinned in \`Dockerfile\` and \`ui/Dockerfile\`:

$(printf '%s\n' "${behind[@]}")

For OpenVPN and easy-rsa, verify the tarball's OpenPGP signature before pinning its SHA-256 (the keys are named at the top of \`Dockerfile\`). A new Alpine minor release also changes \`PYTHON_IMAGE\` in \`ui/Dockerfile\`. Run \`tests/e2e/run.sh\` before releasing."
echo "$title"
if [[ -n ${DRY_RUN:-} ]]; then
    echo "$body"
elif [[ -z $(gh issue list --state open --search "in:title \"$title\"" --json number --jq '.[].number') ]]; then
    gh issue create --title "$title" --body "$body"
fi
