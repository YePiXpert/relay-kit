#!/usr/bin/env bash
# Install our own manager from a fixed release; engines are selected in the menu.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if (( $# != 0 )); then printf '用法：sudo bash install.sh\n' >&2; exit 1; fi
if [[ $EUID != 0 ]]; then printf '请使用 sudo bash install.sh 或 root 运行。\n' >&2; exit 1; fi
command -v apt-get >/dev/null || { printf '支持 Debian 11+/Ubuntu 22.04+。\n' >&2; exit 1; }
missing=()
for package in python3 curl ca-certificates; do
    [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) == 'install ok installed' ]] || missing+=("$package")
done
if (( ${#missing[@]} )); then
    apt-get update
    apt-get install -y "${missing[@]}"
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
base=https://raw.githubusercontent.com/YePiXpert/relay-kit/v0.2.0
for file in forward.sh relay.py nodes.py; do
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 180 --retry 2 "$base/$file" --output "$work/$file"
done
(
    cd "$work"
    sha256sum --check <<'SUMS'
cc357f101e4823914620fcc00748870e5b35622a5ee00e0c5b4614ad74c6185e  forward.sh
e6fb821b93f052e8ab8ed4cd080a691ddb900066a8e7e2153d42c87bc9020f70  relay.py
ef1f7e497d7dc7605aaaca48614a733650bdd3b98f7194ffd4dc895fb7db4f3d  nodes.py
SUMS
)
bash -n "$work/forward.sh"
bash "$work/forward.sh" --install
