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
base=https://raw.githubusercontent.com/YePiXpert/relay-kit/v0.3.1
# Mirror prefixes are tried only after GitHub fails; the SHA-256 check below decides what is installed.
prefixes=${RELAY_KIT_MIRRORS-https://ghfast.top/ https://gh-proxy.com/}
read -r -a mirrors <<< "${prefixes//,/ }"
for file in forward.sh relay.py nodes.py menu.py; do
    for prefix in '' "${mirrors[@]}"; do
        [[ -z $prefix ]] || printf '改用镜像 %s 下载 %s，内容同样校验 SHA-256。\n' "$prefix" "$file" >&2
        if curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
                --connect-timeout 15 --max-time 180 --retry 1 "$prefix$base/$file" --output "$work/$file"; then
            continue 2
        fi
    done
    printf '无法下载 %s；可下载完整仓库后执行 sudo bash forward.sh --install。\n' "$file" >&2
    exit 1
done
(
    cd "$work"
    sha256sum --check <<'SUMS'
cc357f101e4823914620fcc00748870e5b35622a5ee00e0c5b4614ad74c6185e  forward.sh
effc629780018875321d5641555e1c91be0f7df9c79063c2f7d292a4c06063c4  relay.py
d8ff7ced6c22e66ef074ed5321a9f0db931e9acdef2a8ac51c598b28cd2d7f51  nodes.py
7126582bbffcfb7aa5f48e5eb2bcf3d917ba26dc532d7ae29ec4ccb954ad08a2  menu.py
SUMS
)
bash -n "$work/forward.sh"
bash "$work/forward.sh" --install
