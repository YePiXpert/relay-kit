#!/usr/bin/env bash
# Install only the Relay Kit menu; forwarding engines are chosen later.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if (( $# != 0 )); then printf '用法：sudo bash install.sh\n' >&2; exit 1; fi
if [[ $EUID != 0 ]]; then printf '请使用 sudo bash install.sh 或 root 运行。\n' >&2; exit 1; fi
command -v curl >/dev/null || { printf '请先安装 curl 和 ca-certificates。\n' >&2; exit 1; }

installer_file=$(mktemp)
trap 'rm -f -- "$installer_file"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 --retry 2 \
    https://raw.githubusercontent.com/YePiXpert/relay-kit/main/forward.sh \
    --output "$installer_file"
bash -n "$installer_file"
grep -Fqx '# relay-kit managed entry' "$installer_file" || {
    printf '下载文件不是 Relay Kit 入口，已停止安装。\n' >&2
    exit 1
}
bash "$installer_file" --install
