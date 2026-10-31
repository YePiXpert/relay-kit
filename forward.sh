#!/usr/bin/env bash
# relay-kit managed entry
# Original Relay Kit launcher; all configuration logic lives in relay.py.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

command -v python3 >/dev/null || { printf '请先安装 python3。\n' >&2; exit 1; }
source_file=$(readlink -f -- "${BASH_SOURCE[0]}")
if [[ $source_file == /usr/local/bin/relay ]]; then
    core=/usr/local/lib/relay-kit/relay.py
else
    core=$(dirname -- "$source_file")/relay.py
fi
[[ -f $core ]] || { printf '缺少 relay.py，请使用完整安装包或 install.sh。\n' >&2; exit 1; }
if [[ ${1:-} == --install ]]; then
    shift
    exec python3 -I "$core" install --launcher "$source_file" "$@"
fi
exec python3 -I "$core" "$@"
