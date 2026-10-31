#!/usr/bin/env bash
# All addresses, routes, firewall rules, hosts entries and sysctls are isolated.
# Run: sudo unshare --mount --net --pid --fork bash tests/run-network.sh
set -Eeuo pipefail
[[ $(readlink /proc/self/ns/net) != "$(readlink /proc/1/ns/net)" ]] || {
    printf 'Use unshare --mount --net --pid --fork\n' >&2
    exit 1
}
mount --make-rprivate /
mount -t proc proc /proc
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
task_temp=$(mktemp -d)
trap 'rm -rf -- "$task_temp"' EXIT
cat /etc/hosts > "$task_temp/hosts"
printf '\n11.0.0.2 target.example\n' >> "$task_temp/hosts"
mount --bind "$task_temp/hosts" /etc/hosts
ip link set lo up
ip netns add relay-client
ip netns add relay-backend
ip link add in0 type veth peer name client0
ip link set client0 netns relay-client
ip addr add 198.18.0.1/24 dev in0
ip link set in0 up
ip -n relay-client addr add 198.18.0.2/24 dev client0
ip -n relay-client link set lo up
ip -n relay-client link set client0 up
ip -n relay-client route add default via 198.18.0.1
ip link add out0 type veth peer name backend0
ip link set backend0 netns relay-backend
ip addr add 11.0.0.1/24 dev out0
ip link set out0 up
ip -n relay-backend addr add 11.0.0.2/24 dev backend0
ip -n relay-backend link set lo up
ip -n relay-backend link set backend0 up
# Backend has no default route; nft forwarding requires correct source NAT.
if [[ -x .test-tools/root/usr/sbin/nft ]]; then
    project_dir=$(pwd)
    export PATH="$project_dir/.test-tools/root/usr/sbin:$PATH"
    export LD_LIBRARY_PATH="$project_dir/.test-tools/root/usr/lib/x86_64-linux-gnu"
fi
python3 tests/integration.py
