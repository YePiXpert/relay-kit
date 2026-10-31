#!/usr/bin/env bash
# Run with: sudo unshare --mount bash tests/test-install.sh
set -Eeuo pipefail
[[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]] || {
    printf 'Run with sudo unshare --mount bash tests/test-install.sh\n' >&2
    exit 1
}
mount --make-rprivate /
mount -t tmpfs tmpfs /usr/local/bin
mount -t tmpfs tmpfs /usr/local/lib
bash forward.sh --install
[[ $(/usr/local/bin/relay --version) == 'Relay Kit 0.3.1' ]]
[[ $(stat -c '%a' /usr/local/bin/relay) == 755 ]]
[[ $(stat -c '%a' /usr/local/lib/relay-kit/relay.py) == 644 ]]
[[ $(stat -c '%a' /usr/local/lib/relay-kit/menu.py) == 644 ]]
bash forward.sh --install
printf 'unrelated application\n' > /usr/local/bin/relay
if bash forward.sh --install; then
    printf 'Unexpectedly overwrote an unrelated executable\n' >&2
    exit 1
fi
[[ $(cat /usr/local/bin/relay) == 'unrelated application' ]]
rm /usr/local/bin/relay
ln -s /usr/bin/true /usr/local/bin/relay
if bash forward.sh --install; then
    printf 'Unexpectedly overwrote a symlink\n' >&2
    exit 1
fi
[[ $(readlink /usr/local/bin/relay) == /usr/bin/true ]]
printf 'PASS install, update, permissions and unrelated-file protection\n'
