#!/usr/bin/env bash
# relay-kit managed entry
# Unified entry point for two upstream forwarding managers on Debian/Ubuntu.
# Engines are installed only after selecting their install action.
set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

VERSION=0.1.0
NFT_SOURCE=https://raw.githubusercontent.com/arloor/nftables-nat-rust/master/setup.sh
REALM_SOURCE=https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh
WORK=

cleanup() { [[ -z $WORK ]] || rm -f -- "$WORK"; }
trap cleanup EXIT

root_only() {
    if [[ $EUID != 0 ]]; then printf '此操作需要 root，请用 sudo relay 或 sudo bash forward.sh 运行。\n' >&2; return 1; fi
}

install_self() {
    root_only || return 1
    local source target=/usr/local/bin/relay
    source=$(readlink -f -- "${BASH_SOURCE[0]}") || return 1
    if [[ -e $target || -L $target ]]; then
        if [[ -L $target ]] || ! grep -Fqx '# relay-kit managed entry' "$target"; then
            printf '%s 已被其他程序占用，请保留原文件并手动处理。\n' "$target" >&2
            return 1
        fi
    fi
    install -d -m 755 /usr/local/bin || return 1
    cleanup
    WORK=$(mktemp /usr/local/bin/.relay.XXXXXX) || return 1
    install -m 755 "$source" "$WORK" || return 1
    mv -f -- "$WORK" "$target" || return 1
    WORK=
    printf 'Relay Kit %s 已安装。运行 sudo relay 打开菜单。\n' "$VERSION"
}

prepare_install() {
    root_only || return 1
    [[ -d /run/systemd/system ]] || { printf '需要 systemd 系统。\n' >&2; return 1; }
    command -v apt-get >/dev/null || { printf '此入口的安装功能面向 Debian/Ubuntu。\n' >&2; return 1; }
    local package
    local -a missing=()
    for package in curl ca-certificates "$@"; do
        [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) == 'install ok installed' ]] || missing+=("$package")
    done
    if (( ${#missing[@]} )); then
        apt-get update || return 1
        apt-get install -y "${missing[@]}" || return 1
    fi
}

download_script() {
    cleanup
    WORK=$(mktemp) || return 1
    printf '下载上游脚本：%s\n' "$1"
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 180 --retry 2 --output "$WORK" "$1" || return 1
    bash -n "$WORK" || return 1
}

install_nft() {
    # Upstream downloads a single `nat` asset, without architecture detection.
    [[ $(uname -m) == x86_64 ]] || { printf '该上游安装路径仅接入 x86_64；其他架构请查看项目发布说明。\n' >&2; return 1; }
    prepare_install nftables || return 1
    download_script "$NFT_SOURCE" || return 1
    # Preserve setup logic but download the release directly from GitHub.
    sed -i 's#https://us.arloor.dev/https://github.com/#https://github.com/#g' "$WORK" || return 1
    bash -e "$WORK" toml || return 1
    printf '\n已运行上游安装程序。转发规则写在 /etc/nat.toml。\n'
}

edit_nft() {
    root_only || return 1
    [[ -f /etc/nat.toml ]] || { printf '请先安装 nftables 管理器。\n'; return 1; }
    local editor
    for editor in nano vi; do
        if command -v "$editor" >/dev/null; then
            "$editor" /etc/nat.toml || return 1
            printf '配置由上游程序自动检测；通常在 60 秒内生效，请查看服务日志确认。\n'
            return 0
        fi
    done
    printf '未找到 nano/vi；请自行编辑 /etc/nat.toml。\n' >&2
    return 1
}

nft_menu() {
    local choice
    while true; do
        printf '\nNFTABLES — arloor/nftables-nat-rust\n'
        printf '1) 安装/更新（上游可能调整系统 FORWARD 策略）\n2) 编辑规则\n3) 查看状态\n4) 查看日志\n0) 返回\n'
        read -r -p '请选择：' choice || return 0
        case $choice in
            1) install_nft || printf '安装未完成，请查看上方错误。\n' >&2 ;;
            2) edit_nft || true ;;
            3) systemctl --no-pager --full status nat || true ;;
            4) root_only && journalctl -u nat -n 50 --no-pager ;;
            0) return 0 ;;
            *) printf '无效选项。\n' ;;
        esac
    done
}

realm_menu() {
    local choice
    while true; do
        printf '\nREALM — zywe03/realm-xwPF\n1) 安装/更新管理脚本\n2) 打开上游规则管理菜单\n3) 查看状态\n4) 查看日志\n0) 返回\n'
        read -r -p '请选择：' choice || return 0
        case $choice in
            1)
                if prepare_install && download_script "$REALM_SOURCE"; then
                    bash "$WORK" install || printf '安装未完成，请查看上方错误。\n' >&2
                fi ;;
            2)
                if root_only; then
                    if [[ -f /usr/local/bin/xwPF.sh ]]; then
                        bash /usr/local/bin/xwPF.sh
                    else
                        printf '请先选择 1 安装。\n'
                    fi
                fi ;;
            3) systemctl --no-pager --full status realm || true ;;
            4) root_only && journalctl -u realm -n 50 --no-pager ;;
            0) return 0 ;;
            *) printf '无效选项。\n' ;;
        esac
    done
}

main() {
    if (( $# > 1 )); then printf '参数过多；使用 --help 查看用法。\n' >&2; return 1; fi
    case ${1:-} in
        --help|-h)
            printf 'Relay Kit %s\n用法：sudo bash forward.sh [nft|realm|--install]\n' "$VERSION"
            printf '  --install  安装为 /usr/local/bin/relay（不安装转发引擎）\n  --version  查看版本\n'
            printf '安装后：sudo relay，或 sudo relay nft / sudo relay realm。\n'
            return 0 ;;
        --version) printf 'Relay Kit %s\n' "$VERSION"; return 0 ;;
        --install) install_self; return $? ;;
        nft) nft_menu; return $? ;;
        realm) realm_menu; return $? ;;
        '') ;;
        *) printf '不支持该参数；使用 --help 查看用法。\n' >&2; return 1 ;;
    esac
    local choice
    while true; do
        printf '\nRelay Kit %s — 请选择转发方式\n1) nftables（arloor）\n2) Realm（realm-xwPF）\n0) 退出\n' "$VERSION"
        read -r -p '请选择：' choice || return 0
        case $choice in
            1) nft_menu ;;
            2) realm_menu ;;
            0) return 0 ;;
            *) printf '无效选项。\n' ;;
        esac
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
