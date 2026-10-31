"""Relay Kit: interactive menus, status screens and guided prompts."""

import functools
import ipaddress
import os
import pathlib
import platform
import re
import secrets
import shutil
import socket
import sys
import unicodedata
import urllib.parse
import urllib.request

from relay import (BLOCKED_PORTS, TABLE, UNITS, VERSION, RelayError, bbr, blocked_port_note, certificate,
                   firewall_backend, forward_drop_note, host, json_text, mirrors, nft_config, port, protocols,
                   realm_config, require_root, run, uninstall, valid_name)
from nodes import (CORE_VERSIONS, PROTOCOLS, SS_METHOD, NodeManager, check_label, domain, next_label,
                   node_link, node_protocols, official_assets, pem, relayed)

COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
INTERACTIVE = sys.stdin.isatty() and sys.stdout.isatty()
WIDTH = max(40, min(58, shutil.get_terminal_size((80, 24)).columns - 2))
ANSI = re.compile(r"\033\[[0-9;]*m")
BACK = object()  # returned by actions the user left without doing anything; no pause needed
ENGINES = {"nft": "nftables", "realm": "Realm"}
CORE_NAMES = {"realm": "Realm", "xray": "Xray", "sing-box": "sing-box", "snell4": "Snell v4",
              "snell5": "Snell v5", "snell6": "Snell v6"}
TRANSPORTS = {"both": "TCP+UDP", "tcp": "TCP", "udp": "UDP"}
STATES = {"active": ("运行中", "32"), "failed": ("已失败", "31"), "activating": ("启动中", "33"),
          "reloading": ("重载中", "33"), "inactive": ("未运行", "33")}
REALITY_TARGETS = ("www.microsoft.com", "www.apple.com", "www.amazon.com", "www.cloudflare.com",
                   "addons.mozilla.org")
SS_METHODS = ("aes-256-gcm", "aes-128-gcm", "chacha20-poly1305")
NODE_GROUPS = (
    ("免域名 · 免证书", (("reality", "推荐 · 抗封锁"), ("reality-xhttp", "XHTTP 传输"),
                     ("vless-encryption", "后量子加密"), ("vmess-ws", "可套 CDN · TLS 可选"),
                     ("ss2022", "轻量 · TCP/UDP"), ("shadowsocks", "兼容旧客户端"),
                     ("socks5", "不加密 · 适合中转"))),
    ("Surge 专属", (("snell4", ""), ("snell5", "支持 UDP"), ("snell6", ""))),
    ("需要域名和证书", (("vless-ws", "可套 CDN"), ("vless-vision", "可回落网站"),
                    ("trojan", "可回落网站"), ("hysteria2", "UDP · 高速"), ("tuic", "UDP · QUIC"),
                    ("anytls", ""), ("naive", "伪装 HTTPS"))),
)
EMPTY_NODES = "暂无节点，请先选择 1) 添加节点。"
EMPTY_RULES = "暂无规则，请先选择 1) 添加规则。"


class Notice(Exception):
    """Something to tell the user that is not a failure, such as an empty list."""


def paint(code, text):
    return f"\033[{code}m{text}\033[0m" if COLOR else str(text)


def red(text):
    return paint("31", text)


def green(text):
    return paint("32", text)


def yellow(text):
    return paint("33", text)


def cyan(text):
    return paint("36", text)


def gray(text):
    return paint("90", text)


def bold(text):
    return paint("1", text)


def width(text):
    return sum(0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in "WF" else 1
               for char in ANSI.sub("", str(text)))


def pad(text, size):
    return f"{text}{' ' * max(0, size - width(text))}"


def line():
    print(gray("─" * WIDTH))


def heading(label):
    left = max(2, (WIDTH - width(label) - 2) // 2)
    print(gray("─" * left) + f" {label} " + gray("─" * max(2, WIDTH - left - width(label) - 2)))


def screen(title, subtitle=None):
    if INTERACTIVE:
        print("\033[H\033[2J", end="")
    print(cyan("═" * WIDTH))
    print(f"  {bold('Relay Kit')} {cyan('v' + VERSION)}  {gray('│')}  {bold(title)}")
    if subtitle:
        print("  " + gray(subtitle))
    print(cyan("═" * WIDTH))


def entry(key, label, hint=""):
    text = f"  {green(key.rjust(2))}) {label}"
    print(pad(text, 26) + gray(hint) if hint else text)


def field(label, value, size=10):
    print(f"  {pad(label, size)}{value}")


def say(icon, text):
    first, *rest = str(text).splitlines() or [""]
    print(f"  {icon} {first}")
    for extra in rest:
        print("    " + extra)


def ok(text):
    say(green("✓"), text)


def fail(text):
    say(red("✗"), text)


def warn(text):
    say(yellow("!"), text)


def note(text):
    say(cyan("▸"), text)


def read(prompt):
    return input(f"  {prompt}").strip()


def pause():
    if INTERACTIVE:
        try:
            input("\n  按回车键返回菜单...")
        except KeyboardInterrupt:
            print()


def choose(keys, prompt="请选择", default=None):
    keys = [str(key) for key in keys]
    numbers = [key for key in keys if key.isdigit()]
    span = "/".join(([f"{numbers[0]}-{numbers[-1]}"] if len(numbers) > 1 else numbers) +
                    [key for key in keys if not key.isdigit()])
    hint = f"，默认 {default}" if default else ""
    while True:
        value = read(f"{prompt} [{span}{hint}]: ").lower()
        if not value and default:
            return default
        if value in keys:
            return value
        fail(f"无效选择，请输入 {span}。")


def ask(prompt, default=None, check=None, keep=False):
    hint = "" if default in (None, "") else f" [回车{'保留' if keep else '使用'} {default}]"
    while True:
        value = read(f"{prompt}{hint}: ") or ("" if default is None else str(default))
        if not value:
            fail("不能为空。")
            continue
        try:
            return check(value) if check else value
        except (RelayError, ValueError, OSError) as error:
            fail(error)


def confirm(prompt, default=False):
    while True:
        value = read(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").lower()
        if not value:
            return default
        if value in ("y", "yes", "n", "no", "0", "q"):
            return value in ("y", "yes")
        fail("请输入 y 或 n。")


def pick(items, row, label, empty, extra=None):
    """Return the chosen item, `extra`'s key, or None for 返回. One item is chosen automatically."""
    if not items:
        raise Notice(empty)
    if len(items) == 1:
        note(f"{label}：{row(items[0])}")
        return items[0]
    print(f"  选择{label}：")
    for index, item in enumerate(items, 1):
        print(f"  {green(str(index).rjust(2))}) {row(item)}")
    keys = [str(index) for index in range(len(items) + 1)]
    if extra:
        print(f"  {green(extra[0].rjust(2))}) {extra[1]}")
        keys.append(extra[0])
    print(f"  {green(' 0')}) 返回")
    choice = choose(keys)
    if choice == "0":
        return None
    return extra[0] if extra and choice == extra[0] else items[int(choice) - 1]


def pick_option(label, options, current=None):
    print(f"  {label}：")
    for index, (_, text) in enumerate(options, 1):
        print(f"  {green(str(index).rjust(2))}) {text}")
    values = [value for value, _ in options]
    default = str(values.index(current) + 1) if current in values else "1"
    return values[int(choose(range(1, len(options) + 1), default=default)) - 1]


def act(action, *args, quiet=False):
    """Run one menu action and keep its result or failure on screen until the user continues."""
    try:
        result = action(*args)
        if result is BACK or quiet:
            return result
    except KeyboardInterrupt:
        print()
        warn("已取消。")
        result = None
    except Notice as notice:
        warn(notice)
        result = None
    except PermissionError as error:
        fail(error if os.geteuid() == 0 else "权限不足：请使用 sudo relay 或 root 运行。")
        result = None
    except (RelayError, ValueError, OSError) as error:
        fail(error)
        result = None
    pause()
    return result


def safely(load):
    try:
        return load(), None
    except PermissionError:
        return None, gray("需要 root 才能查看")
    except (RelayError, ValueError, OSError) as error:
        return None, red(f"✗ 读取失败：{error}")


def service_states(units):
    units = list(units)
    try:
        values = run("systemctl", "is-active", *units, check=False).stdout.split() if units else []
    except OSError:
        values = []
    return {unit: values[index] if index < len(values) else "unknown" for index, unit in enumerate(units)}


def state_parts(state, enabled=True):
    if not enabled:
        return gray("○"), gray("已停用")
    word, code = STATES.get(state, ("状态未知", "90"))
    return paint(code, "●"), paint(code, word)


def state_text(state, enabled=True):
    return " ".join(state_parts(state, enabled))


def sysctl(key):
    try:
        return run("sysctl", "-n", key, check=False).stdout.strip()
    except OSError:
        return ""


def busy_ports():
    """Listening (proto, port) pairs plus the SSH port, which Relay Kit never takes over."""
    try:
        output = run("ss", "-H", "-lntu", check=False).stdout
    except OSError:
        output = ""
    found = set()
    for row in output.splitlines():
        fields = row.split()
        number = fields[4].rpartition(":")[2] if len(fields) > 4 else ""
        if fields and fields[0] in ("tcp", "udp") and number.isdigit():
            found.add((fields[0], int(number)))
    ssh = os.environ.get("SSH_CONNECTION", "").split(" ")[-1]
    return found | {("tcp", int(value)) for value in ("22", ssh) if value.isdigit()}


def random_port(free):
    for _ in range(200):
        number = 10000 + secrets.randbelow(50000)
        if free(number):
            return number
    return None


def allow_port(number, current=None):
    """Return the port, asking first when it is one that Po0-style entries block."""
    if number != current and number in BLOCKED_PORTS:
        warn(blocked_port_note(number))
        if not confirm(f"仍然使用 {number}?"):
            raise RelayError("请换一个端口。")
    return number


def ask_port(label, taken, transports, current=None):
    def free(number):
        return number not in BLOCKED_PORTS and all((proto, number) not in taken for proto in transports)

    def check(value):
        number = port(value)
        busy = [proto.upper() for proto in transports if (proto, number) in taken]
        if number != current and busy:
            raise RelayError(f"端口 {number}（{'/'.join(busy)}）已被占用，请换一个。")
        return allow_port(number, current)

    default = current or random_port(free)
    return ask(label, default=default, keep=current is not None, check=check)


@functools.lru_cache(maxsize=1)
def public_address():
    """The address clients most likely use: a global source address, else what Cloudflare sees."""
    for family, probe in ((socket.AF_INET, "1.1.1.1"), (socket.AF_INET6, "2606:4700:4700::1111")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((probe, 53))
                address = sock.getsockname()[0]
            if ipaddress.ip_address(address).is_global:
                return address
        except (OSError, ValueError):
            pass
    try:
        request = urllib.request.Request("https://one.one.one.one/cdn-cgi/trace",
                                         headers={"User-Agent": "Relay-Kit/" + VERSION})
        with urllib.request.urlopen(request, timeout=5) as response:
            match = re.search(r"^ip=(\S+)$", response.read(4096).decode(errors="replace"), re.M)
        if match and ipaddress.ip_address(match[1]).is_global:
            return match[1]
    except (OSError, ValueError):
        pass
    return None


def unique_name(base, names):
    base = re.sub(r"[^A-Za-z0-9_-]", "-", base)[:28]
    name, index = base, 2
    while name in names:
        name, index = f"{base}-{index}", index + 1
    return name


def new_name(value, names):
    valid_name(value)
    if value in names:
        raise RelayError(f"名称 {value} 已存在。")
    return value


def check_path(value):
    if not re.fullmatch(r"/[A-Za-z0-9._~/-]{0,255}", value):
        raise RelayError("路径需以 / 开头，只含字母、数字和 . _ ~ / -，最长 256 字符。")
    return value


def check_email(value):
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        raise RelayError("请输入合法邮箱。")
    return value


def pem_path(value, private=False):
    if not pathlib.Path(value).is_absolute():
        raise RelayError("请输入绝对路径。")
    pem(value, private)
    return value


def open_menu(manager, target=None):
    """Entry point for `relay`, `relay nft`, `relay realm` and `relay node`."""
    if INTERACTIVE:
        try:
            import readline  # noqa: F401  (arrow keys and history in input())
        except ImportError:
            pass
    try:
        if target is None:
            top_menu(manager)
        elif target == "node":
            node_menu(NodeManager(manager.root))
        else:
            forward_menu(manager, target)
    except EOFError:
        print()


def system_text(root):
    name = platform.system()
    try:
        match = re.search(r'^PRETTY_NAME="?([^"\n]*)"?$', (root / "etc/os-release").read_text(), re.M)
        name = match[1] if match else name
    except OSError:
        pass
    return gray(f"{name} · {platform.release()} · {platform.machine()}")


def forward_text(manager):
    if not manager.state_file.exists():
        return gray("○ 未启用")
    state, problem = safely(manager.load)
    if problem:
        return problem
    total, enabled = len(state["rules"]), sum(rule["enabled"] for rule in state["rules"])
    name = ENGINES[state["engine"]]
    if not enabled:
        return yellow(f"○ {name} · 暂无启用的规则")
    unit = UNITS[state["engine"]]
    stopped = f"（{total - enabled} 条停用）" if enabled < total else ""
    return f"{state_text(service_states([unit])[unit])} · {name} · {enabled} 条规则{stopped}"


def nodes_text(nodes):
    state, problem = safely(nodes.load)
    if problem:
        return problem
    if not state["nodes"]:
        return gray("○ 暂无节点")
    enabled = [node for node in state["nodes"] if node["enabled"]]
    stopped = len(state["nodes"]) - len(enabled)
    if not enabled:
        return gray(f"○ {stopped} 个节点均已停用")
    states = service_states(nodes.unit(node) for node in enabled)
    running = sum(value == "active" for value in states.values())
    color = green if running == len(enabled) else yellow if running else red
    return color(f"● {running}/{len(enabled)} 运行中") + (gray(f" · {stopped} 个已停用") if stopped else "")


def bbr_text():
    control, qdisc = sysctl("net.ipv4.tcp_congestion_control"), sysctl("net.core.default_qdisc")
    if control == "bbr":
        return green(f"● 已启用（{control} + {qdisc}）")
    return gray(f"○ 未启用（当前 {control or '未知'}）")


def top_menu(manager):
    nodes = NodeManager(manager.root)
    while True:
        screen("转发 · 节点 · BBR", "快捷命令 relay · 命令行用法 relay -h")
        for label, value in (("系统", system_text(manager.root)), ("转发", forward_text(manager)),
                             ("节点", nodes_text(nodes)), ("BBR", bbr_text())):
            field(label, value, 6)
        if os.geteuid() != 0:
            warn("当前不是 root：可以浏览，修改配置请使用 sudo relay")
        state, _ = safely(manager.load) if manager.state_file.exists() else (None, None)
        current = state and state["engine"]
        line()
        entry("1", "nftables 转发", green("● 当前引擎") if current == "nft" else "内核转发 · 仅 IPv4 目标")
        entry("2", "Realm 转发", green("● 当前引擎") if current == "realm" else "支持域名 / IPv6 目标")
        entry("3", "节点管理", "搭建 · 分享链接 · 二维码")
        entry("4", "BBR 加速")
        line()
        entry("5", "核心组件", "版本 · 离线导入")
        entry("6", "卸载 Relay Kit")
        entry("0", "退出")
        line()
        try:
            choice = choose("0123456")
        except KeyboardInterrupt:
            print()
            return
        if choice == "0":
            return
        if choice in ("1", "2"):
            forward_menu(manager, "nft" if choice == "1" else "realm")
        elif choice == "3":
            node_menu(nodes)
        elif choice == "4":
            bbr_menu(manager)
        elif choice == "5":
            core_menu(nodes)
        elif act(remove_all, manager) is True:
            return


def forward_menu(manager, engine):
    if act(enter_forward, manager, engine, quiet=True) is not True:
        return
    actions = {"1": add_rule, "2": edit_rule, "3": delete_rule, "4": toggle_rule, "5": forward_status,
               "6": forward_logs, "7": reapply, "8": show_config}
    while True:
        screen(f"{ENGINES[engine]} 转发")
        state, problem = safely(manager.load)
        if problem or state["engine"] != engine:
            print("  " + (problem or gray("转发引擎已被切换。")))
            pause()
            return
        forward_overview(state)
        line()
        entry("1", "添加规则")
        entry("2", "修改规则")
        entry("3", "删除规则")
        entry("4", "启用 / 停用规则")
        line()
        entry("5", "运行状态", "服务状态" + (" · 流量计数" if engine == "nft" else ""))
        entry("6", "查看日志", "最近 50 行")
        entry("7", "重新应用配置")
        entry("8", "查看生成的配置")
        line()
        entry("0", "返回上级")
        line()
        try:
            choice = choose("012345678")
        except KeyboardInterrupt:
            print()
            return
        if choice == "0":
            return
        act(actions[choice], manager)


def enter_forward(manager, engine):
    name = ENGINES[engine]
    if manager.state_file.exists():
        state = manager.load()
        if state["engine"] == engine:
            return True
        screen(f"{name} 转发")
        warn(f"当前转发引擎是 {ENGINES[state['engine']]}，共 {len(state['rules'])} 条规则。")
        note(f"切换到 {name} 会保留全部规则并重新应用，转发会短暂中断。")
        if not confirm(f"切换到 {name}?"):
            return BACK
    else:
        screen(f"{name} 转发")
        note(f"{name} 转发尚未启用：将安装所需依赖并创建 {UNITS[engine]}。")
        if not confirm(f"现在启用 {name} 转发?", default=True):
            return BACK
    require_root()
    with manager.lock():
        manager.init(engine)
    return True


def rule_row(rule, size=12):
    target = f"[{rule['host']}]" if ":" in rule["host"] else rule["host"]
    mark = green("●") if rule["enabled"] else gray("○")
    text = (f"{mark} {pad(rule['name'], size)}  {pad(TRANSPORTS[rule['proto']], 7)}  "
            f"{pad(rule['listen'], 5)} → {target}:{rule['remote']}")
    return text if rule["enabled"] else text + "  " + gray("已停用")


def forward_overview(state):
    unit = UNITS[state["engine"]]
    rules = state["rules"]
    enabled = [rule for rule in rules if rule["enabled"]]
    status = state_text(service_states([unit])[unit]) if enabled else gray("○ 未运行（暂无启用的规则）")
    field("状态", f"{status}  {gray(unit)}", 6)
    hint = forward_drop_note() if state["engine"] == "nft" and enabled and os.geteuid() == 0 else None
    if hint:
        warn(hint)
    if not rules:
        field("规则", gray("暂无规则，选择 1 添加"), 6)
        return
    field("规则", f"{len(rules)} 条" + (f"，{len(rules) - len(enabled)} 条已停用" if len(enabled) < len(rules) else ""), 6)
    size = max(width(rule["name"]) for rule in rules)
    for rule in rules:
        print("    " + rule_row(rule, size))


def pick_rule(state):
    size = max((width(rule["name"]) for rule in state["rules"]), default=8)
    return pick(state["rules"], lambda rule: rule_row(rule, size), "规则", EMPTY_RULES)


def pick_transport(current="both"):
    return pick_option("转发协议", [("both", "TCP + UDP"), ("tcp", "仅 TCP"), ("udp", "仅 UDP")], current)


def rule_ports(manager, state, skip=None):
    taken = busy_ports() | manager.reserved_ports()
    return taken | {(proto, rule["listen"]) for rule in state["rules"] if rule is not skip
                    for proto in protocols(rule)}


def add_rule(manager):
    require_root()
    state = manager.load()
    engine = state["engine"]
    print()
    note(f"添加 {ENGINES[engine]} 转发规则 · 回车使用默认值 · Ctrl+C 取消")
    proto = pick_transport()
    listen = ask_port("入口端口", rule_ports(manager, state), protocols({"proto": proto}))
    target = ask("目标地址" + ("（IPv4）" if engine == "nft" else "（IP 或域名）"),
                 check=lambda value: host(value, engine == "nft"))
    remote = ask("目标端口", default=listen, check=lambda value: allow_port(port(value)))
    names = {rule["name"] for rule in state["rules"]}
    name = ask("规则名称", default=unique_name(f"fwd-{listen}", names), check=lambda value: new_name(value, names))
    with manager.lock():
        manager.change("add", name, proto, listen, target, remote)
    ok(f"规则 {name} 已生效：{TRANSPORTS[proto]} {listen} → {target}:{remote}")
    note(f"客户端把原来的 {target}:{remote} 换成 本机公网IP:{listen}，协议、密码等保持不变。")


def edit_rule(manager):
    require_root()
    state = manager.load()
    rule = pick_rule(state)
    if rule is None:
        return BACK
    note(f"修改规则 {rule['name']} · 回车保留当前值 · Ctrl+C 取消")
    proto = pick_transport(rule["proto"])
    listen = ask_port("入口端口", rule_ports(manager, state, rule), protocols({"proto": proto}),
                      current=rule["listen"])
    target = ask("目标地址", default=rule["host"], keep=True,
                 check=lambda value: host(value, state["engine"] == "nft"))
    remote = ask("目标端口", default=rule["remote"], keep=True,
                 check=lambda value: allow_port(port(value), rule["remote"]))
    with manager.lock():
        manager.change("set", rule["name"], proto, listen, target, remote)
    ok(f"规则 {rule['name']} 已更新：{TRANSPORTS[proto]} {listen} → {target}:{remote}")


def delete_rule(manager):
    require_root()
    rule = pick_rule(manager.load())
    if rule is None or not confirm(f"确认删除规则 {rule['name']}?"):
        return BACK
    with manager.lock():
        manager.change("del", rule["name"])
    ok(f"已删除规则 {rule['name']}。")


def toggle_rule(manager):
    require_root()
    rule = pick_rule(manager.load())
    if rule is None:
        return BACK
    with manager.lock():
        manager.change("disable" if rule["enabled"] else "enable", rule["name"])
    ok(f"已{'停用' if rule['enabled'] else '启用'}规则 {rule['name']}。")


def forward_status(manager):
    state = manager.load()
    print(run("systemctl", "status", "--no-pager", UNITS[state["engine"]], check=False).stdout.rstrip()
          or gray("（无输出）"))
    if state["engine"] == "nft" and os.geteuid() == 0 and shutil.which("nft"):
        heading("nftables 规则与流量计数")
        print(run("nft", "list", "table", "ip", TABLE, check=False).stdout.rstrip() or gray("（规则表未加载）"))


def forward_logs(manager):
    unit = UNITS[manager.load()["engine"]]
    print(run("journalctl", "-u", unit, "-n", "50", "--no-pager", check=False).stdout.rstrip()
          or gray("暂无日志。"))


def reapply(manager):
    require_root()
    with manager.lock():
        manager.commit(manager.load())
    ok("已校验并重新应用全部规则。")


def show_config(manager):
    state = manager.load()
    print(nft_config(state) if state["engine"] == "nft" else json_text(realm_config(state)), end="")


def node_menu(nodes):
    actions = {"1": add_node, "2": view_node, "3": relay_entries, "4": edit_node, "5": delete_node,
               "6": toggle_node, "7": node_status, "8": node_logs}
    while True:
        screen("节点管理")
        state, problem = safely(nodes.load)
        if problem:
            print("  " + problem)
            pause()
            return
        node_overview(nodes, state)
        backend = firewall_backend() if os.geteuid() == 0 else None
        if backend:
            field("防火墙", gray(f"{backend} 已启用 · 节点端口自动放行，删除节点时关闭"), 8)
        line()
        entry("1", "添加节点", f"{len(PROTOCOLS)} 种协议")
        entry("2", "查看节点", "参数 · 分享链接 · 二维码")
        entry("3", "中转入口", "保存 Po0 等入口，生成中转链接")
        entry("4", "修改节点", "端口 · 地址 · 凭据 · SNI")
        entry("5", "删除节点")
        line()
        entry("6", "启用 / 停用节点")
        entry("7", "运行状态")
        entry("8", "查看日志")
        line()
        entry("0", "返回上级")
        line()
        try:
            choice = choose("012345678")
        except KeyboardInterrupt:
            print()
            return
        if choice == "0":
            return
        act(actions[choice], nodes)


def node_row(node, state=None, size=12):
    mark, word = state_parts(state, node["enabled"])
    ports = f"{node['listen']}/{'+'.join(node_protocols(node))}"
    return f"{mark} {pad(node['name'], size)}  {pad(PROTOCOLS[node['kind']][0], 23)}  {pad(ports, 12)}  {word}"


def node_overview(nodes, state):
    if not state["nodes"]:
        print("  " + gray("○ 暂无节点 · 选择 1 添加第一个节点"))
        return
    states = service_states(nodes.unit(node) for node in state["nodes"])
    size = max(width(node["name"]) for node in state["nodes"])
    for node in state["nodes"]:
        print("  " + node_row(node, states[nodes.unit(node)], size))


def pick_node(nodes, state, extra=None):
    states = service_states(nodes.unit(node) for node in state["nodes"])
    size = max((width(node["name"]) for node in state["nodes"]), default=8)
    return pick(state["nodes"], lambda node: node_row(node, states[nodes.unit(node)], size), "节点",
                EMPTY_NODES, extra)


def pick_protocol():
    kinds = []
    for group, members in NODE_GROUPS:
        print("  " + cyan(group))
        for kind, hint in members:
            kinds.append(kind)
            label = pad(PROTOCOLS[kind][0], 25) + gray(hint) if hint else PROTOCOLS[kind][0]
            print(f"  {green(str(len(kinds)).rjust(2))}) {label}")
    print(f"  {green(' 0')}) 返回")
    choice = choose(range(len(kinds) + 1), prompt="选择协议")
    return None if choice == "0" else kinds[int(choice) - 1]


def node_ports(nodes, state, skip=None):
    taken = busy_ports() | nodes.reserved_ports()
    return taken | {(proto, node["listen"]) for node in state["nodes"] if node is not skip
                    for proto in node_protocols(node)}


def ask_certificate(nodes, server):
    live = nodes.root / "etc/letsencrypt/live" / server
    cert, key = live / "fullchain.pem", live / "privkey.pem"
    options = [("live", f"使用已有证书 {live}")] if cert.is_file() and key.is_file() else []
    options += [("acme", "申请 Let's Encrypt 证书（TCP 80 需空闲且公网可达）"),
                ("file", "手动填写证书和私钥路径")]
    source = pick_option("证书", options)
    if source == "live":
        return {"cert": str(cert), "key": str(key)}
    if source == "acme":
        cert, key = certificate(server, ask("证书联系邮箱", check=check_email))
        return {"cert": cert, "key": key}
    return {"cert": ask("证书 PEM 绝对路径", check=pem_path),
            "key": ask("私钥 PEM 绝对路径", check=lambda value: pem_path(value, True))}


def add_node(nodes):
    require_root()
    state = nodes.load()
    screen("添加节点")
    kind = pick_protocol()
    if kind is None:
        return BACK
    display, core, transports, tls = PROTOCOLS[kind]
    line()
    note(f"{display} · 核心 {core} {CORE_VERSIONS[core]} · 回车使用默认值 · Ctrl+C 取消")
    options = {}
    if kind == "vmess-ws":
        tls = options["tls"] = confirm("启用 TLS（需要已解析到本机的域名和证书）?")
    server = None
    if tls:
        server = options["sni"] = ask("域名（已解析到本机）", check=domain)
        options.update(ask_certificate(nodes, server))
    elif kind.startswith("reality"):
        options["sni"] = ask("REALITY 目标网站（支持 TLS 1.3 的 HTTPS 站点）",
                             default=secrets.choice(REALITY_TARGETS), check=domain)
    listen = ask_port("监听端口", node_ports(nodes, state), transports)
    if kind == "naive":
        address = server
    else:
        address = ask("分享地址（客户端连接用的 IP 或域名）", default=server or public_address(), check=host)
    if ":" in address:
        options["bind"] = "::"
    if kind.endswith("-ws") or kind == "reality-xhttp":
        options["path"] = ask("传输路径", default="/" + secrets.token_hex(4), check=check_path)
    if kind == "shadowsocks":
        options["method"] = pick_option("加密方法", [(value, value) for value in SS_METHODS])
    names = {node["name"] for node in state["nodes"]}
    name = ask("节点名称", default=unique_name(f"{kind}-{listen}", names), check=lambda value: new_name(value, names))
    print()
    with nodes.lock():
        node = nodes.add(kind, name, listen, address, options)
    print()
    ok(f"节点 {name} 已创建并启动。")
    show_node(nodes, node, fresh=False)


def node_fields(node):
    opts, keys, kind = node["options"], node["secrets"], node["kind"]
    display, core, transports, tls = PROTOCOLS[kind]
    rows = [("名称", node["name"]), ("协议", display), ("核心", f"{core} {CORE_VERSIONS[core]}"),
            ("地址", node["address"]),
            ("端口", f"{node['listen']}（{'/'.join(proto.upper() for proto in transports)}）")]
    if "bind" in opts:
        rows.append(("监听", opts["bind"]))
    if kind.startswith("snell"):
        rows += [("版本", "v" + kind[-1]), ("PSK", keys["password"])]
        if kind == "snell6":
            rows.append(("模式", opts.get("mode", "default")))
        elif opts.get("obfs") == "http":
            rows.append(("混淆", "http"))
    elif kind in ("ss2022", "shadowsocks"):
        rows += [("加密方法", SS_METHOD if kind == "ss2022" else opts.get("method", "aes-256-gcm")),
                 ("密码", keys["password"])]
    elif kind in ("socks5", "naive"):
        rows += [("用户名", node["name"]), ("密码", keys["password"])]
    elif kind in ("trojan", "hysteria2", "anytls"):
        rows.append(("密码", keys["password"]))
    elif kind == "tuic":
        rows += [("UUID", keys["uuid"]), ("密码", keys["password"]), ("拥塞控制", "bbr")]
    else:
        rows.append(("UUID", keys["uuid"]))
    if kind in ("reality", "vless-vision"):
        rows.append(("流控", "xtls-rprx-vision"))
    if kind == "vless-encryption":
        rows.append(("加密", keys["encryption"][:36] + "…（完整值见链接）"))
    if kind.endswith("-ws") or kind == "reality-xhttp":
        rows.append(("传输", ("WebSocket" if kind.endswith("-ws") else "XHTTP") + " · 路径 " +
                     opts.get("path", "/relay")))
    if kind.startswith("reality"):
        rows += [("SNI", opts["sni"]), ("公钥", keys["public"]), ("Short ID", keys["short_id"]),
                 ("指纹", "chrome")]
    elif tls or opts.get("tls"):
        rows += [("TLS", "开启"), ("SNI", opts.get("sni", "")), ("证书", opts.get("cert", ""))]
    if kind in ("hysteria2", "tuic"):
        rows.append(("ALPN", "h3"))
    if opts.get("fallback"):
        rows.append(("回落", f"127.0.0.1:{opts['fallback']}"))
    for key, label in (("up_mbps", "上行带宽"), ("down_mbps", "下行带宽")):
        if key in opts:
            rows.append((label, f"{opts[key]} Mbps"))
    if opts.get("dns"):
        rows.append(("DNS", opts["dns"]))
    return rows


def show_qr(link, hint=True):
    if len(link) > 1000:
        note("链接较长，二维码难以扫描，请直接复制链接。")
    elif not shutil.which("qrencode"):
        if hint:
            note("安装 qrencode 后可显示二维码：apt install -y qrencode")
    else:
        heading("二维码")
        print(run("qrencode", "-t", "ANSIUTF8" if COLOR else "UTF8", "-m", "1", check=False, text=link).stdout,
              end="")


def show_node(nodes, node, state=None, fresh=True):
    if fresh:
        screen("节点详情")
    if state is None and node["enabled"]:
        state = service_states([nodes.unit(node)])[nodes.unit(node)]
    rows = node_fields(node)
    size = max(width(label) for label, _ in rows) + 4
    for label, value in rows:
        field(label, cyan(value), size)
    field("状态", state_text(state, node["enabled"]), size)
    surge = node["kind"].startswith("snell")
    heading("Surge 配置行" if surge else "分享链接")
    print(node_link(node))
    if not surge:
        show_qr(node_link(node))
    for item in node["options"].get("relays", []):
        show_relay(node, item, hint=False)
    line()
    warn("以上内容包含凭据，请勿公开分享。")


def view_node(nodes):
    state = nodes.load()
    node = pick_node(nodes, state, ("a", "显示全部分享链接"))
    if node is None:
        return BACK
    if node == "a":
        for item in state["nodes"]:
            heading(item["name"])
            print(node_link(item))
        return None
    show_node(nodes, node)


def show_relay(node, item, hint=True):
    link = node_link(relayed(node, item["address"], item["port"]), f"{node['name']}-{item['label']}")
    heading(f"经 {item['label']} 中转 · {item['address']}:{item['port']}")
    print(link)
    if not node["kind"].startswith("snell"):
        show_qr(link, hint)
    transport = {("tcp",): "tcp", ("udp",): "udp"}.get(tuple(node_protocols(node)), "both")
    note(f"{item['label']} 上的转发：{TRANSPORTS[transport]}  入口端口 {item['port']} → "
         f"{node['address']}:{node['listen']}")


def relay_entries(nodes):
    require_root()
    node = pick_node(nodes, nodes.load())
    if node is None:
        return BACK
    relays = node["options"].get("relays", [])
    note("中转入口：客户端经 Po0 等入口连接时用。保存后，节点详情会同时显示每个入口的链接和二维码。")
    if blocked_port_note(node["listen"]):
        warn(f"节点端口 {node['listen']} 在 Po0 上双向封禁，Po0 无法转发到它；请先用 4) 修改节点 换端口。")
    for index, item in enumerate(relays, 1):
        print(f"    {index}. {pad(item['label'], 10)}{item['address']}:{item['port']}")
    action = pick_option("操作", [("add", "添加中转入口")] + ([("del", "删除中转入口")] if relays else []) +
                         [("back", "返回")])
    if action == "back":
        return BACK
    if action == "del":
        item = pick(relays, lambda value: f"{pad(value['label'], 10)}{value['address']}:{value['port']}",
                    "中转入口", "暂无中转入口。")
        if item is None or not confirm(f"删除中转入口 {item['label']}?"):
            return BACK
        with nodes.lock():
            nodes.change("set", node["name"], {"relays": [value for value in relays if value is not item]})
        ok(f"已删除中转入口 {item['label']}。")
        return None
    address = ask("中转入口地址（如 Po0 公网 IP）", check=host)
    number = ask("中转入口端口", default=node["listen"], check=lambda value: allow_port(port(value)))
    relayed(node, address, number)
    kept = [value for value in relays if (value["address"], value["port"]) != (address, number)]

    def fresh_label(value):
        if check_label(value) in {item["label"] for item in kept}:
            raise RelayError(f"名称 {value} 已存在。")
        return value
    item = {"address": address, "port": number, "label": ask("名称", default=next_label(kept), check=fresh_label)}
    with nodes.lock():
        nodes.change("set", node["name"], {"relays": kept + [item]})
    ok(f"已保存中转入口 {item['label']}。")
    show_relay(node, item)
    try:
        ipaddress.IPv4Address(node["address"])
    except ValueError:
        note("nftables 转发的目标要填出口机的 IPv4 地址；Realm 转发可以直接填域名。")


def edit_node(nodes):
    require_root()
    state = nodes.load()
    node = pick_node(nodes, state)
    if node is None:
        return BACK
    kind, opts = node["kind"], node["options"]
    fields = [("listen", "端口", node["listen"]), ("address", "分享地址", node["address"]),
              ("rotate", "重新生成凭据", "UUID / 密码 / 密钥")]
    if kind.startswith("reality"):
        fields.append(("sni", "REALITY 目标网站", opts["sni"]))
    if kind.endswith("-ws") or kind == "reality-xhttp":
        fields.append(("path", "传输路径", opts.get("path", "/relay")))
    if kind == "shadowsocks":
        fields.append(("method", "加密方法", opts.get("method", "aes-256-gcm")))
    print(f"  修改 {node['name']}：")
    size = max(width(label) for _, label, _ in fields) + 4
    for index, (_, label, value) in enumerate(fields, 1):
        print(f"  {green(str(index).rjust(2))}) {pad(label, size)}{gray(value)}")
    print(f"  {green(' 0')}) 返回")
    choice = choose(range(len(fields) + 1))
    if choice == "0":
        return BACK
    key = fields[int(choice) - 1][0]
    if key == "listen":
        value = ask_port("新端口", node_ports(nodes, state, node), node_protocols(node), current=node["listen"])
    elif key == "address":
        value = ask("新分享地址", default=node["address"], keep=True, check=host)
    elif key == "rotate":
        if not confirm("旧的 UUID / 密码 / 密钥会立即失效，确认重新生成?"):
            return BACK
        value = True
    elif key == "sni":
        value = ask("新目标网站", default=opts["sni"], keep=True, check=domain)
    elif key == "path":
        value = ask("新路径", default=opts.get("path", "/relay"), keep=True, check=check_path)
    else:
        value = pick_option("加密方法", [(item, item) for item in SS_METHODS], opts.get("method", "aes-256-gcm"))
    changes = {key: value}
    if key == "address" and ":" in value and ":" not in opts.get("bind", "0.0.0.0"):
        changes["bind"] = "::"
    with nodes.lock():
        nodes.change("set", node["name"], changes)
    updated = next(item for item in nodes.load()["nodes"] if item["name"] == node["name"])
    print()
    ok("已保存并重新应用，客户端请重新导入下面的连接信息。")
    show_node(nodes, updated, fresh=False)


def delete_node(nodes):
    require_root()
    node = pick_node(nodes, nodes.load())
    if node is None or not confirm(f"确认删除节点 {node['name']}（{PROTOCOLS[node['kind']][0]} · 端口 {node['listen']}）?"):
        return BACK
    with nodes.lock():
        nodes.change("del", node["name"])
    ok(f"已删除节点 {node['name']}。")


def toggle_node(nodes):
    require_root()
    node = pick_node(nodes, nodes.load())
    if node is None:
        return BACK
    with nodes.lock():
        nodes.change("disable" if node["enabled"] else "enable", node["name"])
    ok(f"已{'停用' if node['enabled'] else '启用'}节点 {node['name']}。")


def node_status(nodes):
    state = nodes.load()
    node = pick_node(nodes, state, ("a", "全部节点"))
    if node is None:
        return BACK
    for item in state["nodes"] if node == "a" else [node]:
        heading(item["name"])
        print(run("systemctl", "status", "--no-pager", nodes.unit(item), check=False).stdout.rstrip()
              or gray("（无输出）"))


def node_logs(nodes):
    node = pick_node(nodes, nodes.load())
    if node is None:
        return BACK
    print(run("journalctl", "-u", nodes.unit(node), "-n", "50", "--no-pager", check=False).stdout.rstrip()
          or gray("暂无日志。"))


def core_menu(nodes):
    while True:
        screen("核心组件")
        for name, version, installed in nodes.cores():
            mark, state = (green("●"), "已安装") if installed else (gray("○"), gray("未安装 · 用到时自动下载"))
            print(f"  {mark} {pad(CORE_NAMES[name], 11)}{pad(version, 10)}{state}")
        sites = ["直连"] + [urllib.parse.urlsplit(prefix).netloc or prefix for prefix in mirrors()]
        note(f"GitHub 下载顺序：{' → '.join(sites)}；内容都校验固定的 SHA-256。")
        line()
        entry("1", "导入离线包", "上传到服务器的官方压缩包")
        entry("2", "显示下载地址", "在能访问 GitHub 的电脑上下载")
        line()
        entry("0", "返回上级")
        line()
        try:
            choice = choose("012")
        except KeyboardInterrupt:
            print()
            return
        if choice == "0":
            return
        act(import_cores if choice == "1" else show_downloads, nodes)


def existing_file(value):
    if not pathlib.Path(value).is_file():
        raise RelayError(f"找不到文件：{value}")
    return value


def import_cores(nodes):
    require_root()
    names = {asset[3].rsplit("/", 1)[1] for asset in official_assets()}
    found = sorted({str(path) for folder in (pathlib.Path.cwd(), pathlib.Path("/root"), pathlib.Path("/tmp"))
                    if folder.is_dir() for path in folder.iterdir() if path.name in names and path.is_file()})
    if found:
        options = [(path, path) for path in found] + ([("all", "全部导入")] if len(found) > 1 else [])
        choice = pick_option("找到这些官方压缩包", options + [("other", "输入其他路径")])
        paths = found if choice == "all" else [choice]
        if choice == "other":
            paths = [ask("压缩包路径", check=existing_file)]
    else:
        note("当前目录、/root、/tmp 里没有官方压缩包；可以先选 2) 显示下载地址。")
        paths = [ask("压缩包路径", check=existing_file)]
    with nodes.lock():
        for path in paths:
            ok(f"已导入 {nodes.import_archive(path)}，SHA-256 校验通过。")


def show_downloads(nodes):
    machine = platform.machine()
    note(f"本机架构 {machine}。下载后上传到服务器（例如 scp 到 /root），再选 1) 导入离线包。")
    for core, version, arch, url, digest in official_assets():
        if arch == machine:
            heading(f"{CORE_NAMES[core]} {version}")
            print(url)
            print(gray("SHA-256 " + digest))


def bbr_menu(manager):
    while True:
        screen("BBR 加速")
        available = sysctl("net.ipv4.tcp_available_congestion_control")
        field("状态", bbr_text())
        field("内核", platform.release())
        field("拥塞控制", sysctl("net.ipv4.tcp_congestion_control") or "未知")
        field("队列算法", sysctl("net.core.default_qdisc") or "未知")
        field("可用算法", available or "未知")
        if "bbr" not in available.split():
            note("可用算法中没有 bbr，启用时会尝试加载 tcp_bbr 模块。")
        line()
        entry("1", "启用 BBR", "fq + bbr，并保存原设置")
        entry("2", "恢复原设置", "还原启用前的值")
        line()
        entry("0", "返回上级")
        line()
        try:
            choice = choose("012")
        except KeyboardInterrupt:
            print()
            return
        if choice == "0":
            return
        act(switch_bbr, manager, "on" if choice == "1" else "off")


def switch_bbr(manager, action):
    require_root()
    with manager.lock():
        ok(bbr(manager, action))


def remove_all(manager):
    require_root()
    screen("卸载 Relay Kit")
    warn("将停止并删除 Relay Kit 管理的全部内容：")
    for item in ("全部转发规则和 relay-kit-nft / relay-kit-realm 服务", "全部节点和 relay-node-*.service",
                 "配置目录 /etc/relay-kit 与核心目录 /usr/local/lib/relay-kit", "relay 命令"):
        print("    • " + item)
    note("由 Relay Kit 启用的 BBR 会恢复原设置；证书和系统软件包会保留。")
    if read("输入 yes 确认卸载：") != "yes":
        return BACK
    with manager.lock():
        uninstall(manager)
    ok("Relay Kit 已卸载。")
    return True
