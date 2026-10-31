#!/usr/bin/env python3
"""Relay Kit: original forwarding configuration and service management."""

import argparse
import contextlib
import copy
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.parse

VERSION = "0.2.0"
MARKER = "# relay-kit managed entry"
REALM_VERSION = "2.9.6"
REALM_ASSETS = {
    "x86_64": ("x86_64", "b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65"),
    "aarch64": ("aarch64", "f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488"),
}
TABLE = "relay_kit"
UNITS = {"nft": "relay-kit-nft.service", "realm": "relay-kit-realm.service"}


class RelayError(Exception):
    pass


def run(*args, check=True, text=None):
    result = subprocess.run([str(a) for a in args], input=text, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        detail = (result.stderr.strip() + "\n" + result.stdout.strip()).strip()
        raise RelayError(f"命令失败：{' '.join(map(str, args))}\n{detail}")
    return result


def atomic_write(path, data, mode=0o600):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".relay-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data.encode() if isinstance(data, str) else data)
            file.flush()
            os.fsync(file.fileno())
            os.fchmod(file.fileno(), mode)
        os.replace(name, path)
    finally:
        pathlib.Path(name).unlink(missing_ok=True)


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def valid_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}", value):
        raise RelayError("名称需为 1–32 位字母、数字、短横线或下划线。")
    return value


def port(value):
    if not re.fullmatch(r"[1-9][0-9]{0,4}", str(value)) or int(value) > 65535:
        raise RelayError("端口需为 1–65535 的整数。")
    return int(value)


def host(value, ipv4=False):
    if not isinstance(value, str):
        raise RelayError("地址需为字符串。")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        labels = value.split(".")
        if (ipv4 or len(value) > 253 or len(labels) < 2 or
                re.fullmatch(r"[0-9.]+", value) or
                any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in labels)):
            raise RelayError("nftables 目标需为 IPv4；Realm 目标可用 IP 或合法域名。") from None
    else:
        if (address.is_unspecified or address.is_multicast or address.is_loopback or
                address.is_link_local or (ipv4 and address.version != 4)):
            raise RelayError("目标地址不能是未指定、组播、回环或链路本地地址；nftables 只支持 IPv4。")
    return value


def validate_state(state):
    if (not isinstance(state, dict) or not isinstance(state.get("engine"), str) or
            state["engine"] not in UNITS or not isinstance(state.get("rules"), list)):
        raise RelayError("转发配置格式错误。")
    names, listeners = set(), set()
    for rule in state["rules"]:
        required = {"name", "proto", "listen", "host", "remote", "enabled"}
        if (not isinstance(rule, dict) or set(rule) != required or type(rule["enabled"]) is not bool
                or type(rule["listen"]) is not int or type(rule["remote"]) is not int):
            raise RelayError("规则字段错误。")
        name = valid_name(rule["name"])
        if name in names:
            raise RelayError(f"重复名称：{name}")
        names.add(name)
        if rule["proto"] not in ("tcp", "udp", "both"):
            raise RelayError("协议需为 tcp、udp 或 both。")
        port(rule["listen"])
        port(rule["remote"])
        host(rule["host"], state["engine"] == "nft")
        if not rule["enabled"]:
            continue
        for proto in protocols(rule):
            pair = (proto, rule["listen"])
            if pair in listeners:
                raise RelayError(f"重复监听：{proto}/{rule['listen']}")
            listeners.add(pair)
    return state


def protocols(rule):
    return ("tcp", "udp") if rule["proto"] == "both" else (rule["proto"],)


def active_rules(state):
    return [rule for rule in state["rules"] if rule["enabled"]]


def nft_config(state):
    validate_state(state)
    lines = [f"add table ip {TABLE}", f"delete table ip {TABLE}", f"table ip {TABLE} {{",
             " chain prerouting {", "  type nat hook prerouting priority dstnat; policy accept;"]
    rules = active_rules(state) if state["engine"] == "nft" else []
    for rule in rules:
        for proto in protocols(rule):
            lines.append(f"  fib daddr type local {proto} dport {rule['listen']} counter "
                         f"dnat to {rule['host']}:{rule['remote']} comment \"{rule['name']}\"")
    lines += [" }", " chain postrouting {", "  type nat hook postrouting priority srcnat; policy accept;"]
    for rule in rules:
        for proto in protocols(rule):
            lines.append(f"  ct status dnat ct original proto-dst {rule['listen']} ip daddr "
                         f"{rule['host']} {proto} dport {rule['remote']} counter masquerade")
    return "\n".join(lines + [" }", "}", ""])


def realm_config(state):
    validate_state(state)
    endpoints = []
    for rule in active_rules(state) if state["engine"] == "realm" else []:
        target = f"[{rule['host']}]" if ":" in rule["host"] else rule["host"]
        endpoints.append({"listen": f"0.0.0.0:{rule['listen']}",
                          "remote": f"{target}:{rule['remote']}",
                          "network": {"no_tcp": rule["proto"] == "udp", "use_udp": rule["proto"] != "tcp"}})
    return {"log": {"level": "warn", "output": "stderr"}, "endpoints": endpoints}


def download_verified(url, digest, limit=32 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "Relay-Kit/" + VERSION})
    with urllib.request.urlopen(request, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise RelayError("下载被重定向到了非 HTTPS 地址。")
        data = response.read(limit + 1)
    if len(data) > limit or hashlib.sha256(data).hexdigest() != digest:
        raise RelayError("下载内容大小或 SHA-256 校验失败，未执行下载文件。")
    return data


class Manager:
    def __init__(self, root="/"):
        self.root = pathlib.Path(root)
        self.directory = self.root / "etc/relay-kit"
        self.state_file = self.directory / "forward.json"
        self.library = self.root / "usr/local/lib/relay-kit"
        self.units = self.root / "etc/systemd/system"
        self.realm = self.library / f"realm-{REALM_VERSION}"

    def load(self):
        if not self.state_file.exists():
            raise RelayError("请先运行 relay init nft 或 relay init realm。")
        return validate_state(json.loads(self.state_file.read_text()))

    @contextlib.contextmanager
    def lock(self):
        path = self.root / "run/lock/relay-kit.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def install_engine(self, engine):
        if not (self.root / "run/systemd/system").is_dir():
            raise RelayError("需要使用 systemd 的 Debian/Ubuntu 系统。")
        if not shutil.which("apt-get"):
            raise RelayError("当前自动安装支持 Debian/Ubuntu。")
        packages = ["iproute2", "procps"] + (["nftables"] if engine == "nft" else ["ca-certificates"])
        missing = [name for name in packages if run("dpkg-query", "-W", "-f=${Status}", name,
                   check=False).stdout != "install ok installed"]
        if missing:
            print("安装系统依赖：" + ", ".join(missing), flush=True)
            run("apt-get", "update")
            run("apt-get", "install", "-y", *missing)
        if engine == "realm" and not self.realm.exists():
            try:
                arch, digest = REALM_ASSETS[platform.machine()]
            except KeyError:
                raise RelayError("Realm 固定版本支持 x86_64 / aarch64。") from None
            url = (f"https://github.com/zhboner/realm/releases/download/v{REALM_VERSION}/"
                   f"realm-{arch}-unknown-linux-musl.tar.gz")
            print(f"下载官方 Realm {REALM_VERSION} 并校验 SHA-256。", flush=True)
            data = download_verified(url, digest)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                member = archive.getmember("realm")
                if not member.isfile() or member.size > 32 * 1024 * 1024:
                    raise RelayError("Realm 压缩包内容无效。")
                atomic_write(self.realm, archive.extractfile(member).read(), 0o755)
            run(self.realm, "--version")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.directory.chmod(0o755)
        self.library.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.library.chmod(0o755)
        self.write_units()

    def write_units(self):
        common = "[Unit]\nDescription=Relay Kit {engine}\nWants=network-online.target\nAfter=network-online.target nftables.service\n\n"
        nft = ("[Service]\nType=oneshot\nRemainAfterExit=yes\n"
               "ExecStartPre=/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1\n"
               f"ExecStart=/usr/sbin/nft -f {self.directory}/nftables.nft\n"
               f"ExecReload=/usr/sbin/nft -f {self.directory}/nftables.nft\n"
               f"ExecStop=-/usr/sbin/nft delete table ip {TABLE}\n")
        realm = (f"[Service]\nExecStart={self.realm} -c {self.directory}/realm.json\n"
                 "Restart=on-failure\nRestartSec=3\nDynamicUser=yes\n"
                 "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
                 "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nLimitNOFILE=65536\n")
        for engine, body in (("nft", nft), ("realm", realm)):
            atomic_write(self.units / UNITS[engine], common.format(engine=engine) + body +
                         "\n[Install]\nWantedBy=multi-user.target\n", 0o644)
        run("systemctl", "daemon-reload")

    def check_ports(self, state, previous):
        occupied = self.reserved_ports()
        existing = {(proto, rule["listen"]) for rule in active_rules(previous)
                    for proto in protocols(rule)} if previous else set()
        for rule in active_rules(state):
            for proto in protocols(rule):
                listen = rule["listen"]
                if (proto, listen) in occupied:
                    raise RelayError(f"端口与另一模块的规则冲突：{proto}/{listen}")
                if proto == "tcp" and (listen == 22 or str(listen) == os.environ.get("SSH_CONNECTION", "").split(" ")[-1]):
                    raise RelayError("入口端口与 SSH 端口冲突。")
                result = run("ss", "-H", "-lntp" if proto == "tcp" else "-lnup", f"sport = :{listen}")
                if result.stdout.strip():
                    pids = set(re.findall(r"pid=(\d+),", result.stdout))
                    if (proto, listen) in existing and pids and pids <= self.owned_listener_pids():
                        continue
                    raise RelayError(f"端口已有程序监听：{proto}/{listen}")

    def owned_listener_pids(self):
        if not self.state_file.exists() or self.load()["engine"] != "realm":
            return set()
        pid = run("systemctl", "show", "-p", "MainPID", "--value", UNITS["realm"], check=False).stdout.strip()
        return {pid} if pid.isdigit() and int(pid) else set()

    def reserved_ports(self):
        path = self.directory / "nodes.json"
        if not path.exists():
            return set()
        return node_ports(validate_nodes(json.loads(path.read_text())))

    def write_configs(self, state):
        atomic_write(self.directory / "nftables.nft", nft_config(state))
        atomic_write(self.directory / "realm.json", json_text(realm_config(state)), 0o644)

    def sync(self, state):
        engine = state["engine"]
        self.write_configs(state)
        other = "realm" if engine == "nft" else "nft"
        run("systemctl", "disable", "--now", UNITS[other])
        if not active_rules(state):
            run("systemctl", "disable", "--now", UNITS[engine])
            return
        if engine == "nft":
            config = self.directory / "nftables.nft"
            run("nft", "--check", "--file", config)
            run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            run("nft", "--file", config)
            run("systemctl", "enable", "--now", UNITS[engine])
        else:
            run("systemctl", "restart", UNITS[engine])
            self.wait_realm(state)
            run("systemctl", "enable", UNITS[engine])

    def wait_realm(self, state):
        for _ in range(30):
            pid = run("systemctl", "show", "-p", "MainPID", "--value", UNITS["realm"]).stdout.strip()
            if pid.isdigit() and int(pid) > 0:
                ready = True
                for rule in active_rules(state):
                    for proto in protocols(rule):
                        result = run("ss", "-H", "-lntp" if proto == "tcp" else "-lnup", f"sport = :{rule['listen']}")
                        ready = ready and f"pid={pid}," in result.stdout
                if ready:
                    return
            time.sleep(0.1)
        raise RelayError("Realm 未建立全部监听端口，已触发回退；请查看 relay logs realm。")

    def commit(self, state):
        validate_state(state)
        previous = self.load() if self.state_file.exists() else None
        self.check_ports(state, previous)
        if state["engine"] == "nft":
            run("nft", "--check", "--file", "-", text=nft_config(state))
        if previous:
            atomic_write(self.directory / "forward.json.bak", json_text(previous))
        try:
            self.sync(state)
            atomic_write(self.state_file, json_text(state))
        except BaseException as error:
            try:
                self.sync(previous or {"engine": state["engine"], "rules": []})
            except Exception as rollback:
                raise RelayError(f"应用失败：{error}\n回退也失败：{rollback}\n请检查备份及服务日志。") from error
            raise

    def init(self, engine):
        state = self.load() if self.state_file.exists() else {"engine": engine, "rules": []}
        state["engine"] = engine
        validate_state(state)
        self.install_engine(engine)
        self.commit(state)

    def change(self, action, name, proto=None, listen=None, target=None, remote=None):
        state = copy.deepcopy(self.load())
        match = next((r for r in state["rules"] if r["name"] == name), None)
        if action == "add":
            if match:
                raise RelayError("该名称已存在，修改请使用 set。")
            state["rules"].append({"name": name, "proto": proto, "listen": port(listen),
                                   "host": target, "remote": port(remote), "enabled": True})
        elif not match:
            raise RelayError("未找到该规则。")
        elif action == "set":
            match.update(proto=proto, listen=port(listen), host=target, remote=port(remote))
        elif action == "del":
            state["rules"].remove(match)
        else:
            match["enabled"] = action == "enable"
        self.commit(state)


def install_self(launcher):
    target = pathlib.Path("/usr/local/bin/relay")
    if target.is_symlink() or (target.exists() and MARKER not in target.read_text().splitlines()):
        raise RelayError("/usr/local/bin/relay 属于其他程序，拒绝覆盖。")
    module = pathlib.Path(__file__).resolve()
    library = pathlib.Path("/usr/local/lib/relay-kit")
    destination = library / "relay.py"
    if library.is_symlink() or destination.is_symlink():
        raise RelayError("安装目录或模块是符号链接，拒绝覆盖。")
    if destination.exists() and '"""Relay Kit:' not in destination.read_text():
        raise RelayError("已有未知 relay.py，拒绝覆盖。")
    source = pathlib.Path(launcher)
    if MARKER not in source.read_text().splitlines():
        raise RelayError("入口脚本标记不匹配。")
    payloads = [(destination, module.read_bytes(), 0o644)]
    for filename in ("nodes.py",):
        companion = module.parent / filename
        output = library / filename
        if output.is_symlink() or (output.exists() and not output.read_text().startswith('"""Relay Kit:')):
            raise RelayError(f"已有未知 {filename}，拒绝覆盖。")
        data = companion.read_bytes()
        if not data.startswith(b'"""Relay Kit:'):
            raise RelayError(f"安装包 {filename} 标记错误。")
        payloads.append((output, data, 0o644))
    payloads.append((target, source.read_bytes(), 0o755))
    library.mkdir(parents=True, exist_ok=True, mode=0o755)
    library.chmod(0o755)
    previous = [(path, path.read_bytes() if path.exists() else None,
                 path.stat().st_mode & 0o777 if path.exists() else mode) for path, _, mode in payloads]
    try:
        for path, data, mode in payloads:
            atomic_write(path, data, mode)
    except BaseException:
        for path, data, mode in previous:
            if data is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, data, mode)
        raise
    print(f"Relay Kit {VERSION} 已安装。运行 sudo relay 打开菜单。")


def node_menu(manager):
    from nodes import PROTOCOLS
    while True:
        print("\n节点管理\n1) 添加节点  2) 查看节点  3) 导出连接信息\n"
              "4) 删除节点  5) 启用节点  6) 停用节点  7) 修改端口/密钥\n"
              "8) 查看状态  9) 查看日志  0) 返回")
        try:
            choice = input("请选择：").strip()
            if choice == "0":
                return
            require_root()
            with manager.lock():
                if choice == "1":
                    kinds = list(PROTOCOLS)
                    for index, kind in enumerate(kinds, 1):
                        print(f"{index}) {PROTOCOLS[kind][0]}")
                    selected = int(input("协议编号："))
                    if not 1 <= selected <= len(kinds):
                        raise RelayError("协议编号无效。")
                    kind = kinds[selected - 1]
                    name = input("节点名称：").strip()
                    listen = input("监听端口：").strip()
                    address = input("服务器公网 IP/域名（用于分享链接）：").strip()
                    options = {}
                    if ":" in address:
                        options["bind"] = "::"
                    if kind.startswith("reality"):
                        options["sni"] = input("REALITY 目标网站域名（支持 TLS 1.3，443 端口）：").strip()
                    tls = PROTOCOLS[kind][3]
                    if kind == "vmess-ws":
                        tls = input("启用 TLS？[Y/n]：").strip().lower() != "n"
                        options["tls"] = tls
                    if tls:
                        options["sni"] = input("证书域名 / SNI：").strip()
                        if input("证书：1) 使用现有证书  2) 申请 Let's Encrypt [1]：").strip() == "2":
                            email = input("证书联系邮箱：").strip()
                            cert, key = certificate(options["sni"], email)
                            options.update(cert=cert, key=key)
                        else:
                            options["cert"] = input("证书 PEM 绝对路径：").strip()
                            options["key"] = input("私钥 PEM 绝对路径：").strip()
                    if kind.endswith("-ws") or kind == "reality-xhttp":
                        options["path"] = input("传输路径 [/relay]：").strip() or "/relay"
                    manager.add(kind, name, listen, address, options)
                elif choice == "2":
                    show_nodes(manager.load())
                elif choice in ("3", "4", "5", "6"):
                    manager.change({"3": "link", "4": "del", "5": "enable", "6": "disable"}[choice],
                                   input("节点名称：").strip())
                elif choice == "7":
                    name = input("节点名称：").strip()
                    changes = {}
                    listen = input("新端口（留空保留）：").strip()
                    if listen:
                        changes["listen"] = listen
                    if input("重新生成凭据？[y/N]：").strip().lower() == "y":
                        changes["rotate"] = True
                    manager.change("set", name, changes)
                elif choice in ("8", "9"):
                    node_service_info(manager, "status" if choice == "8" else "logs",
                                      input("节点名称（留空查看全部）：").strip())
                else:
                    print("无效选项。")
        except EOFError:
            return
        except (RelayError, ValueError, OSError) as error:
            print(f"错误：{error}", file=sys.stderr)


def node_service_info(manager, action, name=None):
    selected = [node for node in manager.load()["nodes"] if not name or node["name"] == name]
    if not selected:
        raise RelayError("未找到节点。")
    for node in selected:
        if action == "status":
            print(run("systemctl", "status", "--no-pager", manager.unit(node), check=False).stdout)
        else:
            print(run("journalctl", "-u", manager.unit(node), "-n", "50", "--no-pager").stdout)


def bbr(manager, action):
    config = manager.root / "etc/sysctl.d/99-relay-kit-bbr.conf"
    backup = manager.directory / "bbr.json"
    keys = ("net.core.default_qdisc", "net.ipv4.tcp_congestion_control")
    if action == "status":
        for key in keys:
            print(key + " = " + run("sysctl", "-n", key).stdout.strip())
        return
    require_root()
    marker = "# Relay Kit BBR\n"
    if config.is_symlink() or (config.exists() and not config.read_text().startswith(marker)):
        raise RelayError("BBR 配置路径被其他文件占用，拒绝覆盖。")
    current = {key: run("sysctl", "-n", key).stdout.strip() for key in keys}
    if action == "on":
        available = run("sysctl", "-n", "net.ipv4.tcp_available_congestion_control").stdout.split()
        if "bbr" not in available:
            run("modprobe", "tcp_bbr", check=False)
            available = run("sysctl", "-n", "net.ipv4.tcp_available_congestion_control").stdout.split()
        if "bbr" not in available:
            raise RelayError("当前内核不提供 BBR；未修改设置，也不会替换内核。")
        desired = dict(zip(keys, ("fq", "bbr")))
        if not backup.exists():
            atomic_write(backup, json_text(current))
    elif action == "off":
        if not backup.exists():
            raise RelayError("没有本工具保存的 BBR 原设置。")
        desired = json.loads(backup.read_text())
        if set(desired) != set(keys) or any(not re.fullmatch(r"[A-Za-z0-9_-]+", x) for x in desired.values()):
            raise RelayError("BBR 原设置备份格式错误。")
    else:
        raise RelayError("BBR 操作需为 status / on / off。")
    try:
        for key, value in desired.items():
            run("sysctl", "-q", "-w", key + "=" + value)
        if action == "on":
            atomic_write(config, marker + "\n".join(k + "=" + v for k, v in desired.items()) + "\n", 0o644)
        else:
            config.unlink(missing_ok=True)
            backup.unlink()
    except BaseException:
        for key, value in current.items():
            run("sysctl", "-q", "-w", key + "=" + value, check=False)
        raise
    print("BBR 已启用（fq + bbr）。" if action == "on" else "已恢复启用 BBR 前的设置。")


def bbr_menu(manager):
    print("\nBBR：1) 查看状态  2) 启用  3) 恢复原设置  0) 返回")
    choice = input("请选择：").strip()
    if choice in ("1", "2", "3"):
        require_root()
        with manager.lock():
            bbr(manager, {"1": "status", "2": "on", "3": "off"}[choice])


def certificate(name, email):
    from nodes import domain
    domain(name)
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email):
        raise RelayError("请输入合法邮箱。")
    if run("ss", "-H", "-lnt", "sport = :80").stdout.strip():
        raise RelayError("HTTP-01 申请需要空闲 TCP/80；已有服务占用，请提供现有证书。")
    if not shutil.which("certbot"):
        run("apt-get", "update")
        run("apt-get", "install", "-y", "certbot")
    print("申请 Let's Encrypt 证书；域名必须指向本机，TCP/80 必须可从公网访问。", flush=True)
    run("certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
        "--email", email, "--domain", name, "--keep-until-expiring")
    hook = pathlib.Path("/etc/letsencrypt/renewal-hooks/deploy/relay-kit")
    marker = "# Relay Kit certificate reload"
    if hook.is_symlink() or (hook.exists() and marker not in hook.read_text()):
        raise RelayError("证书续期钩子同名文件属于其他程序，请手动处理。")
    atomic_write(hook, "#!/bin/sh\n" + marker +
                 "\n[ ! -f /etc/relay-kit/nodes.json ] || /usr/local/bin/relay node apply\n", 0o755)
    cert, key = f"/etc/letsencrypt/live/{name}/fullchain.pem", f"/etc/letsencrypt/live/{name}/privkey.pem"
    print(f"证书：{cert}\n私钥：{key}")
    return cert, key


def top_menu(manager):
    while True:
        print(f"\nRelay Kit {VERSION}\n1) nftables 转发\n2) Realm 转发\n3) 搭建/管理节点\n4) BBR\n0) 退出")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            return
        if choice == "0":
            return
        if choice in ("1", "2"):
            menu(manager, "nft" if choice == "1" else "realm")
        elif choice == "3":
            node_menu(NodeManager(manager.root))
        elif choice == "4":
            try:
                bbr_menu(manager)
            except (RelayError, ValueError, OSError) as error:
                print(f"错误：{error}", file=sys.stderr)
        else:
            print("无效选项。")


def show_rules(state):
    print(f"当前引擎：{state['engine']}")
    for rule in state["rules"]:
        print(f"{rule['name']:<20} {rule['proto']:<5} {rule['listen']} -> "
              f"{rule['host']}:{rule['remote']}  {'启用' if rule['enabled'] else '停用'}")


def ask_rule():
    return [input(prompt).strip() for prompt in
            ("名称：", "协议 tcp/udp/both：", "入口端口：", "目标 IP/域名：", "目标端口：")]


def menu(manager, selected=None):
    while True:
        print(f"\nRelay Kit {VERSION} — 自有转发管理")
        if selected:
            print(f"初始化时选用：{selected}")
        print("1) 初始化/切换引擎  2) 添加规则  3) 修改规则\n"
              "4) 删除规则  5) 查看规则  6) 启用规则  7) 停用规则\n"
              "8) 重新应用  9) 查看服务状态  0) 返回")
        try:
            choice = input("请选择：").strip()
            if choice == "0":
                return
            if choice == "5":
                show_rules(manager.load())
                continue
            require_root()
            with manager.lock():
                if choice == "1":
                    engine = selected or input("选择 nft / realm：").strip()
                    if engine not in UNITS:
                        raise RelayError("请选择 nft 或 realm。")
                    manager.init(engine)
                elif choice in ("2", "3"):
                    manager.change("add" if choice == "2" else "set", *ask_rule())
                elif choice in ("4", "6", "7"):
                    manager.change({"4": "del", "6": "enable", "7": "disable"}[choice], input("规则名称：").strip())
                elif choice == "8":
                    manager.commit(manager.load())
                elif choice == "9":
                    status(manager)
                else:
                    print("无效选项。")
        except EOFError:
            return
        except (RelayError, ValueError, OSError) as error:
            print(f"错误：{error}", file=sys.stderr)


def require_root():
    if os.geteuid() != 0:
        raise RelayError("请使用 sudo relay 或 root 运行。")


def status(manager):
    state = manager.load()
    show_rules(state)
    print(run("systemctl", "status", "--no-pager", UNITS[state["engine"]], check=False).stdout)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Relay Kit 自有转发与节点管理")
    parser.add_argument("--version", action="version", version=f"Relay Kit {VERSION}")
    sub = parser.add_subparsers(dest="action")
    sub.add_parser("nft")
    sub.add_parser("realm")
    node_parser = sub.add_parser("node")
    node_sub = node_parser.add_subparsers(dest="node_action")
    node_add = node_sub.add_parser("add")
    node_add.add_argument("kind", choices=PROTOCOLS)
    for argument in ("name", "listen", "address"):
        node_add.add_argument(argument)
    edit = node_sub.add_parser("set")
    edit.add_argument("name")
    edit.add_argument("--port", dest="listen", type=port)
    edit.add_argument("--address")
    edit.add_argument("--rotate", action="store_true")
    for command in (node_add, edit):
        for option in ("sni", "cert", "key", "bind", "path", "method", "mode", "dns", "obfs"):
            command.add_argument("--" + option)
        for option in ("fallback", "up_mbps", "down_mbps"):
            command.add_argument("--" + option.replace("_", "-"), type=int)
        command.add_argument("--tls", action="store_true", default=None)
    bbr_parser = sub.add_parser("bbr")
    bbr_parser.add_argument("operation", choices=("status", "on", "off"), nargs="?", default="status")
    cert_parser = sub.add_parser("cert")
    cert_parser.add_argument("domain")
    cert_parser.add_argument("email")
    for action in ("del", "enable", "disable", "link"):
        node_sub.add_parser(action).add_argument("name")
    for action in ("list", "apply"):
        node_sub.add_parser(action)
    for action in ("status", "logs"):
        node_sub.add_parser(action).add_argument("name", nargs="?")
    install = sub.add_parser("install")
    install.add_argument("--launcher", required=True)
    init = sub.add_parser("init")
    init.add_argument("engine", choices=UNITS)
    for action in ("add", "set"):
        command = sub.add_parser(action)
        for argument in ("name", "proto", "listen", "target", "remote"):
            command.add_argument(argument)
    for action in ("del", "enable", "disable"):
        sub.add_parser(action).add_argument("name")
    for action in ("list", "status", "apply", "show"):
        sub.add_parser(action)
    sub.add_parser("logs").add_argument("engine", choices=UNITS)
    args = parser.parse_args(argv)
    manager = Manager()
    if args.action is None:
        top_menu(manager)
        return
    if args.action in ("nft", "realm"):
        menu(manager, args.action)
        return
    require_root()
    if args.action == "install":
        install_self(args.launcher)
        return
    if args.action == "logs":
        print(run("journalctl", "-u", UNITS[args.engine], "-n", "50", "--no-pager").stdout)
        return
    if args.action == "bbr":
        with manager.lock():
            bbr(manager, args.operation)
        return
    if args.action == "cert":
        certificate(args.domain, args.email)
        return
    if args.action == "node":
        nodes = NodeManager()
        if args.node_action is None:
            node_menu(nodes)
            return
        with nodes.lock():
            if args.node_action == "add":
                options = {key: getattr(args, key) for key in NODE_OPTIONS if getattr(args, key, None) is not None}
                nodes.add(args.kind, args.name, args.listen, args.address, options)
            elif args.node_action == "set":
                changes = {key: getattr(args, key) for key in NODE_OPTIONS | {"listen", "address", "rotate"}
                           if getattr(args, key, None) is not None}
                nodes.change("set", args.name, changes)
            elif args.node_action == "list":
                show_nodes(nodes.load())
            elif args.node_action == "apply":
                nodes.prepare()
                current = nodes.load()
                for node in current["nodes"]:
                    if node["enabled"]:
                        nodes.install_core(PROTOCOLS[node["kind"]][1])
                nodes.commit(current)
            elif args.node_action in ("status", "logs"):
                node_service_info(nodes, args.node_action, args.name)
            else:
                nodes.change(args.node_action, args.name)
        return
    with manager.lock():
        if args.action == "init":
            manager.init(args.engine)
        elif args.action in ("add", "set"):
            manager.change(args.action, args.name, args.proto, args.listen, args.target, args.remote)
        elif args.action in ("del", "enable", "disable"):
            manager.change(args.action, args.name)
        elif args.action == "list":
            show_rules(manager.load())
        elif args.action == "status":
            status(manager)
        elif args.action == "apply":
            manager.commit(manager.load())
        elif args.action == "show":
            state = manager.load()
            print(nft_config(state) if state["engine"] == "nft" else json_text(realm_config(state)))


# Resolve only modules shipped beside this file; Python's -I ignores PYTHONPATH.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.modules.setdefault("relay", sys.modules[__name__])
from nodes import (NodeManager, PROTOCOLS, OPTION_KEYS as NODE_OPTIONS, SS_METHOD,
                   validate_nodes, node_ports, node_link, show_nodes)

if __name__ == "__main__":
    try:
        main()
    except (RelayError, ValueError, OSError) as error:
        print(f"错误：{error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
