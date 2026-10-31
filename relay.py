#!/usr/bin/env python3
"""Relay Kit: original forwarding configuration and service management."""

import argparse
import contextlib
import copy
import fcntl
import hashlib
import http.client
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

VERSION = "0.3.1"
MARKER = "# relay-kit managed entry"
REALM_VERSION = "2.9.6"
REALM_ASSETS = {
    "x86_64": ("x86_64", "b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65"),
    "aarch64": ("aarch64", "f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488"),
}
TABLE = "relay_kit"
UNITS = {"nft": "relay-kit-nft.service", "realm": "relay-kit-realm.service"}
# TCP MSS for forwarded connections; the Po0 Wiki clamps to 1452 to avoid stalls on lower-MTU paths.
MSS = 1452
# Blocked in both directions by default on Po0 Guangzhou/East China BGP entries.
BLOCKED_PORTS = (80, 443, 8080, 8443, 8000, 1080)
# Prefixes for GitHub downloads, tried only after a direct download fails. Pinned SHA-256
# digests decide what is accepted, so a mirror can make a download fail but not change it.
MIRRORS = ("https://ghfast.top/", "https://gh-proxy.com/")
FIREWALL_TAG = "relay-kit"


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
    lines += [" }", " chain forward {", "  type filter hook forward priority mangle; policy accept;"]
    tcp = sorted({rule["listen"] for rule in rules if rule["proto"] != "udp"})
    if tcp:
        # Lower, never raise, the MSS of SYN and SYN-ACK in both directions of our connections.
        lines.append(f"  ct status dnat ct original proto-dst {{ {', '.join(map(str, tcp))} }} "
                     f"tcp flags & (syn | rst) == syn tcp option maxseg size > {MSS} counter "
                     f"tcp option maxseg size set {MSS}")
    return "\n".join(lines + [" }", "}", ""])


def blocked_port_note(*numbers):
    hits = sorted({int(number) for number in numbers if str(number).isdigit() and int(number) in BLOCKED_PORTS})
    if hits:
        return (f"端口 {'、'.join(map(str, hits))} 在 Po0 广州/华东 BGP 等国内入口默认双向封禁；"
                "链路经过这类入口时请换端口。")
    return None


def foreign_forwards(ruleset):
    """(proto, low, high, table) port ranges that other nftables tables DNAT or redirect."""
    found, table = [], None
    for line in ruleset.splitlines():
        head = re.match(r"\s*table (\S+) (\S+) \{", line)
        if head:
            table = head.groups()
            continue
        if not table or table == ("ip", TABLE) or not re.search(r"\b(dnat|redirect)\b", line):
            continue
        for proto, values in re.findall(r"\b(tcp|udp|th) dport (?:map )?(\{[^}]*\}|\d+(?:-\d+)?)", line):
            for element in values.strip("{}").split(","):
                match = re.fullmatch(r"\s*(\d+)(?:-(\d+))?\s*(?::.*)?", element)
                if match:
                    for name in ("tcp", "udp") if proto == "th" else (proto,):
                        found.append((name, int(match[1]), int(match[2] or match[1]), " ".join(table)))
    return found


def forward_blockers(ruleset):
    """Forward-hook chains of other tables that drop whatever they do not accept (Docker, ufw, firewalld)."""
    chains, table, chain, depth = {}, None, None, 0
    for line in ruleset.splitlines():
        text = line.strip()
        if depth == 0 and text.startswith("table "):
            table = " ".join(text.split()[1:3])
        elif depth == 1 and text.startswith("chain "):
            chain = (table, text.split()[1])
            chains[chain] = []
        elif depth >= 2 and chain:
            chains[chain].append(text)
        depth += text.count("{") - text.count("}")
        if depth <= 1:
            chain = None
    blockers = []
    for (name, chain), lines in chains.items():
        rules = [text for text in lines[1:] if text and text != "}"]
        if name == f"ip {TABLE}" or not lines or "hook forward" not in lines[0]:
            continue
        last = rules[-1] if rules else ""
        if "policy drop" in lines[0] or re.fullmatch(r"(counter packets \d+ bytes \d+ )?(drop|reject\b.*)", last):
            blockers.append(f"{name} {chain}")
    return blockers


def forward_drop_note():
    blockers = forward_blockers(run("nft", "list", "ruleset", check=False).stdout) if shutil.which("nft") else []
    if blockers:
        return (f"{'、'.join(blockers)} 默认丢弃转发流量（常见于 Docker、ufw、firewalld），nftables 转发的连接会被丢弃。"
                "可以改用 Realm 引擎，或在该防火墙中放行（ufw route allow、Docker 的 DOCKER-USER 链）。")
    return None


def input_block(tool):
    """Where ACCEPT rules must go in INPUT (1-based), or None when INPUT does not reject by default."""
    if not shutil.which(tool):
        return None
    rules = run(tool, "-S", "INPUT", check=False).stdout.splitlines()
    appended = [rule for rule in rules if rule.startswith("-A INPUT ")]
    for index, rule in enumerate(appended, 1):
        if re.fullmatch(r"-A INPUT -j (REJECT|DROP)( --reject-with \S+)?", rule):
            return index
    return len(appended) + 1 if "-P INPUT DROP" in rules else None


def firewall_backend():
    """The active host firewall that would block Relay Kit's listeners, if any."""
    if shutil.which("ufw") and run("ufw", "status", check=False).stdout.startswith("Status: active"):
        return "ufw"
    if shutil.which("firewall-cmd") and run("firewall-cmd", "--state", check=False).stdout.strip() == "running":
        return "firewalld"
    if any(input_block(tool) for tool in ("iptables", "ip6tables")):
        return "iptables"
    return None


def accept_rule(proto, number):
    return ["-p", proto, "--dport", str(number), "-m", "comment", "--comment", FIREWALL_TAG, "-j", "ACCEPT"]


def firewall_allow(backend, proto, number):
    """Open one port; True when Relay Kit added the rule rather than finding it already open."""
    spec = f"{number}/{proto}"
    if backend == "ufw":
        return "Skipping" not in run("ufw", "allow", spec, "comment", FIREWALL_TAG).stdout
    if backend == "firewalld":
        result = run("firewall-cmd", "--permanent", f"--add-port={spec}")
        run("firewall-cmd", f"--add-port={spec}", check=False)
        return "ALREADY_ENABLED" not in result.stdout + result.stderr
    for tool in ("iptables", "ip6tables"):
        position = input_block(tool)
        if position and run(tool, "-C", "INPUT", *accept_rule(proto, number), check=False).returncode:
            run(tool, "-I", "INPUT", str(position), *accept_rule(proto, number))
    return True


def firewall_remove(backend, proto, number):
    spec = f"{number}/{proto}"
    if backend == "ufw":
        run("ufw", "--force", "delete", "allow", spec, check=False)
    elif backend == "firewalld":
        run("firewall-cmd", "--permanent", f"--remove-port={spec}", check=False)
        run("firewall-cmd", f"--remove-port={spec}", check=False)
    elif backend == "iptables":
        for tool in ("iptables", "ip6tables"):
            while shutil.which(tool) and not run(tool, "-C", "INPUT", *accept_rule(proto, number), check=False).returncode:
                run(tool, "-D", "INPUT", *accept_rule(proto, number))


def firewall_record(path):
    record = json.loads(path.read_text()) if path.exists() else {"backend": None, "ports": []}
    if (not isinstance(record, dict) or record.get("backend") not in (None, "ufw", "firewalld", "iptables") or
            not isinstance(record.get("ports"), list) or
            any(not isinstance(item, list) or len(item) != 2 or item[0] not in ("tcp", "udp") or
                type(item[1]) is not int for item in record["ports"])):
        raise RelayError("防火墙放行记录格式错误。")
    return record["backend"], {(proto, number) for proto, number in record["ports"]}


def listening_ports(root):
    """(proto, port) pairs Relay Kit services accept on this host: enabled nodes and Realm entries."""
    manager = Manager(root)
    wanted = manager.reserved_ports()
    if manager.state_file.exists():
        state = manager.load()
        if state["engine"] == "realm":
            wanted |= {(proto, rule["listen"]) for rule in active_rules(state) for proto in protocols(rule)}
    return wanted


def sync_firewall(root, wanted=None):
    """Open the active host firewall for Relay Kit's listeners and close what it opened before.

    Only rules Relay Kit added are recorded, so rules the user had already are never removed.
    Passing `wanted` (as uninstall does) skips detection and works on the recorded firewall."""
    path = Manager(root).directory / "firewall.json"
    previous, before = firewall_record(path)
    backend = firewall_backend() if wanted is None else previous
    opened, messages = set(before), []

    def attempt(action, name, proto, number):
        try:
            return action(name, proto, number)
        except RelayError as error:
            messages.append(f"{name} 处理 {number}/{proto} 失败：{error}")
            return False

    if previous and previous != backend:
        for proto, number in sorted(opened):
            attempt(firewall_remove, previous, proto, number)
        opened = set()
    if wanted is None:
        wanted = listening_ports(root) if backend else set()
    for proto, number in sorted(wanted - opened):
        if attempt(firewall_allow, backend, proto, number):
            opened.add((proto, number))
            messages.append(f"已在 {backend} 放行 {number}/{proto}")
    for proto, number in sorted(opened - wanted):
        attempt(firewall_remove, backend, proto, number)
        opened.discard((proto, number))
        messages.append(f"已在 {backend} 关闭 {number}/{proto}")
    if messages and "iptables" in (backend, previous):
        if shutil.which("netfilter-persistent"):
            run("netfilter-persistent", "save", check=False)
        else:
            messages.append("未安装 netfilter-persistent，iptables 放行规则重启后会失效")
    if (backend if opened else None, opened) != (previous, before):
        atomic_write(path, json_text({"backend": backend if opened else None,
                                      "ports": [list(item) for item in sorted(opened)]}))
    return messages


def apply_firewall(root):
    try:
        for message in sync_firewall(root):
            print("防火墙：" + message, flush=True)
    except (RelayError, ValueError, OSError) as error:
        print(f"提示：自动放行防火墙失败，请手动放行端口：{error}", file=sys.stderr)


def realm_config(state):
    validate_state(state)
    endpoints = []
    for rule in active_rules(state) if state["engine"] == "realm" else []:
        target = f"[{rule['host']}]" if ":" in rule["host"] else rule["host"]
        endpoints.append({"listen": f"0.0.0.0:{rule['listen']}",
                          "remote": f"{target}:{rule['remote']}",
                          "network": {"no_tcp": rule["proto"] == "udp", "use_udp": rule["proto"] != "tcp"}})
    return {"log": {"level": "warn", "output": "stderr"}, "endpoints": endpoints}


def mirrors():
    value = os.environ.get("RELAY_KIT_MIRRORS")
    return MIRRORS if value is None else tuple(item for item in re.split(r"[\s,]+", value) if item)


def fetch(url, limit):
    request = urllib.request.Request(url, headers={"User-Agent": "Relay-Kit/" + VERSION})
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.url.startswith("https://"):
            raise RelayError("下载被重定向到了非 HTTPS 地址。")
        return response.read(limit + 1)


def download_verified(url, digest, limit=32 * 1024 * 1024):
    sources = [url] + [prefix + url for prefix in mirrors() if url.startswith("https://github.com/")]
    problems = []
    for source in sources:
        site = urllib.parse.urlsplit(source).netloc
        if source != url:
            print(f"改用镜像 {site} 下载，内容同样校验 SHA-256。", flush=True)
        try:
            data = fetch(source, limit)
        except (OSError, ValueError, http.client.HTTPException, RelayError) as error:
            problems.append(f"{site}：{error}")
            continue
        if len(data) <= limit and hashlib.sha256(data).hexdigest() == digest:
            return data
        problems.append(f"{site}：大小或 SHA-256 校验失败，已丢弃")
    raise RelayError("下载失败，未使用任何下载内容：\n" + "\n".join(problems) +
                     f"\n离线安装：在能访问该地址的电脑上下载\n{url}\n上传到服务器后运行 sudo relay core import 文件路径")


def realm_url(arch):
    return (f"https://github.com/zhboner/realm/releases/download/v{REALM_VERSION}/"
            f"realm-{arch}-unknown-linux-musl.tar.gz")


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
            self.install_realm()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.directory.chmod(0o755)
        self.library.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.library.chmod(0o755)
        self.write_units()

    def install_realm(self, data=None):
        """Install the pinned Realm binary, downloading it unless an imported archive is given."""
        try:
            arch, digest = REALM_ASSETS[platform.machine()]
        except KeyError:
            raise RelayError("Realm 固定版本支持 x86_64 / aarch64。") from None
        if data is None:
            print(f"下载官方 Realm {REALM_VERSION} 并校验 SHA-256。", flush=True)
            data = download_verified(realm_url(arch), digest)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember("realm")
            if not member.isfile() or member.size > 32 * 1024 * 1024:
                raise RelayError("Realm 压缩包内容无效。")
            atomic_write(self.realm, archive.extractfile(member).read(), 0o755)
        run(self.realm, "--version")

    def write_units(self):
        common = ("[Unit]\nDescription=Relay Kit {engine}\nWants=network-online.target\n"
                  "After=network-online.target nftables.service\n{extra}\n")
        # Debian's nftables.service flushes the whole ruleset when it stops, and the Po0 Wiki's
        # /etc/nftables.conf starts with `flush ruleset`; re-apply our table after either.
        follow = "PartOf=nftables.service\nReloadPropagatedFrom=nftables.service\n"
        nft = ("[Service]\nType=oneshot\nRemainAfterExit=yes\n"
               "ExecStartPre=/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1\n"
               f"ExecStart=/usr/sbin/nft -f {self.directory}/nftables.nft\n"
               f"ExecReload=/usr/sbin/nft -f {self.directory}/nftables.nft\n"
               f"ExecStop=-/usr/sbin/nft delete table ip {TABLE}\n")
        realm = (f"[Service]\nExecStart={self.realm} -c {self.directory}/realm.json\n"
                 "Restart=on-failure\nRestartSec=3\nDynamicUser=yes\n"
                 "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
                 "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nLimitNOFILE=65536\n")
        changed = False
        for engine, extra, body, wanted in (("nft", follow, nft, "multi-user.target nftables.service"),
                                           ("realm", "", realm, "multi-user.target")):
            path = self.units / UNITS[engine]
            text = common.format(engine=engine, extra=extra) + body + f"\n[Install]\nWantedBy={wanted}\n"
            if not path.is_file() or path.read_text() != text:
                atomic_write(path, text, 0o644)
                changed = True
        if changed:
            run("systemctl", "daemon-reload")

    def check_ports(self, state, previous):
        occupied = self.reserved_ports()
        existing = {(proto, rule["listen"]) for rule in active_rules(previous)
                    for proto in protocols(rule)} if previous else set()
        foreign = foreign_forwards(run("nft", "list", "ruleset", check=False).stdout) if shutil.which("nft") else []
        for rule in active_rules(state):
            for proto in protocols(rule):
                listen = rule["listen"]
                if (proto, listen) in occupied:
                    raise RelayError(f"端口与另一模块的规则冲突：{proto}/{listen}")
                if proto == "tcp" and (listen == 22 or str(listen) == os.environ.get("SSH_CONNECTION", "").split(" ")[-1]):
                    raise RelayError("入口端口与 SSH 端口冲突。")
                clash = next((table for name, low, high, table in foreign if name == proto and low <= listen <= high), None)
                if clash and (proto, listen) not in existing:
                    raise RelayError(f"端口 {proto}/{listen} 已被 nftables 表 {clash} 中的其他规则转发；请先删除旧规则"
                                     "（例如按 Po0 Wiki 手写的 /etc/nftables.conf），只用一套工具管理转发。")
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
        self.write_units()
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
        apply_firewall(self.root)
        hint = forward_drop_note() if state["engine"] == "nft" and active_rules(state) else None
        if hint:
            print("提示：" + hint, file=sys.stderr)

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
            raise RelayError(f"未找到规则：{name}")
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
    for filename in ("nodes.py", "menu.py"):
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


def node_service_info(manager, action, name=None):
    nodes = manager.load()["nodes"]
    if not nodes:
        raise RelayError("暂无节点，请先添加节点。")
    selected = [node for node in nodes if not name or node["name"] == name]
    if not selected:
        raise RelayError(f"未找到节点：{name}")
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
        return None
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
    return "BBR 已启用（fq + bbr）。" if action == "on" else "已恢复启用 BBR 前的设置。"


def uninstall(manager):
    """Remove every service, file and setting Relay Kit created; leave anything it does not own."""
    require_root()
    owned = [path for path in sorted(manager.units.glob("relay-node-*.service"))
             if path.is_file() and not path.is_symlink() and
             path.read_text().startswith("# Relay Kit managed node\n")]
    owned += [manager.units / name for name in UNITS.values() if (manager.units / name).is_file()]
    if shutil.which("systemctl"):
        for path in owned:
            run("systemctl", "disable", "--now", path.name, check=False)
    if shutil.which("nft"):
        run("nft", "delete", "table", "ip", TABLE, check=False)
    if (manager.directory / "bbr.json").exists():
        try:
            bbr(manager, "off")
        except RelayError as error:
            print(f"未能恢复 BBR 原设置：{error}")
    marked = ((manager.root / "etc/sysctl.d/99-relay-kit-bbr.conf", "# Relay Kit BBR"),
              (manager.root / "etc/letsencrypt/renewal-hooks/deploy/relay-kit", "# Relay Kit certificate reload"),
              (manager.root / "usr/local/bin/relay", MARKER))
    for path, marker in marked:
        if path.is_file() and not path.is_symlink() and marker in path.read_text().splitlines():
            owned.append(path)
    for path in owned:
        path.unlink(missing_ok=True)
    try:
        for message in sync_firewall(manager.root, wanted=set()):
            print("防火墙：" + message)
    except (RelayError, ValueError, OSError) as error:
        print(f"未能撤销防火墙放行，请手动检查：{error}")
    for directory in (manager.directory, manager.library):
        if directory.is_dir() and not directory.is_symlink():
            shutil.rmtree(directory)
    if shutil.which("systemctl"):
        run("systemctl", "daemon-reload", check=False)


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


def show_rules(state):
    print(f"当前引擎：{state['engine']}")
    if not state["rules"]:
        print("暂无规则。")
    for rule in state["rules"]:
        print(f"{rule['name']:<20} {rule['proto']:<5} {rule['listen']} -> "
              f"{rule['host']}:{rule['remote']}  {'启用' if rule['enabled'] else '停用'}")


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
    edit.add_argument("--via")
    edit.add_argument("--via-port", type=port)
    edit.add_argument("--via-label")
    edit.add_argument("--clear-via", action="store_true")
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
    for action in ("del", "enable", "disable", "link", "info"):
        node_sub.add_parser(action).add_argument("name")
    for action in ("link", "info"):
        node_sub.choices[action].add_argument("--via")
        node_sub.choices[action].add_argument("--via-port", type=port)
    for action in ("list", "apply"):
        node_sub.add_parser(action)
    for action in ("status", "logs"):
        node_sub.add_parser(action).add_argument("name", nargs="?")
    install = sub.add_parser("install")
    install.add_argument("--launcher", required=True)
    sub.add_parser("uninstall").add_argument("--yes", action="store_true")
    core_sub = sub.add_parser("core").add_subparsers(dest="core_action", required=True)
    core_sub.add_parser("list")
    core_sub.add_parser("import").add_argument("files", nargs="+")
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
    if args.action in (None, "nft", "realm") or (args.action == "node" and args.node_action is None):
        menu.open_menu(manager, args.action)
        return
    require_root()
    if args.action == "install":
        install_self(args.launcher)
        return
    if args.action == "uninstall":
        try:
            answer = "yes" if args.yes else input("将删除 Relay Kit 的全部规则、节点、配置和程序。输入 yes 确认：").strip()
        except EOFError:
            answer = ""
        if answer != "yes":
            print("已取消。")
            return
        with manager.lock():
            uninstall(manager)
        print("Relay Kit 已卸载。")
        return
    if args.action == "logs":
        print(run("journalctl", "-u", UNITS[args.engine], "-n", "50", "--no-pager").stdout)
        return
    if args.action == "bbr":
        with manager.lock():
            message = bbr(manager, args.operation)
        if message:
            print(message)
        return
    if args.action == "cert":
        certificate(args.domain, args.email)
        return
    if args.action == "core":
        nodes = NodeManager()
        if args.core_action == "list":
            installed = {name: present for name, _, present in nodes.cores()}
            for name, version, machine, url, digest in official_assets():
                if machine == platform.machine():
                    print(f"{name} {version}  {'已安装' if installed[name] else '未安装'}\n  {url}\n  sha256 {digest}")
            return
        with nodes.lock():
            for file in args.files:
                print(f"已导入 {nodes.import_archive(file)}，SHA-256 校验通过。")
        return
    if args.action == "node":
        nodes = NodeManager()
        hint = blocked_port_note(args.listen) if args.node_action in ("add", "set") and args.listen else None
        if hint:
            print("提示：" + hint, file=sys.stderr)
        with nodes.lock():
            if args.node_action == "add":
                options = {key: getattr(args, key) for key in NODE_OPTIONS if getattr(args, key, None) is not None}
                node = nodes.add(args.kind, args.name, args.listen, args.address, options)
                print("节点已创建。连接信息（含凭据）：\n" + node_link(node))
            elif args.node_action == "set":
                changes = {key: getattr(args, key) for key in NODE_OPTIONS | {"listen", "address", "rotate"}
                           if getattr(args, key, None) is not None}
                if args.via or args.clear_via:
                    node = next((item for item in nodes.load()["nodes"] if item["name"] == args.name), None)
                    if node is None:
                        raise RelayError(f"未找到节点：{args.name}")
                    relays = [] if args.clear_via else node["options"].get("relays", [])
                    if args.via:
                        entry = relayed(node, args.via, args.via_port)
                        relays = [item for item in relays if (item["address"], item["port"]) !=
                                  (entry["address"], entry["listen"])]
                        relays.append({"address": entry["address"], "port": entry["listen"],
                                       "label": args.via_label or next_label(relays)})
                    changes["relays"] = relays
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
            elif args.node_action in ("info", "link"):
                node = next((item for item in nodes.load()["nodes"] if item["name"] == args.name), None)
                if node is None:
                    raise RelayError(f"未找到节点：{args.name}")
                if args.via:
                    node = relayed(node, args.via, args.via_port)
                if args.node_action == "info":
                    menu.show_node(nodes, node, fresh=False)
                else:
                    print(node_link(node))
            else:
                nodes.change(args.node_action, args.name)
        return
    with manager.lock():
        if args.action == "init":
            manager.init(args.engine)
        elif args.action in ("add", "set"):
            hint = blocked_port_note(args.listen, args.remote)
            if hint:
                print("提示：" + hint, file=sys.stderr)
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
                   validate_nodes, next_label, node_ports, node_link, official_assets, relayed, show_nodes)
import menu

if __name__ == "__main__":
    try:
        main()
    except (RelayError, ValueError, OSError) as error:
        print(f"错误：{error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
