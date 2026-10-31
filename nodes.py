"""Relay Kit: independently implemented node configuration and lifecycle."""

import base64
import copy
import hashlib
import io
import ipaddress
import json
import pathlib
import platform
import re
import secrets
import shutil
import tempfile
import time
import urllib.parse
import uuid
import zipfile
import tarfile

from relay import (REALM_ASSETS, REALM_VERSION, Manager, RelayError, apply_firewall, atomic_write,
                   download_verified, host, json_text, port, protocols, active_rules, realm_url, run,
                   valid_name, validate_state)

# name: (display name, official runtime, public transports, certificate required)
PROTOCOLS = {
    "reality": ("VLESS + REALITY", "xray", ("tcp",), False),
    "reality-xhttp": ("VLESS + REALITY + XHTTP", "xray", ("tcp",), False),
    "vless-encryption": ("VLESS Encryption", "xray", ("tcp",), False),
    "vless-ws": ("VLESS + WebSocket + TLS", "xray", ("tcp",), True),
    "vmess-ws": ("VMess + WebSocket", "xray", ("tcp",), False),
    "vless-vision": ("VLESS + XTLS Vision", "xray", ("tcp",), True),
    "trojan": ("Trojan", "xray", ("tcp",), True),
    "hysteria2": ("Hysteria2", "sing-box", ("udp",), True),
    "ss2022": ("Shadowsocks 2022", "xray", ("tcp", "udp"), False),
    "shadowsocks": ("Shadowsocks AEAD", "xray", ("tcp", "udp"), False),
    "socks5": ("SOCKS5", "xray", ("tcp", "udp"), False),
    "snell4": ("Snell v4", "snell4", ("tcp",), False),
    "snell5": ("Snell v5", "snell5", ("tcp", "udp"), False),
    "snell6": ("Snell v6", "snell6", ("tcp",), False),
    "anytls": ("AnyTLS", "sing-box", ("tcp",), True),
    "tuic": ("TUIC v5", "sing-box", ("udp",), True),
    "naive": ("NaiveProxy", "sing-box", ("tcp", "udp"), True),
}
CORE_VERSIONS = {"xray": "26.10.29", "sing-box": "1.14.4",
                 "snell4": "4.1.1", "snell5": "5.0.1", "snell6": "6.0.0"}
# Archives fetched from official publishers; fixed digests make replacement fail closed.
CORE_DIGESTS = {
    "xray": ("8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2",
             "afe01f19045b05237420328028ee1ee2e1edd2100eb41a8cbbf50e683b0a6e58"),
    "sing-box": ("699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968",
                 "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"),
    "snell4": ("cc2271b79c7506888b34e651e8741b3aa7fc7d5f60aa65ef8bb096f3313a193b",
               "38d4cdc03dcdb3608af8594df83e1795265167fafc5d802f815148908902d758"),
    "snell5": ("9bea1c2b9e35b73b31634856c04d18c393072b9e5dcde6a32781d8b8f908c539",
               "2f178bf5ac468ce1a130454efa40a0603fbbe4e47ecc4880a989f4abc7f824cf"),
    "snell6": ("8a9c4463ca87cfa5eaa37c6af0d37ab93ea275aa12391985bb2a375ca3abd7f2",
               "a0b2915cbc77dc3baf8fa069e741c20808d8a10c3a8a93e709a0a580645c3bd7"),
}
SS_METHOD = "2022-blake3-aes-128-gcm"
OPTION_KEYS = {"sni", "path", "cert", "key", "bind", "method", "mode", "dns", "obfs",
               "fallback", "tls", "up_mbps", "down_mbps", "relays"}
SECRET_KEYS = {"uuid", "password", "private", "public", "short_id", "encryption", "decryption"}


def domain(value):
    host(value)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise RelayError("SNI 需要域名。")


def core_url(core, machine):
    arm, version = machine == "aarch64", CORE_VERSIONS[core]
    if core == "xray":
        return (f"https://github.com/XTLS/Xray-core/releases/download/v{version}/"
                f"Xray-linux-{'arm64-v8a' if arm else '64'}.zip")
    if core == "sing-box":
        return (f"https://github.com/SagerNet/sing-box/releases/download/v{version}/"
                f"sing-box-{version}-linux-{'arm64' if arm else 'amd64'}.tar.gz")
    return f"https://dl.nssurge.com/snell/snell-server-v{version}-linux-{'aarch64' if arm else 'amd64'}.zip"


def official_assets():
    """Every pinned download as (core, version, machine, url, sha256)."""
    assets = [("realm", REALM_VERSION, machine, realm_url(arch), digest)
              for machine, (arch, digest) in REALM_ASSETS.items()]
    for core, digests in CORE_DIGESTS.items():
        for machine, digest in zip(("x86_64", "aarch64"), digests):
            assets.append((core, CORE_VERSIONS[core], machine, core_url(core, machine), digest))
    return assets


def next_label(relays):
    labels, index = {item["label"] for item in relays}, len(relays) + 1
    while f"中转{index}" in labels:
        index += 1
    return f"中转{index}"


def check_label(value):
    if not re.fullmatch(r"[^\s,=#\"'\\]{1,24}", value):
        raise RelayError("名称为 1–24 个字符，不能包含空白、逗号、等号、# 或引号。")
    return value


def node_protocols(node):
    return PROTOCOLS[node["kind"]][2]


def listener_protocols(node):
    # Xray creates SOCKS UDP associations lazily, after the TCP handshake.
    return ("tcp",) if node["kind"] == "socks5" else node_protocols(node)


def node_ports(state):
    return {(proto, node["listen"]) for node in state["nodes"] if node["enabled"]
            for proto in node_protocols(node)}


def validate_nodes(state):
    if not isinstance(state, dict) or set(state) != {"nodes"} or not isinstance(state["nodes"], list):
        raise RelayError("节点配置格式错误。")
    names, ports = set(), set()
    for node in state["nodes"]:
        if not isinstance(node, dict) or set(node) != {
                "name", "kind", "listen", "address", "enabled", "options", "secrets"}:
            raise RelayError("节点字段错误。")
        if not isinstance(node["kind"], str) or node["kind"] not in PROTOCOLS:
            raise RelayError("不支持的节点协议。")
        valid_name(node["name"])
        host(node["address"])
        if type(node["listen"]) is not int or type(node["enabled"]) is not bool:
            raise RelayError("节点端口或启用标记格式错误。")
        port(node["listen"])
        if node["name"] in names:
            raise RelayError("节点名称重复。")
        names.add(node["name"])
        opts, keys = node["options"], node["secrets"]
        if not isinstance(opts, dict) or set(opts) - OPTION_KEYS or not isinstance(keys, dict) or set(keys) - SECRET_KEYS:
            raise RelayError("未知的节点配置字段。")
        bind = ipaddress.ip_address(opts.get("bind", "0.0.0.0"))
        if bind.is_multicast:
            raise RelayError("监听地址不能是组播。")
        if ":" in node["address"] and bind.version == 4:
            raise RelayError("IPv6 分享地址需要设置 IPv6 监听地址，例如 --bind ::。")
        if opts.get("sni"):
            domain(opts["sni"])
        if opts.get("tls") and node["kind"] != "vmess-ws" and not PROTOCOLS[node["kind"]][3]:
            raise RelayError("--tls 用于 VMess WS；其余协议的 TLS 模式由协议类型决定。")
        if node["kind"].startswith("reality") and not opts.get("sni"):
            raise RelayError("REALITY 需要 --sni 目标域名。")
        if PROTOCOLS[node["kind"]][3] or opts.get("tls"):
            if not all(isinstance(opts.get(key), str) and pathlib.Path(opts[key]).is_absolute() for key in ("cert", "key")):
                raise RelayError("该协议需要绝对路径的 --cert 证书和 --key 私钥。")
            domain(opts.get("sni", ""))
        if node["kind"] == "naive" and node["address"] != opts.get("sni"):
            raise RelayError("NaiveProxy 分享地址需要使用与证书 SNI 相同的域名。")
        for name in ("path", "mode", "method", "dns", "obfs"):
            if name in opts and (not isinstance(opts[name], str) or any(c in opts[name] for c in "\r\n\0")):
                raise RelayError("协议参数不能包含换行或空字符。")
        if "path" in opts and (not opts["path"].startswith("/") or len(opts["path"]) > 256):
            raise RelayError("WebSocket/XHTTP 路径必须以 / 开头，最长 256 字符。")
        if opts.get("mode", "default") not in ("default", "unshaped"):
            raise RelayError("Snell v6 模式支持 default / unshaped。")
        if opts.get("obfs", "off") not in ("off", "http"):
            raise RelayError("Snell 混淆支持 off / http。")
        if opts.get("dns"):
            for item in opts["dns"].split(","):
                ipaddress.ip_address(item)
        if opts.get("fallback"):
            if node["kind"] not in ("vless-vision", "trojan"):
                raise RelayError("只有 Vision / Trojan 支持此回落入口。")
            port(opts["fallback"])
            if int(opts["fallback"]) == node["listen"]:
                raise RelayError("回落端口不能指向节点自身。")
        for name in ("up_mbps", "down_mbps"):
            if name in opts and (type(opts[name]) is not int or not 1 <= opts[name] <= 100000):
                raise RelayError("Hysteria2 带宽需为 1–100000 Mbps。")
        relays = opts.get("relays", [])
        if not isinstance(relays, list) or len(relays) > 8:
            raise RelayError("每个节点最多保存 8 个中转入口。")
        for item in relays:
            if (not isinstance(item, dict) or set(item) != {"address", "port", "label"} or
                    type(item["port"]) is not int or not isinstance(item["label"], str)):
                raise RelayError("中转入口格式错误。")
            host(item["address"])
            port(item["port"])
            check_label(item["label"])
        if not isinstance(keys.get("password"), str) or not re.fullmatch(r"[A-Za-z0-9_+/=-]{16,256}", keys["password"]):
            raise RelayError("节点凭据格式错误。")
        uuid.UUID(keys.get("uuid", ""))
        if node["kind"] == "ss2022":
            if len(base64.b64decode(keys["password"], validate=True)) != 16:
                raise RelayError("SS2022 密钥需要 16 字节。")
        if node["kind"].startswith("reality"):
            if any(not re.fullmatch(r"[A-Za-z0-9_-]{43}", keys.get(k, "")) for k in ("private", "public")):
                raise RelayError("REALITY 密钥无效。")
            if not re.fullmatch(r"[0-9a-f]{16}", keys.get("short_id", "")):
                raise RelayError("REALITY short ID 无效。")
        if node["kind"] == "vless-encryption":
            if any(not re.fullmatch(r"mlkem768x25519plus\.native\.[A-Za-z0-9.]+[A-Za-z0-9_-]+",
                                   keys.get(k, "")) for k in ("encryption", "decryption")):
                raise RelayError("VLESS Encryption 密钥无效。")
        if opts.get("method", "aes-256-gcm") not in ("aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"):
            raise RelayError("传统 Shadowsocks 仅支持 AEAD 加密方法。")
        if node["enabled"]:
            for proto in node_protocols(node):
                pair = (proto, node["listen"])
                if pair in ports:
                    raise RelayError(f"节点端口重复：{proto}/{node['listen']}")
                ports.add(pair)
    return state


def pem(path, private=False):
    value = pathlib.Path(path).read_text()
    expected = "PRIVATE KEY-----" if private else "-----BEGIN CERTIFICATE-----"
    if len(value) > 1024 * 1024 or expected not in value:
        raise RelayError("证书或私钥不是有效 PEM 文件。")
    return value.splitlines()


def xray_config(node):
    opts, keys, kind = node["options"], node["secrets"], node["kind"]
    inbound = {"tag": node["name"], "listen": opts.get("bind", "0.0.0.0"), "port": node["listen"]}
    if kind in ("ss2022", "shadowsocks"):
        inbound.update(protocol="shadowsocks", settings={"method": SS_METHOD if kind == "ss2022" else opts.get("method", "aes-256-gcm"),
                                                       "password": keys["password"], "network": "tcp,udp"})
    elif kind == "socks5":
        inbound.update(protocol="socks", settings={"auth": "password", "accounts": [
            {"user": node["name"], "pass": keys["password"]}], "udp": True})
    else:
        flow = "xtls-rprx-vision" if kind in ("reality", "vless-vision") else ""
        if kind == "trojan":
            inbound.update(protocol="trojan", settings={"clients": [{"password": keys["password"]}]})
        elif kind == "vmess-ws":
            inbound.update(protocol="vmess", settings={"clients": [{"id": keys["uuid"], "alterId": 0}]})
        else:
            client = {"id": keys["uuid"]}
            if flow:
                client["flow"] = flow
            inbound.update(protocol="vless", settings={"clients": [client],
                            "decryption": keys.get("decryption", "none")})
        network = "ws" if kind.endswith("-ws") else "xhttp" if kind == "reality-xhttp" else "raw"
        stream = {"network": network}
        if network in ("ws", "xhttp"):
            stream[network + "Settings"] = {"path": opts.get("path", "/relay")}
            if network == "xhttp":
                stream["xhttpSettings"]["mode"] = "auto"
        if kind.startswith("reality"):
            stream.update(security="reality", realitySettings={
                "show": False, "target": opts["sni"] + ":443", "xver": 0, "serverNames": [opts["sni"]],
                "privateKey": keys["private"], "shortIds": [keys["short_id"]]})
        elif PROTOCOLS[kind][3] or opts.get("tls"):
            stream.update(security="tls", tlsSettings={"certificates": [
                {"certificate": pem(opts["cert"]), "key": pem(opts["key"], True)}]})
        else:
            stream["security"] = "none"
        inbound["streamSettings"] = stream
        if opts.get("fallback"):
            inbound["settings"]["fallbacks"] = [{"dest": "127.0.0.1:" + str(port(opts["fallback"]))}]
    return {"log": {"access": "none", "loglevel": "warning"}, "inbounds": [inbound],
            "outbounds": [{"protocol": "freedom"}]}


def sing_config(node):
    opts, keys, kind = node["options"], node["secrets"], node["kind"]
    inbound = {"type": kind, "tag": node["name"], "listen": opts.get("bind", "0.0.0.0"),
               "listen_port": node["listen"], "tls": {"enabled": True, "server_name": opts["sni"],
               "certificate": pem(opts["cert"]), "key": pem(opts["key"], True)}}
    if kind == "naive":
        inbound["users"] = [{"username": node["name"], "password": keys["password"]}]
    else:
        user = {"name": node["name"], "password": keys["password"]}
        if kind == "tuic":
            user["uuid"] = keys["uuid"]
            inbound.update(congestion_control="bbr", zero_rtt_handshake=False)
            inbound["tls"]["alpn"] = ["h3"]
        inbound["users"] = [user]
    if kind == "hysteria2":
        for key in ("up_mbps", "down_mbps"):
            if key in opts:
                inbound[key] = opts[key]
        inbound["tls"]["alpn"] = ["h3"]
    return {"log": {"level": "warn"}, "inbounds": [inbound], "outbounds": [{"type": "direct"}]}


def snell_config(node):
    opts, keys = node["options"], node["secrets"]
    bind = opts.get("bind", "0.0.0.0")
    bind = f"[{bind}]" if ":" in bind else bind
    lines = ["[snell-server]", f"listen = {bind}:{node['listen']}", f"psk = {keys['password']}", "tfo = true"]
    if node["kind"] == "snell6":
        lines.append("mode = " + opts.get("mode", "default"))
    elif opts.get("obfs") == "http":
        lines.append("obfs = http")
    if opts.get("dns"):
        lines.append("dns = " + opts["dns"])
    return "\n".join(lines) + "\n"


def node_link(node, title=None):
    opts, keys, kind = node["options"], node["secrets"], node["kind"]
    address = f"[{node['address']}]" if ":" in node["address"] else node["address"]
    endpoint = f"{address}:{node['listen']}"
    quote = lambda text: urllib.parse.quote(str(text), safe="")
    title = title or node["name"]
    label, password = quote(title), quote(keys["password"])
    sni = opts.get("sni", node["address"])
    if kind.startswith("snell"):
        version = kind[-1]
        result = f"{title} = snell, {node['address']}, {node['listen']}, psk={keys['password']}, version={version}, tfo=true"
        if version == "6":
            result += ", mode=" + opts.get("mode", "default")
        elif opts.get("obfs") == "http":
            result += ", obfs=http"
        return result
    if kind in ("ss2022", "shadowsocks"):
        method = SS_METHOD if kind == "ss2022" else opts.get("method", "aes-256-gcm")
        return f"ss://{method}:{password}@{endpoint}#{label}"
    if kind == "socks5":
        return f"socks5://{quote(node['name'])}:{password}@{endpoint}#{label}"
    if kind == "naive":
        return f"naive+https://{quote(node['name'])}:{password}@{endpoint}#{label}"
    if kind == "vmess-ws":
        value = {"v": "2", "ps": title, "add": node["address"], "port": str(node["listen"]),
                 "id": keys["uuid"], "aid": "0", "scy": "auto", "net": "ws", "type": "none",
                 "host": sni, "path": opts.get("path", "/relay"),
                 "tls": "tls" if opts.get("tls") else "", "sni": sni}
        return "vmess://" + base64.b64encode(json.dumps(value).encode()).decode()
    if kind in ("hysteria2", "anytls", "tuic", "trojan"):
        auth = f"{keys['uuid']}:{password}" if kind == "tuic" else password
        params = {"sni": sni}
        if kind == "tuic":
            params.update(congestion_control="bbr", alpn="h3")
        return f"{kind}://{auth}@{endpoint}?{urllib.parse.urlencode(params)}#{label}"
    params = {"encryption": keys.get("encryption", "none"), "type": "tcp"}
    if kind.startswith("reality"):
        params.update(security="reality", sni=sni, fp="chrome", pbk=keys["public"], sid=keys["short_id"])
        if kind == "reality-xhttp":
            params.update(type="xhttp", path=opts.get("path", "/relay"), mode="auto")
        else:
            params["flow"] = "xtls-rprx-vision"
    elif kind == "vless-encryption":
        params["security"] = "none"
    else:
        params.update(security="tls", sni=sni)
        if kind == "vless-ws":
            params.update(type="ws", host=sni, path=opts.get("path", "/relay"))
        else:
            params["flow"] = "xtls-rprx-vision"
    return f"vless://{keys['uuid']}@{endpoint}?{urllib.parse.urlencode(params)}#{label}"


def relayed(node, address, listen=None):
    """The node as clients reach it through a relay entry such as Po0: same protocol, new endpoint."""
    if node["kind"] == "naive":
        raise RelayError("NaiveProxy 会校验证书域名，不能改用中转 IP；请把域名解析到中转机后使用原链接。")
    via = copy.deepcopy(node)
    via["options"].setdefault("sni", node["address"])
    via.update(address=host(address), listen=port(listen or node["listen"]))
    return via


class NodeManager(Manager):
    def __init__(self, root="/"):
        super().__init__(root)
        self.state_file = self.directory / "nodes.json"
        self.runtime = self.directory / "nodes"

    def load(self):
        return validate_nodes(json.loads(self.state_file.read_text())) if self.state_file.exists() else {"nodes": []}

    def reserved_ports(self):
        path = self.directory / "forward.json"
        if not path.exists():
            return set()
        state = validate_state(json.loads(path.read_text()))
        return {(proto, rule["listen"]) for rule in active_rules(state) for proto in protocols(rule)}

    def owned_listener_pids(self):
        pids = set()
        for node in self.load()["nodes"]:
            if node["enabled"]:
                pid = run("systemctl", "show", "-p", "MainPID", "--value", self.unit(node), check=False).stdout.strip()
                if pid.isdigit() and int(pid):
                    pids.add(pid)
        return pids

    @staticmethod
    def forwarding_shape(state):
        return {"rules": [{"proto": "both" if len(node_protocols(n)) == 2 else node_protocols(n)[0],
                           "listen": n["listen"], "enabled": n["enabled"]} for n in state["nodes"]]}

    @staticmethod
    def unit(node):
        return f"relay-node-{node['name']}.service"

    def binary(self, core):
        return self.library / (core + "-" + CORE_VERSIONS[core])

    def config_path(self, node):
        return self.runtime / (node["name"] + (".conf" if node["kind"].startswith("snell") else ".json"))

    def prepare(self):
        if not (self.root / "run/systemd/system").is_dir() or not shutil.which("apt-get"):
            raise RelayError("节点安装需要使用 systemd 的 Debian/Ubuntu。")
        missing = [name for name in ("ca-certificates", "iproute2")
                   if run("dpkg-query", "-W", "-f=" + "$" + "{Status}", name, check=False).stdout != "install ok installed"]
        if missing:
            print("安装依赖：" + ", ".join(missing), flush=True)
            run("apt-get", "update")
            run("apt-get", "install", "-y", *missing)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.directory.chmod(0o755)
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.runtime.chmod(0o700)

    def install_core(self, core, data=None):
        """Install a pinned core, downloading it unless an imported archive is given."""
        self.library.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.library.chmod(0o755)
        destination = self.binary(core)
        if data is None and (destination.is_file() and not destination.is_symlink() and
                             (core != "sing-box" or (self.library / "libcronet.so").is_file())):
            return
        arch = platform.machine()
        if arch not in ("x86_64", "aarch64"):
            raise RelayError("固定节点核心支持 x86_64 / aarch64。")
        arm, version = arch == "aarch64", CORE_VERSIONS[core]
        stem = f"sing-box-{version}-linux-" + ("arm64" if arm else "amd64")
        member = {"xray": "xray", "sing-box": stem + "/sing-box"}.get(core, "snell-server")
        if data is None:
            print(f"下载官方 {core} {version} 并校验 SHA-256。", flush=True)
            data = download_verified(core_url(core, arch), CORE_DIGESTS[core][int(arm)], 128 * 1024 * 1024)
        if core == "sing-box":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                item = archive.getmember(member)
                if not item.isfile() or item.size > 256 * 1024 * 1024:
                    raise RelayError("核心压缩包格式错误。")
                binary = archive.extractfile(item).read()
                library_item = archive.getmember(stem + "/libcronet.so")
                if not library_item.isfile() or library_item.size > 256 * 1024 * 1024:
                    raise RelayError("Cronet 运行库格式错误。")
                atomic_write(self.library / "libcronet.so", archive.extractfile(library_item).read(), 0o644)
        else:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                item = archive.getinfo(member)
                if item.is_dir() or item.file_size > 256 * 1024 * 1024:
                    raise RelayError("核心压缩包格式错误。")
                binary = archive.read(item)
        atomic_write(destination, binary, 0o755)

    def import_archive(self, path):
        """Install a pinned runtime from an uploaded official archive; returns its name and version."""
        path = pathlib.Path(path)
        if not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
            raise RelayError(f"找不到文件，或文件超过 256 MB：{path}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        match = next((asset for asset in official_assets() if asset[4] == digest), None)
        if not match:
            raise RelayError(f"{path.name} 不是 Relay Kit 固定版本的官方压缩包（SHA-256 不匹配），未导入。")
        core, version, machine = match[:3]
        if machine != platform.machine():
            raise RelayError(f"{path.name} 是 {machine} 版本，本机是 {platform.machine()}。")
        if core == "realm":
            self.install_realm(data)
        else:
            self.install_core(core, data)
        return f"{core} {version}"

    def cores(self):
        """(name, version, installed) for every pinned runtime."""
        return [("realm", REALM_VERSION, self.realm.is_file())] + [
            (core, version, self.binary(core).is_file()) for core, version in CORE_VERSIONS.items()]

    def render(self, node):
        core = PROTOCOLS[node["kind"]][1]
        if core.startswith("snell"):
            return snell_config(node)
        return json_text(xray_config(node) if core == "xray" else sing_config(node))

    def check(self, node, filename):
        core = PROTOCOLS[node["kind"]][1]
        if core == "xray":
            run(self.binary(core), "run", "-test", "-format", "json", "-config", filename)
        elif core == "sing-box":
            run(self.binary(core), "check", "-c", filename)
        # Snell has no offline validation command. Its startup and listener are
        # checked before the transaction is committed.

    def service_text(self, node, filename):
        core = PROTOCOLS[node["kind"]][1]
        args = "run -format json -config" if core == "xray" else "run -c" if core == "sing-box" else "-c"
        return (
            "# Relay Kit managed node\n[Unit]\nDescription=Relay Kit node " + node["name"] +
            "\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\n"
            f"LoadCredential=config.json:{filename}\nExecStart={self.binary(core)} {args} %d/config.json\n"
            "DynamicUser=yes\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=yes\n"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
            "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nLimitNOFILE=65536\n"
            "\n[Install]\nWantedBy=multi-user.target\n")

    def wait_node(self, node):
        for _ in range(50):
            pid = run("systemctl", "show", "-p", "MainPID", "--value", self.unit(node)).stdout.strip()
            if pid.isdigit() and int(pid) > 0 and all(
                    f"pid={pid}," in run("ss", "-H", "-lntp" if proto == "tcp" else "-lnup",
                    f"sport = :{node['listen']}").stdout for proto in listener_protocols(node)):
                return
            time.sleep(0.1)
        raise RelayError(f"{node['name']} 未建立全部监听端口，已触发回退。")

    def sync(self, state):
        wanted = {self.unit(n) for n in state["nodes"] if n["enabled"]}
        for path in self.units.glob("relay-node-*.service"):
            if path.name not in wanted and path.read_text().startswith("# Relay Kit managed node\n"):
                run("systemctl", "disable", "--now", path.name)
        changed = []
        for node in state["nodes"]:
            if not node["enabled"]:
                continue
            filename = self.config_path(node)
            unit_path = self.units / self.unit(node)
            if unit_path.exists() and not unit_path.read_text().startswith("# Relay Kit managed node\n"):
                raise RelayError("检测到同名外部服务，拒绝覆盖。")
            config = self.render(node)
            service = self.service_text(node, filename)
            dirty = (not filename.exists() or filename.read_text() != config or
                     not unit_path.exists() or unit_path.read_text() != service)
            atomic_write(filename, config)
            atomic_write(unit_path, service, 0o644)
            changed.append((node, dirty))
        run("systemctl", "daemon-reload")
        for node, dirty in changed:
            if dirty or run("systemctl", "is-active", "--quiet", self.unit(node), check=False).returncode:
                run("systemctl", "restart", self.unit(node))
            self.wait_node(node)
            run("systemctl", "enable", self.unit(node))

    def commit(self, state):
        validate_nodes(state)
        previous = self.load()
        self.check_ports(self.forwarding_shape(state), self.forwarding_shape(previous))
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix=".check-", dir=self.runtime) as temporary:
            for node in state["nodes"]:
                if node["enabled"]:
                    filename = pathlib.Path(temporary) / self.config_path(node).name
                    atomic_write(filename, self.render(node))
                    self.check(node, filename)
        atomic_write(self.directory / "nodes.json.bak", json_text(previous))
        try:
            self.sync(state)
            atomic_write(self.state_file, json_text(state))
        except BaseException as error:
            try:
                self.sync(previous)
            except Exception as rollback:
                raise RelayError(f"节点应用失败：{error}\n回退也失败：{rollback}") from error
            raise
        existing = {node["name"] for node in state["nodes"]}
        for node in previous["nodes"]:
            if node["name"] not in existing:
                self.config_path(node).unlink(missing_ok=True)
                (self.units / self.unit(node)).unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        apply_firewall(self.root)

    def new_secrets(self, kind):
        values = {"uuid": str(uuid.uuid4()), "password": secrets.token_urlsafe(24)}
        if kind == "ss2022":
            values["password"] = base64.b64encode(secrets.token_bytes(16)).decode()
        if kind.startswith("snell"):
            values["password"] = secrets.token_hex(16)
        if kind.startswith("reality"):
            result = run(self.binary("xray"), "x25519").stdout
            private = re.search(r"^PrivateKey:\s*(\S+)$", result, re.M)
            public = re.search(r"^(?:Password \(PublicKey\)|PublicKey|Password):\s*(\S+)$", result, re.M)
            if not private or not public:
                raise RelayError("不能解析 REALITY 密钥生成结果。")
            values.update(private=private[1], public=public[1], short_id=secrets.token_hex(8))
        if kind == "vless-encryption":
            result = run(self.binary("xray"), "vlessenc").stdout
            pairs = re.findall(r'"(decryption|encryption)":\s*"([^"]+)"', result)
            if len(pairs) < 2 or pairs[0][0] != "decryption" or pairs[1][0] != "encryption":
                raise RelayError("不能解析 VLESS Encryption 密钥生成结果。")
            values.update(pairs[:2])
        return values

    def add(self, kind, name, listen, address, options=None):
        if kind not in PROTOCOLS:
            raise RelayError("不支持的节点协议。")
        state = self.load()
        if any(node["name"] == name for node in state["nodes"]):
            raise RelayError("节点名称已存在。")
        node = {"name": valid_name(name), "kind": kind, "listen": port(listen), "address": host(address),
                "enabled": True, "options": options or {}, "secrets": {}}
        self.check_ports(self.forwarding_shape({"nodes": [node]}), self.forwarding_shape(state))
        self.prepare()
        self.install_core(PROTOCOLS[kind][1])
        node["secrets"] = self.new_secrets(kind)
        state["nodes"].append(node)
        self.commit(state)
        return node

    def change(self, action, name, changes=None):
        state = copy.deepcopy(self.load())
        node = next((n for n in state["nodes"] if n["name"] == name), None)
        if not node:
            raise RelayError(f"未找到节点：{name}")
        if action == "del":
            state["nodes"].remove(node)
        elif action == "set":
            changes = dict(changes or {})
            if changes.pop("rotate", False):
                node["secrets"] = self.new_secrets(node["kind"])
            for key in ("listen", "address"):
                if key in changes:
                    node[key] = port(changes.pop(key)) if key == "listen" else host(changes.pop(key))
            node["options"].update(changes)
        else:
            node["enabled"] = action == "enable"
        self.commit(state)


def show_nodes(state):
    if not state["nodes"]:
        print("暂无节点。")
    for node in state["nodes"]:
        print(f"{node['name']:<16} {PROTOCOLS[node['kind']][0]:<25} "
              f"{node['address']}:{node['listen']}  {'启用' if node['enabled'] else '停用'}")
