"""Real TCP/UDP forwarding and node protocol checks, inside fresh namespaces."""
import contextlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import relay
import nodes

CORES = ROOT / ".test-tools/cores"


def command(*args, text=None):
    result = subprocess.run([str(arg) for arg in args], input=text, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result.stdout


@contextlib.contextmanager
def process(args, log):
    with open(log, "w+") as file:
        child = subprocess.Popen([str(arg) for arg in args], stdout=file, stderr=subprocess.STDOUT)
        try:
            time.sleep(0.15)
            if child.poll() is not None:
                file.seek(0)
                raise AssertionError(file.read())
            yield child
        except BaseException:
            file.flush()
            file.seek(0)
            print("Process log:", file.read()[-6000:], file=sys.stderr)
            raise
        finally:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def probe(address, port, proto, expect=True):
    # Executed in a separate client namespace to exercise the actual ingress.
    code = """
import socket,sys,time
address,port,proto,expect=sys.argv[1:]
for attempt in range(5 if expect=='yes' else 1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect((address,int(port)))
            s.sendall(b'relay-test')
            assert s.recv(256)==b'11.0.0.1:relay-test'
        if expect=='no': raise AssertionError('unexpected connection')
        break
    except OSError:
        if expect=='no': break
        if attempt==29: raise
        time.sleep(.05)
"""
    command("ip", "netns", "exec", "relay-client", "python3", "-c", code,
            address, port, proto, "yes" if expect else "no")


def xray_client(node):
    kind, keys, opts = node["kind"], node["secrets"], node["options"]
    server = {"address": "198.18.0.1", "port": node["listen"]}
    outbound = {}
    if kind in ("ss2022", "shadowsocks"):
        server.update(method=nodes.SS_METHOD if kind == "ss2022" else "aes-256-gcm", password=keys["password"])
        outbound.update(protocol="shadowsocks", settings={"servers": [server]})
    elif kind == "socks5":
        server["users"] = [{"user": node["name"], "pass": keys["password"]}]
        outbound.update(protocol="socks", settings={"servers": [server]})
    elif kind == "trojan":
        server["password"] = keys["password"]
        outbound.update(protocol="trojan", settings={"servers": [server]})
    else:
        user = {"id": keys["uuid"]}
        if kind in ("reality", "vless-vision"):
            user["flow"] = "xtls-rprx-vision"
        user["encryption"] = keys.get("encryption", "none")
        server["users"] = [user]
        outbound.update(protocol="vmess" if kind == "vmess-ws" else "vless", settings={"vnext": [server]})
    if kind not in ("ss2022", "shadowsocks", "socks5"):
        network = "ws" if kind.endswith("-ws") else "xhttp" if kind == "reality-xhttp" else "raw"
        stream = {"network": network}
        if network in ("ws", "xhttp"):
            stream[network + "Settings"] = {"path": "/relay"}
        if kind.startswith("reality"):
            stream.update(security="reality", realitySettings={
                "serverName": "target.example", "fingerprint": "chrome", "password": keys["public"],
                "shortId": keys["short_id"]})
        elif nodes.PROTOCOLS[kind][3] or opts.get("tls"):
            # Test certificate is generated locally and trusted explicitly.
            stream.update(security="tls", tlsSettings={"serverName": "target.example",
                "certificates": [{"certificate": nodes.pem(opts["cert"]), "usage": "verify"}]})
        outbound["streamSettings"] = stream
    return {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1", "port": 31000,
            "protocol": "dokodemo-door", "settings": {"address": "11.0.0.2", "port": 30000, "network": "tcp,udp"}}],
            "outbounds": [outbound]}


def sing_client(node):
    kind, opts, keys = node["kind"], node["options"], node["secrets"]
    outbound = {"type": "snell" if kind.startswith("snell") else kind, "server": "198.18.0.1",
                "server_port": node["listen"]}
    if kind.startswith("snell"):
        outbound.update(version=6 if kind == "snell6" else 5, psk=keys["password"])
    else:
        outbound.update(password=keys["password"], tls={"enabled": True, "server_name": "target.example",
                         "certificate": nodes.pem(opts["cert"])})
        if kind == "tuic":
            outbound.update(uuid=keys["uuid"], congestion_control="bbr")
            outbound["tls"]["alpn"] = ["h3"]
        if kind == "naive":
            outbound["username"] = node["name"]
    return {"log": {"level": "warn"}, "inbounds": [{"type": "direct", "listen": "127.0.0.1",
            "listen_port": 31000, "override_address": "11.0.0.2", "override_port": 30000}],
            "outbounds": [outbound]}


def main():
    with tempfile.TemporaryDirectory(prefix="relay-net-") as temporary, contextlib.ExitStack() as stack:
        directory = pathlib.Path(temporary)
        echo = directory / "echo.py"
        echo.write_text("""
import selectors,socket
sel=selectors.DefaultSelector()
for proto,kind in [('tcp',socket.SOCK_STREAM),('udp',socket.SOCK_DGRAM)]:
    s=socket.socket(socket.AF_INET,kind)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('0.0.0.0',30000))
    if proto=='tcp': s.listen()
    sel.register(s,selectors.EVENT_READ,proto)
while True:
    for key,_ in sel.select():
        if key.data=='tcp':
            conn,addr=key.fileobj.accept()
            with conn:
                conn.settimeout(2)
                data=conn.recv(256)
                conn.sendall(addr[0].encode()+b':'+data)
        else:
            data,addr=key.fileobj.recvfrom(256)
            key.fileobj.sendto(addr[0].encode()+b':'+data,addr)
""")
        stack.enter_context(process(["ip", "netns", "exec", "relay-backend", "python3", echo], directory / "echo.log"))
        state = {"engine": "nft", "rules": [{"name": "test", "proto": "both", "listen": 20000,
                 "host": "11.0.0.2", "remote": 30000, "enabled": True}]}
        command("nft", "-f", "-", text="table inet unrelated {\n chain input {\n type filter hook input priority filter; policy accept;\n }\n}\n")
        unrelated = command("nft", "list", "table", "inet", "unrelated")
        command("sysctl", "-qw", "net.ipv4.ip_forward=1")
        command("nft", "--check", "-f", "-", text=relay.nft_config(state))
        for _ in range(2):
            command("nft", "-f", "-", text=relay.nft_config(state))
        for proto in ("tcp", "udp"):
            probe("198.18.0.1", 20000, proto)
        assert unrelated == command("nft", "list", "table", "inet", "unrelated")
        state["rules"] = []
        command("nft", "-f", "-", text=relay.nft_config(state))
        for proto in ("tcp", "udp"):
            probe("198.18.0.1", 20000, proto, expect=False)
        command("nft", "delete", "table", "ip", relay.TABLE)
        print("PASS nft TCP/UDP, source NAT, repeated apply, deletion and unrelated firewall preservation", flush=True)
        for mode in ("tcp", "udp", "both"):
            value = {"engine": "realm", "rules": [{"name": "test", "proto": mode, "listen": 20000,
                     "host": "11.0.0.2", "remote": 30000, "enabled": True}]}
            filename = directory / "realm.json"
            filename.write_text(relay.json_text(relay.realm_config(value)))
            with process([CORES / "realm", "-c", filename], directory / "realm.log"):
                for proto in ("tcp", "udp"):
                    probe("198.18.0.1", 20000, proto, expect=mode in (proto, "both"))
            print("PASS Realm " + mode, flush=True)
        cert, key = directory / "cert.pem", directory / "key.pem"
        command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                "-subj", "/CN=target.example", "-addext", "subjectAltName=DNS:target.example",
                "-keyout", key, "-out", cert)
        tls_server = directory / "tls.py"
        tls_server.write_text('''
import ssl,socketserver,sys
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version=ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[1],sys.argv[2])
ctx.set_alpn_protocols(['h2','http/1.1'])
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(3)
            with ctx.wrap_socket(self.request,server_side=True) as conn:
                conn.recv(4096)
        except (OSError,ssl.SSLError): pass
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
Server(('0.0.0.0',443),Handler).serve_forever()
''')
        stack.enter_context(process(["ip", "netns", "exec", "relay-backend", "python3",
                                    tls_server, cert, key], directory / "tls.log"))
        manager = nodes.NodeManager(temporary)
        manager.library = CORES
        for index, (kind, (_, core, transports, tls)) in enumerate(nodes.PROTOCOLS.items()):
            node = {"name": "test", "kind": kind, "listen": 21000 + index, "address": "198.18.0.1",
                    "enabled": True, "secrets": manager.new_secrets(kind),
                    "options": {"sni": "target.example", "cert": str(cert), "key": str(key)}}
            if kind == "naive":
                node["address"] = "target.example"
            nodes.validate_nodes({"nodes": [node]})
            filename = directory / "server.json"
            server_text = manager.render(node)
            if core == "xray":
                debug_config = json.loads(server_text)
                debug_config["log"]["loglevel"] = "debug"
                server_text = json.dumps(debug_config)
            filename.write_text(server_text)
            manager.check(node, filename)
            server_args = [manager.binary(core)]
            server_args += ["run", "-format", "json", "-config", filename] if core == "xray" else ["run", "-c", filename] if core == "sing-box" else ["-c", filename]
            with process(server_args, directory / (kind + ".log")) as server:
                for proto in nodes.listener_protocols(node):
                    for attempt in range(50):
                        output = command("ss", "-H", "-lntp" if proto == "tcp" else "-lnup", f"sport = :{node['listen']}")
                        if f"pid={server.pid}," in output:
                            break
                        time.sleep(0.1)
                    assert f"pid={server.pid}," in output, (kind, proto, output)
                client_file = directory / "client.json"
                client_core = "xray" if core == "xray" else "sing-box"
                client_file.write_text(relay.json_text(xray_client(node) if client_core == "xray" else sing_client(node)))
                with process(["ip", "netns", "exec", "relay-client", manager.binary(client_core),
                              "run", "-c", client_file], directory / (kind + "-client.log")):
                    probe("127.0.0.1", 31000, "tcp")
                    if kind in ("ss2022", "shadowsocks", "socks5", "hysteria2", "tuic", "snell4", "snell5", "snell6"):
                        probe("127.0.0.1", 31000, "udp")
            print("PASS node configuration, listener and proxy round trip: " + kind, flush=True)
        assert unrelated == command("nft", "list", "table", "inet", "unrelated")


if __name__ == "__main__":
    main()
