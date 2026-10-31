import base64
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("relay", ROOT / "relay.py")
relay = importlib.util.module_from_spec(spec)
sys.modules["relay"] = relay
spec.loader.exec_module(relay)
import nodes
import menu


def rule(**changes):
    value = dict(name="demo", proto="both", listen=20000, host="198.19.0.2", remote=30000, enabled=True)
    value.update(changes)
    return value


def state(engine="nft"):
    return dict(engine=engine, rules=[rule()])


def ss_node(**changes):
    value = dict(name="demo", kind="ss2022", listen=20001, address="server.example.org",
                 enabled=True, options={}, secrets={
                     "uuid": "a8a2bc52-04b3-4490-84b3-d94b9c916a50",
                     "password": base64.b64encode(b"\xfa" * 16).decode()})
    if "password" in changes:
        value["secrets"]["password"] = changes.pop("password")
    value.update(changes)
    return value


def ok(*args, **kwargs):
    return subprocess.CompletedProcess(args, 0, "", "")


class ValidationTests(unittest.TestCase):
    def test_untrusted_target_cannot_inject_nft(self):
        for value in ("1.2.3.4; flush ruleset", "127.0.0.1", "0.0.0.0", "::1", "foo\nbar", "256.1.1.1"):
            with self.subTest(value=value), self.assertRaises(relay.RelayError):
                relay.validate_state(dict(engine="nft", rules=[rule(host=value)]))

    def test_protocol_collisions_and_disabled_rules(self):
        value = state()
        value["rules"].append(rule(name="second", proto="udp"))
        with self.assertRaises(relay.RelayError):
            relay.validate_state(value)
        value["rules"][1]["enabled"] = False
        relay.validate_state(value)

    def test_port_validation_and_duplicate_names(self):
        for value in (0, -1, 65536, "20000", True):
            with self.subTest(value=value), self.assertRaises(relay.RelayError):
                relay.validate_state(dict(engine="nft", rules=[rule(listen=value)]))
        with self.assertRaises(relay.RelayError):
            relay.validate_state(dict(engine="realm", rules=[rule(), rule(listen=20001)]))

    def test_realm_ipv6_and_udp_are_native(self):
        value = dict(engine="realm", rules=[rule(proto="udp", host="2001:db8::1")])
        endpoint = relay.realm_config(value)["endpoints"][0]
        self.assertEqual(endpoint["remote"], "[2001:db8::1]:30000")
        self.assertEqual(endpoint["network"], {"no_tcp": True, "use_udp": True})
        self.assertNotIn("udp://", json.dumps(endpoint))

    def test_nft_is_local_and_table_scoped(self):
        config = relay.nft_config(state())
        self.assertNotIn("flush ruleset", config)
        self.assertIn("fib daddr type local", config)
        self.assertIn("ct original proto-dst 20000", config)
        self.assertEqual(config.count("masquerade"), 2)
        self.assertIn("ct original proto-dst { 20000 } tcp flags & (syn | rst) == syn "
                      "tcp option maxseg size > 1452 counter tcp option maxseg size set 1452", config)
        self.assertNotIn("maxseg", relay.nft_config(dict(engine="nft", rules=[rule(proto="udp")])))

    def test_other_tables_forwarding_a_port_are_found(self):
        ruleset = ("table ip nat {\n\tchain prerouting {\n"
                   "\t\tmeta l4proto { tcp, udp } th dport 30001 dnat to 203.0.113.10:30001\n"
                   "\t\ttcp dport { 30002, 30010-30012 } counter packets 0 bytes 0 dnat to 203.0.113.11\n"
                   "\t\tip daddr . tcp dport { 1.2.3.4 . 30020 } dnat to 203.0.113.12\n"
                   "\t\tdnat ip to udp dport map { 30030 : 203.0.113.13 }\n"
                   "\t\ttcp dport 30040 accept\n\t}\n}\n"
                   "table ip relay_kit {\n\tchain prerouting {\n"
                   "\t\tfib daddr type local tcp dport 20000 counter dnat to 198.19.0.2:30000\n\t}\n}\n")
        found = {(proto, low, high) for proto, low, high, _ in relay.foreign_forwards(ruleset)}
        self.assertEqual(found, {("tcp", 30001, 30001), ("udp", 30001, 30001), ("tcp", 30002, 30002),
                                 ("tcp", 30010, 30012), ("udp", 30030, 30030)})

    def test_relay_link_keeps_protocol_and_credentials(self):
        node = dict(name="hk", kind="reality", listen=31234, address="203.0.113.10", enabled=True,
                    options={"sni": "www.example.com"},
                    secrets={"uuid": "a8a2bc52-04b3-4490-84b3-d94b9c916a50", "password": "p" * 24,
                             "private": "a" * 43, "public": "b" * 43, "short_id": "0" * 16})
        link = relay.node_link(relay.relayed(node, "198.51.100.1", 30001))
        self.assertTrue(link.startswith("vless://a8a2bc52-04b3-4490-84b3-d94b9c916a50@198.51.100.1:30001?"))
        self.assertIn("sni=www.example.com", link)
        self.assertEqual((node["address"], node["listen"]), ("203.0.113.10", 31234))
        vmess = relay.node_link(relay.relayed(dict(node, kind="vmess-ws", options={"path": "/p"}), "198.51.100.1"))
        fields = json.loads(base64.b64decode(vmess[len("vmess://"):]))
        self.assertEqual((fields["add"], fields["port"], fields["host"]), ("198.51.100.1", "31234", "203.0.113.10"))
        with self.assertRaises(relay.RelayError):
            relay.relayed(dict(node, kind="naive"), "198.51.100.1")

    def test_downloads_fall_back_to_mirrors_but_never_to_other_content(self):
        good = b"official archive"
        digest = relay.hashlib.sha256(good).hexdigest()
        url = "https://github.com/owner/repo/releases/download/v1/file.zip"
        tried = []

        def fetch(source, limit):
            tried.append(source)
            if source == url:
                raise relay.urllib.error.URLError("timed out")
            return b"tampered" if "ghfast" in source else good
        with mock.patch.object(relay, "fetch", side_effect=fetch), contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.dict(relay.os.environ, {}, clear=False):
            relay.os.environ.pop("RELAY_KIT_MIRRORS", None)
            self.assertEqual(relay.download_verified(url, digest), good)
            self.assertEqual(tried, [url, "https://ghfast.top/" + url, "https://gh-proxy.com/" + url])
            tried.clear()
            with mock.patch.dict(relay.os.environ, {"RELAY_KIT_MIRRORS": ""}):
                with self.assertRaisesRegex(relay.RelayError, "sudo relay core import"):
                    relay.download_verified(url, digest)
            self.assertEqual(tried, [url])
            tried.clear()
            with self.assertRaises(relay.RelayError):
                relay.download_verified("https://dl.nssurge.com/snell/x.zip", "0" * 64)
            self.assertEqual(tried, ["https://dl.nssurge.com/snell/x.zip"])

    def test_offline_import_accepts_only_pinned_archives(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        manager = relay.NodeManager(temp.name)
        archive = pathlib.Path(temp.name) / "Xray-linux-64.zip"
        archive.write_bytes(b"pretend official zip")
        digest = relay.hashlib.sha256(archive.read_bytes()).hexdigest()
        machine = relay.platform.machine()
        other = "aarch64" if machine == "x86_64" else "x86_64"
        with mock.patch.object(nodes, "official_assets",
                               return_value=[("xray", "26.10.29", machine, "https://x/Xray-linux-64.zip", digest)]), \
                mock.patch.object(manager, "install_core") as install:
            self.assertEqual(manager.import_archive(archive), "xray 26.10.29")
        install.assert_called_once_with("xray", b"pretend official zip")
        with mock.patch.object(nodes, "official_assets",
                               return_value=[("xray", "26.10.29", other, "https://x/Xray.zip", digest)]):
            with self.assertRaisesRegex(relay.RelayError, other):
                manager.import_archive(archive)
        with self.assertRaisesRegex(relay.RelayError, "SHA-256"):
            manager.import_archive(archive)

    def test_forward_chains_that_drop_by_default_are_found(self):
        ruleset = ("table ip filter {\n\tchain FORWARD {\n"
                   "\t\ttype filter hook forward priority filter; policy drop;\n"
                   "\t\tcounter packets 0 bytes 0 jump DOCKER-USER\n\t}\n"
                   "\tchain DOCKER-USER {\n\t\tcounter packets 0 bytes 0 return\n\t}\n}\n"
                   "table inet firewalld {\n\tset blocked {\n\t\ttype ipv4_addr\n"
                   "\t\telements = { 192.0.2.1,\n\t\t\t     192.0.2.2 }\n\t}\n"
                   "\tchain filter_FORWARD {\n\t\ttype filter hook forward priority filter + 10; policy accept;\n"
                   "\t\tct state { established, related } accept\n"
                   "\t\treject with icmpx admin-prohibited\n\t}\n}\n"
                   "table inet open {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n"
                   "\t\tct state invalid drop\n\t}\n}\n"
                   "table ip relay_kit {\n\tchain forward {\n"
                   "\t\ttype filter hook forward priority mangle; policy drop;\n\t}\n}\n")
        self.assertEqual(relay.forward_blockers(ruleset), ["ip filter FORWARD", "inet firewalld filter_FORWARD"])

    def test_blocked_port_note(self):
        self.assertIn("443", relay.blocked_port_note(443, "30001"))
        self.assertIsNone(relay.blocked_port_note(30001, "abc", None))

    def test_ss2022_link_preserves_password(self):
        node = ss_node()
        parsed = relay.urllib.parse.urlsplit(relay.node_link(node))
        self.assertEqual(parsed.username, relay.SS_METHOD)
        self.assertEqual(relay.urllib.parse.unquote(parsed.password), node["secrets"]["password"])

    def test_invalid_key_is_rejected(self):
        for password in ("", "not-a-key", base64.b64encode(b"x" * 32).decode()):
            with self.subTest(password=password), self.assertRaises(relay.RelayError):
                relay.validate_nodes({"nodes": [ss_node(password=password)]})

    def test_download_digest_is_enforced(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.url = "https://example.org/file"
        response.read.return_value = b"tampered binary"
        with mock.patch.object(relay.urllib.request, "urlopen", return_value=response):
            with self.assertRaises(relay.RelayError):
                relay.download_verified(response.url, "0" * 64)


class Transactions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = relay.Manager(self.temp.name)
        relay.atomic_write(self.manager.state_file, relay.json_text(state()))
        self.commands = mock.patch.object(relay, "run", side_effect=ok)
        self.commands.start()
        self.addCleanup(self.commands.stop)
        patch = mock.patch.object(nodes, "run", side_effect=ok)
        patch.start()
        self.addCleanup(patch.stop)

    def test_failed_apply_restores_previous_state(self):
        old = self.manager.state_file.read_bytes()
        candidate = state()
        candidate["rules"][0]["remote"] = 31000
        applied = []
        def fail_once(value):
            applied.append(copy.deepcopy(value))
            if len(applied) == 1:
                raise relay.RelayError("simulated restart failure")
        with mock.patch.object(self.manager, "sync", side_effect=fail_once), self.assertRaises(relay.RelayError):
            self.manager.commit(candidate)
        self.assertEqual(self.manager.state_file.read_bytes(), old)
        self.assertEqual(applied[-1], state())
        self.assertEqual(self.manager.state_file.stat().st_mode & 0o777, 0o600)

    def test_failed_validation_never_touches_runtime(self):
        with mock.patch.object(self.manager, "sync") as sync, self.assertRaises(relay.RelayError):
            self.manager.change("add", "bad", "tcp", "20000", "198.19.0.2", "30000")
        sync.assert_not_called()

    def test_ssh_listener_is_protected(self):
        for listen in (22, 2222):
            with mock.patch.dict(relay.os.environ, {"SSH_CONNECTION": "1.2.3.4 3000 2.3.4.5 2222"}):
                with self.assertRaises(relay.RelayError):
                    self.manager.check_ports(dict(engine="nft", rules=[rule(listen=listen)]), None)

    def test_foreign_listener_is_protected(self):
        with mock.patch.object(relay, "run", return_value=subprocess.CompletedProcess([], 0, "LISTEN", "")):
            with self.assertRaises(relay.RelayError):
                self.manager.check_ports(state(), None)

    def test_port_forwarded_by_another_table_is_refused(self):
        def execute(*args, **kwargs):
            listing = "table ip nat {\n chain prerouting {\n  tcp dport 20000 dnat to 1.2.3.4:5\n }\n}\n"
            return subprocess.CompletedProcess(args, 0, listing if args[:3] == ("nft", "list", "ruleset") else "", "")
        with mock.patch.object(relay, "run", side_effect=execute), \
                mock.patch.object(relay.shutil, "which", return_value="/usr/sbin/nft"):
            with self.assertRaisesRegex(relay.RelayError, "ip nat"):
                self.manager.check_ports(state(), None)
            self.manager.check_ports(state(), state())

    def test_nft_unit_follows_nftables_service_restarts(self):
        with mock.patch.object(relay, "run", side_effect=ok) as command:
            self.manager.write_units()
            self.manager.write_units()
        unit = (self.manager.units / relay.UNITS["nft"]).read_text()
        for line in ("PartOf=nftables.service", "ReloadPropagatedFrom=nftables.service",
                     "WantedBy=multi-user.target nftables.service"):
            self.assertIn(line, unit)
        self.assertNotIn("PartOf", (self.manager.units / relay.UNITS["realm"]).read_text())
        self.assertEqual(command.call_count, 1)

    def test_nodes_and_nft_cannot_claim_same_port(self):
        relay.atomic_write(self.manager.directory / "nodes.json",
                           relay.json_text({"nodes": [ss_node(listen=20000)]}))
        with self.assertRaises(relay.RelayError):
            self.manager.check_ports(state(), state())
        nodes = relay.NodeManager(self.temp.name)
        with self.assertRaises(relay.RelayError):
            nodes.check_ports(nodes.forwarding_shape({"nodes": [ss_node(listen=20000)]}), {"rules": []})

    def test_node_failure_rolls_back_private_state(self):
        nodes = relay.NodeManager(self.temp.name)
        previous = {"nodes": [ss_node()]}
        relay.atomic_write(nodes.state_file, relay.json_text(previous))
        candidate = copy.deepcopy(previous)
        candidate["nodes"][0]["enabled"] = False
        calls = []
        def fail_once(value):
            calls.append(copy.deepcopy(value))
            if len(calls) == 1:
                raise relay.RelayError("simulated node failure")
        with mock.patch.object(nodes, "sync", side_effect=fail_once), self.assertRaises(relay.RelayError):
            nodes.commit(candidate)
        self.assertEqual(nodes.load(), previous)
        self.assertEqual(calls[-1], previous)
        self.assertEqual((nodes.directory / "nodes.json.bak").stat().st_mode & 0o777, 0o600)


class MenuTests(unittest.TestCase):
    def test_all_menus_can_exit_without_install(self):
        for args, stdin in (([], "0\n"), (["nft"], "0\n"), (["realm"], "0\n"), (["node"], "0\n"),
                            ([], "1\n0\n2\n0\n3\n0\n4\n0\n5\n0\n0\n"), ([], "3\n")):
            result = subprocess.run(["bash", str(ROOT / "forward.sh"), *args], input=stdin,
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("下载官方", result.stdout)
            self.assertNotIn("Traceback", result.stderr)

    def test_version_and_bad_argument(self):
        result = subprocess.run(["bash", str(ROOT / "forward.sh"), "--version"], text=True, capture_output=True)
        self.assertEqual(result.stdout.strip(), "Relay Kit " + relay.VERSION)
        result = subprocess.run(["bash", str(ROOT / "forward.sh"), "nonsense"], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


class MenuFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = relay.Manager(self.temp.name)
        self.nodes = relay.NodeManager(self.temp.name)
        patches = [mock.patch.object(module, "run", side_effect=ok) for module in (relay, nodes, menu)]
        patches += [mock.patch.object(menu, "require_root"),
                    mock.patch.object(menu, "public_address", return_value="203.0.113.10"),
                    mock.patch.object(menu.secrets, "randbelow", return_value=1234)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def drive(self, function, *args, inputs):
        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=list(inputs)), contextlib.redirect_stdout(output):
            function(*args)
        return output.getvalue()

    def test_empty_node_actions_explain_what_to_do(self):
        output = self.drive(menu.node_menu, self.nodes, inputs=["2", "3", "4", "5", "6", "7", "8", "0"])
        self.assertEqual(output.count(menu.EMPTY_NODES), 7)
        self.assertNotIn("未找到节点", output)
        with self.assertRaisesRegex(relay.RelayError, "暂无节点"):
            relay.node_service_info(self.nodes, "status")

    def test_node_wizard_suggests_port_address_and_name(self):
        kinds = [kind for _, members in menu.NODE_GROUPS for kind, _ in members]
        created = []

        def add(kind, name, listen, address, options):
            created.append((kind, name, listen, address, options))
            return ss_node(name=name, listen=listen, address=address)
        with mock.patch.object(self.nodes, "add", side_effect=add):
            output = self.drive(menu.node_menu, self.nodes,
                                inputs=["1", str(kinds.index("ss2022") + 1), "", "", "", "0"])
        self.assertEqual(created, [("ss2022", "ss2022-11234", 11234, "203.0.113.10", {})])
        self.assertIn("ss://", output)

    def test_rule_wizard_rejects_busy_port_and_asks_again(self):
        relay.atomic_write(self.manager.state_file, relay.json_text(state()))
        with mock.patch.object(self.manager, "change") as change:
            output = self.drive(menu.forward_menu, self.manager, "nft",
                                inputs=["1", "", "20000", "", "198.19.0.9", "", "", "0"])
        change.assert_called_once_with("add", "fwd-11234", "both", 11234, "198.19.0.9", 11234)
        self.assertIn("端口 20000（TCP/UDP）已被占用", output)

    def test_blocked_ports_need_confirmation(self):
        relay.atomic_write(self.manager.state_file, relay.json_text(state()))
        with mock.patch.object(self.manager, "change") as change:
            output = self.drive(menu.forward_menu, self.manager, "nft",
                                inputs=["1", "", "443", "n", "", "198.19.0.9", "8443", "y", "", "0"])
        change.assert_called_once_with("add", "fwd-11234", "both", 11234, "198.19.0.9", 8443)
        self.assertEqual(output.count("默认双向封禁"), 2)

    def test_relay_entry_is_saved_and_shown(self):
        relay.atomic_write(self.nodes.state_file, relay.json_text({"nodes": [ss_node()]}))
        with mock.patch.object(self.nodes, "change") as change:
            output = self.drive(menu.node_menu, self.nodes, inputs=["3", "", "198.51.100.1", "", "", "0"])
        entry = {"address": "198.51.100.1", "port": 20001, "label": "中转1"}
        change.assert_called_once_with("set", "demo", {"relays": [entry]})
        self.assertIn("@198.51.100.1:20001#demo-%E4%B8%AD%E8%BD%AC1", output)
        self.assertIn("入口端口 20001 → server.example.org:20001", output)
        node = ss_node(options={"relays": [entry]})
        relay.validate_nodes({"nodes": [node]})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            menu.show_node(self.nodes, node, fresh=False)
        self.assertIn("@server.example.org:20001#demo", output.getvalue())
        self.assertIn("@198.51.100.1:20001#demo-", output.getvalue())

    def test_cli_saves_relay_entries(self):
        relay.atomic_write(self.nodes.state_file, relay.json_text({"nodes": [ss_node()]}))
        with mock.patch.object(relay, "NodeManager", return_value=self.nodes), \
                mock.patch.object(relay, "require_root"), mock.patch.object(self.nodes, "change") as change:
            relay.main(["node", "set", "demo", "--via", "198.51.100.1", "--via-port", "30001", "--via-label", "gz"])
        self.assertEqual(change.call_args.args[2]["relays"],
                         [{"address": "198.51.100.1", "port": 30001, "label": "gz"}])

    def test_relay_entries_are_validated(self):
        good = {"address": "198.51.100.1", "port": 30001, "label": "广州"}
        relay.validate_nodes({"nodes": [ss_node(options={"relays": [good]})]})
        for bad in ([dict(good, label="a b")], [dict(good, port="30001")], [dict(good, address="127.0.0.1")],
                    [dict(good, extra=1)], [good] * 9):
            with self.subTest(bad=bad), self.assertRaises(relay.RelayError):
                relay.validate_nodes({"nodes": [ss_node(options={"relays": bad})]})

    def test_core_screen_lists_runtimes_and_downloads(self):
        output = self.drive(menu.core_menu, self.nodes, inputs=["2", "0"])
        self.assertIn("ghfast.top", output)
        self.assertIn("https://github.com/XTLS/Xray-core/releases/download/", output)

    def test_switching_engine_needs_confirmation(self):
        relay.atomic_write(self.manager.state_file, relay.json_text(state()))
        with mock.patch.object(self.manager, "init") as init:
            output = self.drive(menu.forward_menu, self.manager, "realm", inputs=["n"])
        init.assert_not_called()
        self.assertIn("当前转发引擎是 nftables", output)

    def test_protocol_menu_lists_every_protocol_once(self):
        listed = [kind for _, members in menu.NODE_GROUPS for kind, _ in members]
        self.assertEqual(sorted(listed), sorted(nodes.PROTOCOLS))

    def test_every_protocol_has_a_detail_view(self):
        keys = {"uuid": "a8a2bc52-04b3-4490-84b3-d94b9c916a50", "password": "p" * 24, "private": "a" * 43,
                "public": "b" * 43, "short_id": "0" * 16,
                "encryption": "mlkem768x25519plus.native.0rtt." + "c" * 40,
                "decryption": "mlkem768x25519plus.native.600s." + "d" * 40}
        for kind in nodes.PROTOCOLS:
            with self.subTest(kind=kind):
                node = dict(name="n1", kind=kind, listen=443, address="203.0.113.10", enabled=True,
                            options={"sni": "example.org", "cert": "/c.pem", "key": "/k.pem"}, secrets=keys)
                self.assertTrue(dict(menu.node_fields(node))["端口"].startswith("443"))

    def test_wide_characters_are_aligned(self):
        self.assertEqual(menu.width("节点ab"), 6)
        self.assertEqual(menu.width(menu.pad("转发", 7)), 7)


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.calls, self.existing = [], set()
        self.status = {"ufw": "Status: inactive\n", "iptables": "-P INPUT ACCEPT\n"}

        def execute(*args, check=True, text=None):
            self.calls.append(args)
            output = ""
            if args[:2] == ("ufw", "status"):
                output = self.status["ufw"]
            elif args[:2] == ("ufw", "allow") and args[2] in self.existing:
                output = "Skipping adding existing rule\n"
            elif args[:3] == ("iptables", "-S", "INPUT"):
                output = self.status["iptables"]
            elif args[:3] == ("ip6tables", "-S", "INPUT"):
                output = "-P INPUT ACCEPT\n"
            elif args[0] in ("iptables", "ip6tables") and args[1] == "-C":
                return subprocess.CompletedProcess(args, 1, "", "")
            return subprocess.CompletedProcess(args, 0, output, "")
        for patch in (mock.patch.object(relay, "run", side_effect=execute),
                      mock.patch.object(relay.shutil, "which",
                                        side_effect=lambda name: None if name in ("netfilter-persistent", "firewall-cmd")
                                        else "/usr/sbin/" + name)):
            patch.start()
            self.addCleanup(patch.stop)

    def test_oracle_style_input_rules_get_accepts_before_the_reject(self):
        self.assertIsNone(relay.firewall_backend())
        self.status["iptables"] = ("-P INPUT ACCEPT\n-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                                   "-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\n"
                                   "-A INPUT -j REJECT --reject-with icmp-host-prohibited\n")
        self.assertEqual(relay.input_block("iptables"), 3)
        self.assertEqual(relay.firewall_backend(), "iptables")
        relay.firewall_allow("iptables", "tcp", 20001)
        self.assertIn(("iptables", "-I", "INPUT", "3", "-p", "tcp", "--dport", "20001", "-m", "comment",
                       "--comment", "relay-kit", "-j", "ACCEPT"), self.calls)
        self.assertFalse(any(call[:2] == ("ip6tables", "-I") for call in self.calls))

    def test_ufw_ports_follow_nodes_and_rules_users_had_stay(self):
        self.status["ufw"] = "Status: active\n"
        self.existing.add("20002/udp")
        state_file = relay.NodeManager(self.temp.name).state_file
        record = self.root / "etc/relay-kit/firewall.json"
        relay.atomic_write(state_file, relay.json_text({"nodes": [ss_node(), ss_node(name="two", listen=20002)]}))
        self.assertEqual(relay.sync_firewall(self.root), ["已在 ufw 放行 20001/tcp", "已在 ufw 放行 20002/tcp",
                                                          "已在 ufw 放行 20001/udp"])
        self.assertEqual(json.loads(record.read_text()),
                         {"backend": "ufw", "ports": [["tcp", 20001], ["tcp", 20002], ["udp", 20001]]})
        relay.atomic_write(state_file, relay.json_text({"nodes": []}))
        relay.sync_firewall(self.root)
        deleted = sorted(call[4] for call in self.calls if call[:4] == ("ufw", "--force", "delete", "allow"))
        self.assertEqual(deleted, ["20001/tcp", "20001/udp", "20002/tcp"])
        self.assertEqual(json.loads(record.read_text()), {"backend": None, "ports": []})


class UninstallTests(unittest.TestCase):
    def test_removes_only_what_relay_kit_owns(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        owned = {"etc/relay-kit/forward.json": relay.json_text(state()),
                 "etc/systemd/system/relay-node-demo.service": "# Relay Kit managed node\n[Unit]\n",
                 "etc/systemd/system/relay-kit-nft.service": "[Unit]\n",
                 "usr/local/lib/relay-kit/relay.py": '"""Relay Kit: core"""\n',
                 "usr/local/bin/relay": "#!/usr/bin/env bash\n" + relay.MARKER + "\n",
                 "etc/letsencrypt/renewal-hooks/deploy/relay-kit": "#!/bin/sh\n# Relay Kit certificate reload\n",
                 "etc/relay-kit/firewall.json": relay.json_text({"backend": "ufw", "ports": [["tcp", 20001]]})}
        foreign = {"etc/systemd/system/relay-node-other.service": "[Unit]\nDescription=other\n",
                   "etc/sysctl.d/99-relay-kit-bbr.conf": "net.ipv4.tcp_congestion_control=bbr\n"}
        for name, text in {**owned, **foreign}.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        with mock.patch.object(relay, "run", side_effect=ok) as command, \
                mock.patch.object(relay, "require_root"), \
                mock.patch.object(relay.shutil, "which", return_value="/usr/bin/true"), \
                contextlib.redirect_stdout(io.StringIO()):
            relay.uninstall(relay.Manager(temp.name))
        for name in owned:
            self.assertFalse((root / name).exists(), name)
        for name in foreign:
            self.assertTrue((root / name).exists(), name)
        command.assert_any_call("systemctl", "disable", "--now", "relay-node-demo.service", check=False)
        command.assert_any_call("ufw", "--force", "delete", "allow", "20001/tcp", check=False)
        self.assertNotIn(mock.call("systemctl", "disable", "--now", "relay-node-other.service", check=False),
                         command.call_args_list)


class BBRTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = relay.Manager(self.temp.name)
        self.values = {"net.core.default_qdisc": "fq_codel", "net.ipv4.tcp_congestion_control": "cubic",
                       "net.ipv4.tcp_available_congestion_control": "reno cubic bbr"}
        self.fail = False
        def execute(*args, **kwargs):
            if args[0:2] == ("sysctl", "-n"):
                return subprocess.CompletedProcess(args, 0, self.values[args[2]], "")
            if args[0:3] == ("sysctl", "-q", "-w"):
                key, value = args[3].split("=")
                if self.fail and value == "bbr":
                    raise relay.RelayError("kernel rejected bbr")
                self.values[key] = value
            return ok(*args, **kwargs)
        patch = mock.patch.object(relay, "run", side_effect=execute)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(relay, "require_root")
        patch.start()
        self.addCleanup(patch.stop)

    def test_enable_twice_then_restore_original_values(self):
        relay.bbr(self.manager, "on")
        relay.bbr(self.manager, "on")
        self.assertEqual(self.values["net.ipv4.tcp_congestion_control"], "bbr")
        relay.bbr(self.manager, "off")
        self.assertEqual(self.values["net.core.default_qdisc"], "fq_codel")
        self.assertEqual(self.values["net.ipv4.tcp_congestion_control"], "cubic")
        self.assertFalse((self.manager.root / "etc/sysctl.d/99-relay-kit-bbr.conf").exists())

    def test_failed_enable_restores_qdisc(self):
        self.fail = True
        with self.assertRaises(relay.RelayError):
            relay.bbr(self.manager, "on")
        self.assertEqual(self.values["net.core.default_qdisc"], "fq_codel")
        self.assertFalse((self.manager.root / "etc/sysctl.d/99-relay-kit-bbr.conf").exists())

    def test_unsupported_kernel_is_unchanged(self):
        self.values["net.ipv4.tcp_available_congestion_control"] = "reno cubic"
        with self.assertRaises(relay.RelayError):
            relay.bbr(self.manager, "on")
        self.assertFalse((self.manager.directory / "bbr.json").exists())


if __name__ == "__main__":
    unittest.main()
