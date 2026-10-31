import base64
import copy
import importlib.util
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
        for args, stdin in (([], "0\n"), (["nft"], "0\n"), (["realm"], "0\n"),
                            ([], "1\n0\n2\n0\n3\n0\n0\n")):
            result = subprocess.run(["bash", str(ROOT / "forward.sh"), *args], input=stdin,
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("下载", result.stdout)

    def test_version_and_bad_argument(self):
        result = subprocess.run(["bash", str(ROOT / "forward.sh"), "--version"], text=True, capture_output=True)
        self.assertEqual(result.stdout.strip(), "Relay Kit " + relay.VERSION)
        result = subprocess.run(["bash", str(ROOT / "forward.sh"), "nonsense"], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


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
