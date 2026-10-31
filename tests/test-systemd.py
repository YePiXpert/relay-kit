"""Verify the production DynamicUser/LoadCredential service with real systemd."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import relay
import nodes


def main():
    identifier = "relay-kit-check-" + uuid.uuid4().hex[:12]
    directory = pathlib.Path(tempfile.mkdtemp(prefix=identifier, dir="/run"))
    directory.chmod(0o755)
    unit = pathlib.Path("/run/systemd/system") / (identifier + ".service")
    manager = nodes.NodeManager()
    manager.library = directory
    binary = manager.binary("xray")
    shutil.copyfile(ROOT / ".test-tools/cores" / binary.name, binary)
    binary.chmod(0o755)
    node = {"name": "check", "kind": "ss2022", "listen": 21000, "address": "192.0.2.1",
            "enabled": True, "options": {}, "secrets": manager.new_secrets("ss2022")}
    config = directory / "private.json"
    try:
        relay.atomic_write(config, relay.json_text(nodes.xray_config(node)))
        service = manager.service_text(node, config).replace("[Service]\n", "[Service]\nPrivateNetwork=yes\n")
        relay.atomic_write(unit, service, 0o644)
        relay.run("systemctl", "daemon-reload")
        relay.run("systemctl", "start", unit.name)
        pid = relay.run("systemctl", "show", "-p", "MainPID", "--value", unit.name).stdout.strip()
        assert int(pid) > 0
        for _ in range(50):
            output = relay.run("nsenter", "-t", pid, "-n", "ss", "-H", "-lnt").stdout
            if ":21000" in output:
                break
            time.sleep(.1)
        else:
            raise AssertionError("Xray did not listen under DynamicUser")
        user_line = next(line for line in pathlib.Path("/proc", pid, "status").read_text().splitlines() if line.startswith("Uid:"))
        assert int(user_line.split()[1]) != 0
        assert config.stat().st_mode & 0o777 == 0o600
        print("PASS real systemd, DynamicUser, private credential and isolated network listener")
    finally:
        subprocess.run(["systemctl", "stop", unit.name], capture_output=True)
        unit.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reset-failed", unit.name], capture_output=True)
        shutil.rmtree(directory)


if __name__ == "__main__":
    main()
