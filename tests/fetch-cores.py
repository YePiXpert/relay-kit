"""Download the exact production runtimes into an ignored test directory."""
import io
import pathlib
import sys
import tarfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import relay
import nodes

directory = pathlib.Path(".test-tools/cores").resolve()
manager = nodes.NodeManager()
manager.library = directory
for core in nodes.CORE_VERSIONS:
    manager.install_core(core)
if not (directory / "realm").exists():
    arch, digest = relay.REALM_ASSETS[relay.platform.machine()]
    archive = relay.download_verified(
        f"https://github.com/zhboner/realm/releases/download/v{relay.REALM_VERSION}/realm-{arch}-unknown-linux-musl.tar.gz",
        digest)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as file:
        relay.atomic_write(directory / "realm", file.extractfile("realm").read(), 0o755)
