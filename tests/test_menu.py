"""Menu tests never install an upstream engine or touch the host firewall."""

import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_script(*args, input_text="", command=None):
    return subprocess.run(
        command or ["bash", "forward.sh", *args],
        cwd=ROOT,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=10,
    )


class MenuTests(unittest.TestCase):
    def test_choose_both_engines_and_return_without_installation(self):
        result = run_script(input_text="1\n0\n2\n0\n0\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NFTABLES — arloor/nftables-nat-rust", result.stdout)
        self.assertIn("REALM — zywe03/realm-xwPF", result.stdout)
        self.assertNotIn("下载上游脚本", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_direct_engine_selection(self):
        for engine, label in [("nft", "NFTABLES"), ("realm", "REALM")]:
            with self.subTest(engine=engine):
                result = run_script(engine, input_text="0\n")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(label, result.stdout)

    def test_help_and_version(self):
        result = run_script("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--install", result.stdout)
        self.assertIn("Relay Kit 0.1.0", run_script("--version").stdout)

    def test_bad_argument_does_not_enter_menu(self):
        result = run_script("--unknown")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("请选择转发方式", result.stdout)

    def test_eof_does_not_loop(self):
        self.assertEqual(run_script().returncode, 0)

    def test_failed_download_never_runs_downloaded_content(self):
        # The stub writes valid shell code, then reports a download failure.
        # Even a syntactically valid partial download must never be executed.
        harness = r'''
source ./forward.sh
prepare_install() { return 0; }
uname() { printf 'x86_64\n'; }
curl() {
    local previous= arg
    for arg in "$@"; do
        if [[ $previous == --output ]]; then
            printf 'echo UNEXPECTED_EXECUTION\n' > "$arg"
        fi
        previous=$arg
    done
    return 22
}
main nft <<<'1
0'
'''
        result = run_script(command=["bash", "-c", harness])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("安装未完成", result.stderr)
        self.assertNotIn("UNEXPECTED_EXECUTION", result.stdout)


if __name__ == "__main__":
    unittest.main()
