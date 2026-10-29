"""Exercise scan failures with fake Docker/sleep; no daemon or network is used."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
SCANNER = (
    "ghcr.io/aquasecurity/trivy@sha256:"
    "62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
)
IMAGE = "example.invalid/runtime@sha256:" + "a" * 64
FAKE_COMMAND = r'''
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["SCAN_TEST_ROOT"])
command = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps([command] + args) + "\n")
if command == "sleep":
    sys.exit(0)
if args[:2] == ["image", "inspect"]:
    sys.exit(0 if os.environ.get("SCAN_TEST_CACHED") == "1" else 1)
if args[:1] == ["pull"]:
    counter = root / "pull-count"
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    if count <= int(os.environ.get("SCAN_TEST_PULL_FAILURES", "0")):
        print("simulated GHCR token request timeout", file=sys.stderr)
        sys.exit(17)
    sys.exit(0)
if args[:2] == ["image", "save"]:
    Path(args[args.index("--output") + 1]).write_bytes(b"fake archive")
    sys.exit(0)
if args[:1] == ["run"]:
    code = int(os.environ.get("SCAN_TEST_RUN_EXIT", "0"))
    if code:
        sys.exit(code)
    if os.environ.get("SCAN_TEST_NO_REPORT") != "1":
        output_mount = next(a for a in args if "target=/output" in a)
        output_dir = next(p[7:] for p in output_mount.split(",") if p.startswith("source="))
        report = Path(output_dir) / Path(args[args.index("--output") + 1]).name
        report.write_text(os.environ["SCAN_TEST_REPORT"])
    sys.exit(0)
print("unexpected mock command: " + repr(args), file=sys.stderr)
sys.exit(99)
'''


@unittest.skipUnless(shutil.which("jq"), "scan.sh requires jq")
class ScannerDownloadTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="claude-scan-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("docker", "sleep"):
            command = self.bin / name
            command.write_text("#!" + sys.executable + "\n" + FAKE_COMMAND)
            command.chmod(0o755)
        self.environment = dict(os.environ)
        self.environment.update({
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "SCAN_TEST_ROOT": str(self.root),
            "SCAN_TEST_REPORT": json.dumps({"Results": [{"Vulnerabilities": []}]}),
        })

    def run_scan(self, **overrides):
        environment = dict(self.environment, **overrides)
        return subprocess.run(
            ["bash", str(REPOSITORY / "scripts/scan.sh"), IMAGE, "runtime"],
            cwd=self.root, env=environment, text=True, capture_output=True,
            timeout=10,
        )

    def calls(self, command=None):
        records = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        if command is None:
            return records
        return [record for record in records if record[:len(command)] == command]

    def assert_scanner_boundary(self):
        runs = self.calls(["docker", "run"])
        self.assertEqual(len(runs), 1)
        run = runs[0]
        self.assertIn(SCANNER, run)
        self.assertIn("--pull", run)
        self.assertEqual(run[run.index("--pull") + 1], "never")
        self.assertNotIn("--privileged", run)
        self.assertNotIn("--env", run)
        mounts = [run[i + 1] for i, arg in enumerate(run) if arg == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(any("target=/input,readonly" in mount for mount in mounts))
        self.assertTrue(any("target=/output" in mount for mount in mounts))
        self.assertFalse(any("docker.sock" in mount for mount in mounts))
        for pull in self.calls(["docker", "pull"]):
            self.assertEqual(pull, ["docker", "pull", SCANNER])
        saves = self.calls(["docker", "image", "save"])
        self.assertEqual(len(saves), 1)
        self.assertEqual(saves[0][-1], IMAGE)
        archive = Path(saves[0][saves[0].index("--output") + 1]).parent
        self.assertFalse(archive.exists(), "temporary archive must be removed")

    def test_transient_download_failures_recover_with_same_pinned_scanner(self):
        result = self.run_scan(SCAN_TEST_PULL_FAILURES="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls(["docker", "pull"])), 3)
        self.assertEqual(self.calls(["sleep"]), [["sleep", "5"], ["sleep", "10"]])
        self.assert_scanner_boundary()

    def test_persistent_download_failure_stops_after_three_attempts(self):
        result = self.run_scan(SCAN_TEST_PULL_FAILURES="99")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls(["docker", "pull"])), 3)
        self.assertEqual(self.calls(["sleep"]), [["sleep", "5"], ["sleep", "10"]])
        self.assertEqual(self.calls(["docker", "run"]), [])
        for pull in self.calls(["docker", "pull"]):
            self.assertEqual(pull, ["docker", "pull", SCANNER])

    def test_cached_scanner_requires_no_registry_request(self):
        result = self.run_scan(SCAN_TEST_CACHED="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(["docker", "pull"]), [])
        self.assertEqual(self.calls(["sleep"]), [])
        self.assert_scanner_boundary()

    def test_fixable_high_and_critical_findings_still_block_promotion(self):
        for severity in ("HIGH", "CRITICAL"):
            with self.subTest(severity=severity):
                (self.root / "calls.jsonl").unlink(missing_ok=True)
                report = {"Results": [{"Vulnerabilities": [
                    {"VulnerabilityID": "TEST-FIXABLE", "Severity": severity, "FixedVersion": "2"},
                ]}]}
                result = self.run_scan(SCAN_TEST_CACHED="1", SCAN_TEST_REPORT=json.dumps(report))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(["sleep"]), [])
                self.assert_scanner_boundary()
                saved = json.loads((self.root / "dist/vulnerabilities-runtime.json").read_text())
                self.assertEqual(saved, report, "retain the failing report for diagnosis")

    def test_unfixed_high_findings_remain_in_report_without_changing_gate(self):
        report = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "TEST-UNFIXED", "Severity": "HIGH"},
            {"VulnerabilityID": "TEST-MEDIUM", "Severity": "MEDIUM", "FixedVersion": "2"},
        ]}]}
        result = self.run_scan(SCAN_TEST_CACHED="1", SCAN_TEST_REPORT=json.dumps(report))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_scanner_boundary()
        saved = json.loads((self.root / "dist/vulnerabilities-runtime.json").read_text())
        self.assertEqual(saved, report)

    def test_scan_error_is_not_retried_or_replaced_by_stale_report(self):
        (self.root / "dist").mkdir()
        report = self.root / "dist/vulnerabilities-runtime.json"
        report.write_text(self.environment["SCAN_TEST_REPORT"])
        result = self.run_scan(SCAN_TEST_CACHED="1", SCAN_TEST_RUN_EXIT="23")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(self.calls(["sleep"]), [])
        self.assert_scanner_boundary()

    def test_success_without_new_report_cannot_reuse_stale_clean_report(self):
        (self.root / "dist").mkdir()
        (self.root / "dist/vulnerabilities-runtime.json").write_text(self.environment["SCAN_TEST_REPORT"])
        result = self.run_scan(SCAN_TEST_CACHED="1", SCAN_TEST_NO_REPORT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assert_scanner_boundary()

    def test_malformed_report_fails_without_retrying_scan(self):
        result = self.run_scan(SCAN_TEST_CACHED="1", SCAN_TEST_REPORT="not json")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(["sleep"]), [])
        self.assert_scanner_boundary()


if __name__ == "__main__":
    unittest.main()
