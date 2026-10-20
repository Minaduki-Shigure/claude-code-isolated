import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "upstream", Path(__file__).resolve().parents[1] / "scripts" / "upstream.py"
)
upstream = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upstream)


class ReleaseInputsTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "version": "2.1.304",
            "platforms": {
                platform: {"binary": "claude", "checksum": "a" * 64, "size": 12345}
                for platform in upstream.TARGETS.values()
            },
        }

    def test_signed_manifest_maps_architectures_to_fixed_official_urls(self):
        inputs = upstream.release_inputs("2.1.304", self.manifest)
        self.assertEqual(
            inputs["packages"]["amd64"]["url"],
            upstream.RELEASE_ROOT + "/2.1.304/linux-x64/claude",
        )
        self.assertEqual(
            inputs["packages"]["arm64"]["url"],
            upstream.RELEASE_ROOT + "/2.1.304/linux-arm64/claude",
        )

    def test_prerelease_traversal_and_unsupported_old_releases_are_rejected(self):
        for version in ("2.1.304-beta", "../../latest", "2.1.88", "2.1.284",
                        "latest", "2.1.304\nbad"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                upstream.validate_version(version)
        self.assertEqual(upstream.validate_version("2.1.285"), "2.1.285")

    def test_manifest_version_must_match_channel_resolution(self):
        with self.assertRaises(ValueError):
            upstream.release_inputs("2.1.305", self.manifest)

    def test_invalid_binary_checksum_or_size_is_rejected(self):
        for field, value in (("binary", "../claude"), ("checksum", "bad"),
                             ("size", True), ("size", -1), ("size", 2**40)):
            manifest = copy.deepcopy(self.manifest)
            manifest["platforms"]["linux-x64"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                upstream.release_inputs("2.1.304", manifest)

    def test_changed_lock_url_or_checksum_is_rejected(self):
        for field, value in (("url", "https://untrusted.example/claude"),
                             ("checksum", "b" * 64)):
            inputs = upstream.release_inputs("2.1.304", self.manifest)
            inputs["signing_fingerprint"] = upstream.SIGNING_FINGERPRINT
            inputs["packages"]["amd64"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                upstream.validate_lock(inputs, self.manifest)

    def test_base_must_be_digest_pinned_and_support_both_architectures(self):
        manifest = {
            "digest": "sha256:" + "c" * 64,
            "manifests": [
                {"platform": {"os": "linux", "architecture": arch}}
                for arch in upstream.TARGETS
            ],
        }
        self.assertEqual(
            upstream.locked_base("node:24-bookworm-slim", manifest),
            "node:24-bookworm-slim@sha256:" + "c" * 64,
        )
        manifest["manifests"].pop()
        with self.assertRaises(ValueError):
            upstream.locked_base("node:24-bookworm-slim", manifest)


if __name__ == "__main__":
    unittest.main()
