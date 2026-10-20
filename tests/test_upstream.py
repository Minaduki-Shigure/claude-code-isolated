import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
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


class NpmSecurityPatchTests(unittest.TestCase):
    def test_tarball_cannot_write_outside_package_or_create_links(self):
        for name, kind in (("package/../../escape", tarfile.REGTYPE),
                           ("package/link", tarfile.SYMTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with tarfile.open(root / "bad.tgz", "w:gz") as package:
                    info = tarfile.TarInfo(name)
                    info.type, info.linkname = kind, "/tmp/escape"
                    package.addfile(info)
                with self.assertRaises(ValueError):
                    upstream.extract_npm_archive(root / "bad.tgz", root / "out")
                self.assertFalse((root / "escape").exists())

    def tree(self, root, newer=False, wrong_deps=False):
        npm, patches = root / "npm", root / "patches"
        for name, asset in upstream.NPM_SECURITY_PATCHES.items():
            current, patch = npm / "node_modules" / name, patches / name
            current.mkdir(parents=True)
            patch.mkdir(parents=True)
            version = asset["version"] if newer else {"brace-expansion": "5.0.9", "undici": "6.28.0"}[name]
            if newer:
                version = ".".join(version.split(".")[:2] + ["999"])
            metadata = {"name": name, "version": version}
            (current / "package.json").write_text(json.dumps(metadata))
            metadata["version"] = asset["version"]
            if wrong_deps:
                metadata["dependencies"] = {"unexpected": "^1"}
            (patch / "package.json").write_text(json.dumps(metadata))
        return npm, patches

    def test_patches_installed_versions_and_lock_metadata_together(self):
        with tempfile.TemporaryDirectory() as temp:
            npm, patches = self.tree(Path(temp))
            lock = {"lockfileVersion": 3, "packages": {
                "node_modules/brace-expansion": {"version": "5.0.9"},
                "node_modules/undici": {"version": "6.28.0"},
            }}
            path = npm / "package-lock.json"
            path.write_text(json.dumps(lock))
            with contextlib.redirect_stdout(io.StringIO()):
                upstream.apply_npm_patches(npm, patches)
            lock = json.loads(path.read_text())
            for name, asset in upstream.NPM_SECURITY_PATCHES.items():
                installed = json.loads((npm / "node_modules" / name / "package.json").read_text())
                self.assertEqual(installed["version"], asset["version"])
                entry = lock["packages"]["node_modules/" + name]
                self.assertEqual(entry["version"], asset["version"])
                self.assertEqual(entry["integrity"], asset["integrity"])

    def test_newer_dependencies_are_never_downgraded(self):
        with tempfile.TemporaryDirectory() as temp:
            npm, patches = self.tree(Path(temp), newer=True)
            with contextlib.redirect_stdout(io.StringIO()):
                upstream.apply_npm_patches(npm, patches)
            for name in upstream.NPM_SECURITY_PATCHES:
                installed = json.loads((npm / "node_modules" / name / "package.json").read_text())
                self.assertTrue(installed["version"].endswith(".999"))

    def test_unexpected_dependency_graph_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            npm, patches = self.tree(Path(temp), wrong_deps=True)
            with self.assertRaisesRegex(ValueError, "transitive requirements"):
                upstream.apply_npm_patches(npm, patches)


if __name__ == "__main__":
    unittest.main()
