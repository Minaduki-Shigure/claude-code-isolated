#!/usr/bin/env python3
"""Lock and verify official Claude releases; image construction happens only in CI."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

RELEASE_ROOT = "https://downloads.claude.ai/claude-code-releases"
KEY_URL = "https://downloads.claude.ai/keys/claude-code.asc"
# Published in https://code.claude.com/docs/en/setup#verify-the-manifest-signature
SIGNING_FINGERPRINT = "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
BASE_TAGS = {
    "runtime_base": "docker.io/library/node:24-bookworm-slim",
    "gateway_base": "docker.io/library/debian:bookworm-slim",
    "go_base": "docker.io/library/golang:1-bookworm",
}
TARGETS = {"amd64": "linux-x64", "arm64": "linux-arm64"}
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
CHECKSUM = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
# Node 24's bundled npm (including npm 12.2.0) still ships these vulnerable
# transitive dependencies. Same-major official patch releases, pinned by npm SRI:
# CVE-2026-102276/102278, CVE-2026-19534 and CVE-2026-109869.
# Remove after upstream npm catches up.
NPM_SECURITY_PATCHES = {
    "brace-expansion": {
        "version": "5.0.12",
        "url": "https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.12.tgz",
        "integrity": "sha512-YovQ3rzhaLMIrDjNDMkNS01tea93qhEhG5xy8f6+R0l+dw3Ki+5sCoIoI942iuLZTHWogWktgwVDhU09iNEimQ==",
    },
    "undici": {
        "version": "6.29.1",
        "url": "https://registry.npmjs.org/undici/-/undici-6.29.1.tgz",
        "integrity": "sha512-EvRlUt/QqAEvXdQeRMYUfwOQsfzpDztykrG2owGEE/rBOBoYv9uF39ZzsNDh4lTFHhTr2XOZjKkYgueD12ZmGA==",
    },
}


def download(url, destination):
    subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
        "--connect-timeout", "20", "--max-time", "300",
        "--proto", "=https", "--proto-redir", "=https",
        "--output", str(destination), url,
    ], check=True)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_version(version):
    if not VERSION.fullmatch(version):
        raise ValueError("Expected a stable numeric Claude Code version")
    # Signed manifests begin at 2.1.89; our managed allowedProviders policy and
    # current no-persistence controls require the later supported baseline.
    if tuple(map(int, version.split("."))) < (2, 1, 285):
        raise ValueError("Require Claude Code >= 2.1.285 for the managed isolation policy")
    return version


def release_inputs(version, manifest):
    validate_version(version)
    if manifest.get("version") != version:
        raise ValueError("Manifest version does not match resolved version")
    packages = {}
    for arch, platform in TARGETS.items():
        item = manifest["platforms"][platform]
        if item.get("binary") != "claude" or not CHECKSUM.fullmatch(item.get("checksum", "")):
            raise ValueError(f"Invalid manifest asset for {platform}")
        size = item.get("size")
        if type(size) is not int or not 0 < size <= 1024 * 1024 * 1024:
            raise ValueError(f"Invalid manifest size for {platform}")
        packages[arch] = {
            "url": f"{RELEASE_ROOT}/{version}/{platform}/claude",
            "checksum": item["checksum"],
            "size": size,
        }
    return {"claude_version": version, "release_channel": "stable", "packages": packages}


def verify_manifest(directory):
    """Use a disposable keyring and require the documented key, never TOFU."""
    with tempfile.TemporaryDirectory(prefix="claude-release-keyring-") as keyring:
        os.chmod(keyring, 0o700)
        common = ["gpg", "--homedir", keyring, "--batch", "--no-tty", "--no-autostart"]
        listing = subprocess.check_output(
            common + ["--with-colons", "--import-options", "show-only", "--import",
                      str(directory / "release-key.asc")], text=True
        )
        fingerprints = [
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
        ]
        if not fingerprints or fingerprints[0] != SIGNING_FINGERPRINT:
            raise ValueError("Official release signing-key fingerprint changed")
        if sum(line.startswith("pub:") for line in listing.splitlines()) != 1:
            raise ValueError("Signing-key download contains unexpected extra primary keys")
        public_keyring = Path(keyring) / "release-key.gpg"
        subprocess.run(
            common + ["--output", str(public_keyring), "--dearmor",
                      str(directory / "release-key.asc")],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        verification = subprocess.run(
            common + ["--no-default-keyring", "--keyring", str(public_keyring),
                      "--status-fd", "1", "--verify",
                      str(directory / "manifest.json.sig"), str(directory / "manifest.json")],
            check=True, text=True, capture_output=True,
        )
        valid = [
            line.split() for line in verification.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ")
        ]
        # VALIDSIG contains signing key fingerprint, and may end in primary-key
        # fingerprint when the signer is a subkey. Pin to the documented primary.
        if len(valid) != 1 or SIGNING_FINGERPRINT not in (valid[0][2], valid[0][-1]):
            raise ValueError("Manifest was not signed by the pinned Anthropic key")
        if any(marker in verification.stdout for marker in (
            " EXPKEYSIG ", " EXPSIG ", " REVKEYSIG ", " BADSIG ", " ERRSIG "
        )):
            raise ValueError("Manifest signature is expired, revoked, or invalid")


def locked_base(tag, manifest):
    digest = manifest["digest"]
    if not DIGEST.fullmatch(digest):
        raise ValueError("Invalid base image digest")
    platforms = {
        (m.get("platform", {}).get("os"), m.get("platform", {}).get("architecture"))
        for m in manifest["manifests"]
    }
    if not {("linux", arch) for arch in TARGETS}.issubset(platforms):
        raise ValueError("Every base image must support both amd64 and arm64")
    return f"{tag}@{digest}"


def resolve(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    download(f"{RELEASE_ROOT}/stable", path.parent / "stable.txt")
    version = validate_version((path.parent / "stable.txt").read_text().strip())
    for name in ("manifest.json", "manifest.json.sig"):
        download(f"{RELEASE_ROOT}/{version}/{name}", path.parent / name)
    download(KEY_URL, path.parent / "release-key.asc")
    verify_manifest(path.parent)
    inputs = release_inputs(version, json.loads((path.parent / "manifest.json").read_text()))
    inputs["manifest_sha256"] = sha256(path.parent / "manifest.json")
    inputs["signing_fingerprint"] = SIGNING_FINGERPRINT
    inputs["npm_security_patches"] = NPM_SECURITY_PATCHES
    for key, tag in BASE_TAGS.items():
        manifest = json.loads(subprocess.check_output(
            ["docker", "buildx", "imagetools", "inspect", tag,
             "--format", "{{json .Manifest}}"], text=True, timeout=120
        ))
        inputs[key] = locked_base(tag, manifest)
    path.write_text(json.dumps(inputs, indent=2) + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            for key in (*BASE_TAGS, "claude_version"):
                output.write(f"{key}={inputs[key]}\n")
    print(f"Locked signed stable Claude Code {version} and three multi-architecture bases")


def validate_lock(inputs, manifest):
    expected = release_inputs(inputs["claude_version"], manifest)
    for key, value in expected.items():
        if inputs.get(key) != value:
            raise ValueError(f"Locked {key} does not match the signed manifest")
    if inputs.get("signing_fingerprint") != SIGNING_FINGERPRINT:
        raise ValueError("Unexpected pinned signing fingerprint")


def fetch(path, arch):
    inputs = json.loads(path.read_text())
    verify_manifest(path.parent)
    if sha256(path.parent / "manifest.json") != inputs.get("manifest_sha256"):
        raise ValueError("Manifest changed after input resolution")
    manifest = json.loads((path.parent / "manifest.json").read_text())
    validate_lock(inputs, manifest)
    asset = inputs["packages"][arch]
    destination = path.parent / "claude"
    download(asset["url"], destination)
    if destination.stat().st_size != asset["size"] or sha256(destination) != asset["checksum"]:
        destination.unlink()
        raise ValueError("Native binary size or SHA-256 does not match signed manifest")
    destination.chmod(0o755)
    fetch_npm_patches(path.parent / "npm-patches")
    print(f"Verified signed native Claude Code {inputs['claude_version']} for linux/{arch}")


def extract_npm_archive(archive, destination):
    """Extract only ordinary files/directories below package/, never links."""
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive, "r:gz") as package:
        for member in package.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != "package" or ".." in parts or "\\" in member.name:
                raise ValueError("Unsafe npm package path")
            if not member.isdir() and not member.isfile():
                raise ValueError("npm patch archive contains links or special files")
            target = destination.joinpath(*parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def fetch_npm_patches(destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name, asset in NPM_SECURITY_PATCHES.items():
        with tempfile.TemporaryDirectory(prefix="npm-security-patch-") as temp:
            archive = Path(temp) / "package.tgz"
            download(asset["url"], archive)
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
            if integrity != asset["integrity"]:
                raise ValueError(f"npm patch SRI mismatch: {name}")
            extract_npm_archive(archive, destination / name)
            metadata = json.loads((destination / name / "package.json").read_text())
            if metadata.get("name") != name or metadata.get("version") != asset["version"]:
                raise ValueError(f"npm patch package identity mismatch: {name}")


def apply_npm_patches(npm_root, patch_dir):
    records = {}
    for name, asset in NPM_SECURITY_PATCHES.items():
        target, patch = npm_root / "node_modules" / name, patch_dir / name
        if target.is_symlink() or not target.is_dir():
            raise ValueError(f"Unexpected bundled npm tree for {name}")
        current = json.loads((target / "package.json").read_text())
        fixed = json.loads((patch / "package.json").read_text())
        before = current.get("version", "")
        if current.get("name") != name or not VERSION.fullmatch(before):
            raise ValueError(f"Unexpected bundled npm package identity: {name}")
        if fixed.get("name") != name or fixed.get("version") != asset["version"]:
            raise ValueError(f"Invalid verified npm patch: {name}")
        have, wanted = tuple(map(int, before.split("."))), tuple(map(int, asset["version"].split(".")))
        if have[0] != wanted[0]:
            raise ValueError(f"npm changed {name} major version; review the security overlay")
        if have >= wanted:
            records[name] = {"before": before, "after": before, "action": "kept-newer-or-fixed"}
            continue
        if current.get("dependencies", {}) != fixed.get("dependencies", {}):
            raise ValueError(f"npm patch would change transitive requirements: {name}")
        # Any dependency-lock metadata must continue to describe the actual
        # installed bundle. Current official npm tarballs contain no lockfiles.
        for lock_path in (npm_root / "package-lock.json", npm_root / "npm-shrinkwrap.json",
                          npm_root / "node_modules" / ".package-lock.json"):
            if not lock_path.exists():
                continue
            lock = json.loads(lock_path.read_text())
            if lock.get("lockfileVersion") not in (1, 2, 3):
                raise ValueError("Unknown bundled npm lockfile format")
            entries = [
                lock.get("packages", {}).get(f"node_modules/{name}"),
                lock.get("dependencies", {}).get(name),
            ]
            for entry in entries:
                if entry is not None:
                    if entry.get("version") != before:
                        raise ValueError(f"Stale bundled npm lockfile for {name}")
                    entry.update(version=asset["version"], resolved=asset["url"],
                                 integrity=asset["integrity"])
            lock_path.write_text(json.dumps(lock, indent=2) + "\n")
        shutil.rmtree(target)
        shutil.copytree(patch, target)
        records[name] = {"before": before, "after": asset["version"], "action": "patched",
                         "integrity": asset["integrity"]}
    print(json.dumps(records, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("resolve", "fetch", "verify-manifest",
                                           "fetch-npm-patches", "apply-npm-patches"))
    parser.add_argument("--lock", type=Path, default=Path("dist/build-inputs.json"))
    parser.add_argument("--arch", choices=TARGETS)
    parser.add_argument("--patch-dir", type=Path, default=Path("dist/npm-patches"))
    parser.add_argument("--npm-root", type=Path, default=Path("/usr/local/lib/node_modules/npm"))
    args = parser.parse_args()
    if args.command == "resolve":
        resolve(args.lock)
    elif args.command == "verify-manifest":
        verify_manifest(args.lock.parent)
    elif args.command == "fetch-npm-patches":
        fetch_npm_patches(args.patch_dir)
    elif args.command == "apply-npm-patches":
        apply_npm_patches(args.npm_root, args.patch_dir)
    elif args.arch:
        fetch(args.lock, args.arch)
    else:
        parser.error("fetch requires --arch")
