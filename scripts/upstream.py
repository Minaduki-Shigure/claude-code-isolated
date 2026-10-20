#!/usr/bin/env python3
"""Lock and verify official Claude releases; image construction happens only in CI."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
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
    print(f"Verified signed native Claude Code {inputs['claude_version']} for linux/{arch}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("resolve", "fetch", "verify-manifest"))
    parser.add_argument("--lock", type=Path, default=Path("dist/build-inputs.json"))
    parser.add_argument("--arch", choices=TARGETS)
    args = parser.parse_args()
    if args.command == "resolve":
        resolve(args.lock)
    elif args.command == "verify-manifest":
        verify_manifest(args.lock.parent)
    elif args.arch:
        fetch(args.lock, args.arch)
    else:
        parser.error("fetch requires --arch")
