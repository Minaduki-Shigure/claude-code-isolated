#!/usr/bin/env bash
set -euo pipefail
image=${1:?Usage: scan.sh IMAGE OUTPUT_BASENAME}
name=${2:?Usage: scan.sh IMAGE OUTPUT_BASENAME}
[[ "$name" =~ ^[a-z0-9-]+$ ]]
scanner=ghcr.io/aquasecurity/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969
mkdir -p dist
archive=$(mktemp -d)
trap 'rm -rf -- "$archive"' EXIT
docker image save --output "$archive/image.tar" "$image"

# Scan an archive. The scanner receives no Docker socket, registry credentials,
# workspace files, or user configuration. Keep a complete report including unfixed
# issues; block promotion when a HIGH/CRITICAL vulnerability has a published fix.
docker run --rm \
    --mount "type=bind,source=$archive,target=/input,readonly" \
    --mount "type=bind,source=$(pwd)/dist,target=/output" \
    "$scanner" image --input /input/image.tar \
    --scanners vuln --exit-code 0 --timeout 10m \
    --format json --output "/output/vulnerabilities-$name.json"
test -s "dist/vulnerabilities-$name.json"
jq '[.Results[]?.Vulnerabilities[]?] | group_by(.Severity) | map({severity: .[0].Severity, count: length})' \
    "dist/vulnerabilities-$name.json"
jq -e '[.Results[]?.Vulnerabilities[]?
    | select((.Severity == "CRITICAL" or .Severity == "HIGH") and (.FixedVersion // "") != "")]
    | length == 0' "dist/vulnerabilities-$name.json"
