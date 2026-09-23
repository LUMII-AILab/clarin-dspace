#!/usr/bin/env bash
# Invoked only by an authorized image build, never by make check.
set -euo pipefail
archive=$(realpath "${1:?OCI archive required}")
evidence=$(realpath "${2:?Evidence directory required}")
recipe="$evidence/inputs.json"
scanner_url=$(jq -er .trivy_url "$recipe")
scanner_sha=$(jq -er .trivy_sha256 "$recipe")
scanner_dir=$(mktemp -d)
# Only remove the directory created by this invocation.
trap 'rm -rf -- "$scanner_dir"' EXIT
# The inspector rejects links, traversal and blob tampering before extraction.
expected_digest=$(jq -er .index_digest "$evidence/identity.json")
python3 ci/release/backend_image.py inspect "$archive" "$expected_digest" "$evidence"
mkdir "$scanner_dir/oci"
tar --no-same-owner --no-same-permissions -xf "$archive" -C "$scanner_dir/oci"
# Trivy accepts OCI directories, not OCI tar files. Point the scan-only index at
# the verified runtime manifest rather than relying on attestation/index order.
runtime_digest=$(jq -er .amd64_manifest_digest "$evidence/identity.json")
runtime_size=$(stat -c %s "$scanner_dir/oci/blobs/sha256/${runtime_digest#sha256:}")
jq -n --arg digest "$runtime_digest" --argjson size "$runtime_size" \
    '{schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json",
      digest: $digest, size: $size}]}' > "$scanner_dir/oci/index.json"
curl --fail --show-error --silent --location --retry 3 \
    --connect-timeout 20 --max-time 300 "$scanner_url" -o "$scanner_dir/trivy.tar.gz"
printf '%s  %s\n' "$scanner_sha" "$scanner_dir/trivy.tar.gz" | sha256sum -c -
tar -xzf "$scanner_dir/trivy.tar.gz" -C "$scanner_dir" trivy
"$scanner_dir/trivy" version > "$evidence/trivy-version.txt"
# Fresh DB per run: vulnerability knowledge must not be frozen at recipe creation.
# Vulnerabilities are evidence, not automatic acceptance. Scanner failures still fail the job.
"$scanner_dir/trivy" image --cache-dir "$scanner_dir/cache" --timeout 15m \
    --input "$scanner_dir/oci" --scanners vuln --format json --exit-code 0 \
    --output "$evidence/vulnerabilities.json"
"$scanner_dir/trivy" version --cache-dir "$scanner_dir/cache" \
    --format json > "$evidence/trivy-database.json"
test -s "$evidence/vulnerabilities.json"
