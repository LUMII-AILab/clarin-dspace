"""Verify OCI blobs and attestations before loading or publishing (frontend convention)."""
import hashlib
import json
from pathlib import Path
import re
import tarfile
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
def require(condition, message):
    if not condition: raise ValueError(message)

def inspect_archive(archive, expected_digest, evidence):
    """Verify reachable OCI blobs without extracting filesystem layers or executing code."""
    require(DIGEST.fullmatch(expected_digest), "Invalid expected digest")
    statements = []
    runtime = []
    visited = set()
    with tarfile.open(archive, "r:*") as bundle:
        members = {}
        for member in bundle.getmembers():
            name = member.name.removeprefix("./")
            require(not member.issym() and not member.islnk(), "Archive links forbidden")
            require(member.isfile() or member.isdir(), "Archive special files forbidden")
            require(not name.startswith("/") and ".." not in Path(name).parts,
                    "Unsafe archive member")
            if member.isfile():
                require(name in ("index.json", "oci-layout") or
                        re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name),
                        "Unexpected archive file")
                require(name not in members, "Duplicate archive member")
                members[name] = member

        def read_json(name):
            member = members[name]
            require(member.size < 20 * 1024 * 1024, "Oversized OCI metadata")
            return json.load(bundle.extractfile(member))

        def visit(descriptor):
            digest = descriptor["digest"]
            require(DIGEST.fullmatch(digest), "Unsupported blob digest")
            if digest in visited:
                return
            visited.add(digest)
            name = "blobs/sha256/" + digest.split(":")[1]
            member = members[name]
            require(member.size == descriptor["size"], "Blob size mismatch")
            with bundle.extractfile(member) as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == digest.split(":")[1],
                        "Blob digest mismatch")
            media = descriptor["mediaType"]
            if media.endswith("image.index.v1+json"):
                for child in read_json(name)["manifests"]:
                    visit(child)
            elif media.endswith("image.manifest.v1+json"):
                manifest = read_json(name)
                visit(manifest["config"])
                config = read_json("blobs/sha256/" + manifest["config"]["digest"].split(":")[1])
                if config.get("architecture") == "amd64" and config.get("os") == "linux":
                    runtime.append((digest, manifest["config"]["digest"], config))
                for layer in manifest["layers"]:
                    visit(layer)
            elif media == "application/vnd.in-toto+json":
                statements.append(read_json(name))

        index = read_json("index.json")
        require(len(index["manifests"]) == 1, "Expected one exported image/index")
        require(index["manifests"][0]["digest"] == expected_digest, "Build/export digest mismatch")
        visit(index["manifests"][0])
    require(len(runtime) == 1, "Expected one Linux amd64 runtime image")
    runtime_digest, config_digest, config = runtime[0]
    require(config["config"]["User"] == "1100:1100", "Wrong runtime user")
    require(config["config"]["Labels"]["org.opencontainers.image.revision"] ==
            json.loads((evidence / "inputs.json").read_text())["source_revision"], "Wrong backend source label")
    bound = [s for s in statements if any(
        sub.get("digest", {}).get("sha256") == runtime_digest.split(":")[1]
        for sub in s.get("subject", []))]
    require(any(s.get("predicateType", "").startswith("https://slsa.dev/provenance/")
                for s in bound), "Missing image-bound provenance")
    require(any(s.get("predicateType") == "https://spdx.dev/Document" for s in bound),
            "Missing image-bound SPDX SBOM")
    evidence.mkdir(parents=True, exist_ok=True)
    for number, statement in enumerate(bound):
        (evidence / f"attestation-{number}.json").write_text(json.dumps(statement, indent=2) + "\n")
    result = {"index_digest": expected_digest, "amd64_manifest_digest": runtime_digest,
              "source_revision": json.loads((evidence / "inputs.json").read_text())["source_revision"], "config_digest": config_digest,
              "verified_blobs": len(visited)}
    (evidence / "identity.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
