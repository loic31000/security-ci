#!/usr/bin/env python3
"""Fail-closed audit of exact dependency-manifest snapshots and CycloneDX evidence.

A checksum baseline detects unexpected resolver drift. It does NOT verify the
authenticity of third-party registries or make builds hermetic.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path

EXPECTED = ("python/requirements.txt", "node/package-lock.json", "go/go.mod", "go/go.sum")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    """Invalid, incomplete or unexpectedly changed dependency evidence."""


def verify_manifests(directory, baseline):
    if not isinstance(baseline, dict) or baseline.get("schema_version") != 1:
        raise EvidenceError("manifest baseline schema missing")
    expected = baseline.get("files")
    if not isinstance(expected, dict) or set(expected) != set(EXPECTED):
        raise EvidenceError("manifest baseline missing a required file or has unknown entries")
    hashes = {}
    base = Path(directory).resolve(strict=True)
    for name in EXPECTED:
        reference = expected[name]
        if not isinstance(reference, str) or not SHA256.fullmatch(reference):
            raise EvidenceError(f"bad SHA-256 baseline for {name}")
        path = base / name
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"missing or symlinked manifest: {name}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        hashes[name] = actual
        if actual != reference:
            raise EvidenceError(
                f"dependency drift in {name}: expected {reference}, actual {actual}; "
                "review and update the baseline only after auditing the new manifest"
            )
    return hashes


def verify_cyclonedx(document):
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise EvidenceError("invalid or missing CycloneDX SBOM")
    version = document.get("specVersion")
    if version not in ("1.4", "1.5", "1.6", "1.7"):
        raise EvidenceError("unrecognized CycloneDX spec version")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise EvidenceError("CycloneDX SBOM contains no components")
    names = set()
    for component in components:
        if not isinstance(component, dict) or not isinstance(component.get("name"), str):
            raise EvidenceError("CycloneDX component missing name")
        name = component["name"]
        if not name.strip() or component.get("type") not in ("application", "library", "framework", "file"):
            raise EvidenceError("CycloneDX component has invalid name or type")
        version = component.get("version")
        # CycloneDX permits unversioned application roots and local Go modules.
        if version is not None and (not isinstance(version, str) or not version.strip()):
            raise EvidenceError("CycloneDX component has invalid version")
        names.add(name)
    needed = set(EXPECTED) - {"go/go.sum"}
    if not needed.issubset(names):
        raise EvidenceError("CycloneDX missing one or more of the three audited root manifests")
    return len(components)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--directory", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--sbom", required=True)
    p.add_argument("--provenance", required=True)
    args = p.parse_args()
    try:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        hashes = verify_manifests(args.directory, baseline)
        sbom = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
        components = verify_cyclonedx(sbom)
        provenance = {
            "schema_version": 1,
            "repository_sha": os.environ.get("GITHUB_SHA", "unknown"),
            "reference_commit": baseline.get("reference_commit", "unknown"),
            "manifest_sha256": hashes,
            "sbom_component_count": components,
            "sbom_sha256": hashlib.sha256(Path(args.sbom).read_bytes()).hexdigest(),
            "note": "Evidence of checksums and inventory only; not signed provenance.",
        }
        Path(args.provenance).write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        print(f"Validated 4 unchanged dependency manifests, CycloneDX with {components} components")
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"::error::Engine dependency provenance validation failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
