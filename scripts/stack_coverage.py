#!/usr/bin/env python3
"""Map *actual* Trivy dependency targets to checked-in manifests.

Inventory coverage is not a statement about findings, vulnerable versions,
reachable code, or total language coverage. No manifest contents are read.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
from fnmatch import fnmatchcase

# (family, supported manifest filename pattern, exact Trivy analyzer type)
SUPPORTED = (
    ("go-modules", "go.mod", "gomod"),
    ("python-pip", "requirements.txt", "pip"),
    ("node-npm", "package-lock.json", "npm"),
    ("node-pnpm", "pnpm-lock.yaml", "pnpm"),
    ("java-maven", "pom.xml", "pom"),
    ("java-gradle", "*gradle.lockfile", "gradle"),
    ("rust-cargo", "Cargo.lock", "cargo"),
    ("ruby-bundler", "Gemfile.lock", "bundler"),
    ("php-composer", "composer.lock", "composer"),
)
# Only *manifest-only* hints. Never claim these are dependency coverage.
HINTS = (
    ("java-gradle", ("build.gradle", "build.gradle.kts")),
    ("rust-cargo", ("Cargo.toml",)),
    ("node-npm", ("package.json",)),
    ("dotnet-nuget", ("packages.lock.json", "*.csproj")),
)
SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "vendor", "dist",
    "build", "target", "coverage", ".next", "__pycache__", ".gradle",
})


class CoverageError(ValueError):
    pass


def normalized(value):
    if not isinstance(value, str) or not value.strip():
        raise CoverageError("Trivy target path missing")
    path = value.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    pure = PurePosixPath(path)
    if pure.is_absolute() or not path or any(p in ("", ".", "..") for p in path.split("/")):
        raise CoverageError("unsafe or malformed Trivy target path")
    if "://" in path or path.startswith("~") or (len(path) > 1 and path[1] == ":"):
        raise CoverageError("untrusted Trivy target path")
    return pure.as_posix()


def observed_targets(doc):
    if not isinstance(doc, dict) or type(doc.get("SchemaVersion")) is not int:
        raise CoverageError("Trivy JSON schema missing")
    records = doc.get("Results")
    if not isinstance(records, list):
        raise CoverageError("Trivy Results inventory absent or invalid")
    result = set()
    for row in records:
        if not isinstance(row, dict):
            raise CoverageError("malformed Trivy target record")
        path = normalized(row.get("Target"))
        typ = row.get("Type")
        if not isinstance(typ, str) or not typ:
            raise CoverageError("Trivy analyzer identity absent")
        cls = row.get("Class")
        if cls not in (None, "lang-pkgs", "config", "secret", "license"):
            raise CoverageError("unexpected Trivy result class")
        result.add((path, typ, cls))
    return result


def expected_manifests(root):
    base = Path(root)
    if not base.is_dir() or base.is_symlink():
        raise CoverageError("caller workspace is missing or symlinked")
    names = set()
    hints = set()
    for directory, subdirs, files in os.walk(base, followlinks=False):
        subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS
                      and not d.startswith(".audit-")
                      and not (Path(directory) / d).is_symlink()]
        for name in files:
            is_manifest = any(fnmatchcase(name, pattern) for _, pattern, _ in SUPPORTED)
            is_hint = (any(name in fs for _, fs in HINTS)
                       or (name.endswith(".csproj") and name != ".csproj"))
            if not (is_manifest or is_hint):
                continue
            file = Path(directory) / name
            if file.is_symlink():
                raise CoverageError("workspace includes a symlinked dependency manifest")
            rel = file.relative_to(base).as_posix()
            if is_manifest:
                names.add(rel)
            if is_hint:
                hints.add((rel, name))
    return names, hints


def summarize(workspace, inventory):
    found, hints = expected_manifests(workspace)
    observed = observed_targets(inventory)
    by_family = {}
    incomplete = False
    for family, pattern, typ in SUPPORTED:
        declared = {p for p in found if fnmatchcase(PurePosixPath(p).name, pattern)}
        scanned = {p for p in declared
                   if (p, typ, "lang-pkgs") in observed
        hint_present = any(
            any(name == candidate for candidate in files if not candidate.startswith("*"))
            for p, name in hints for fam, files in HINTS if fam == family
        )
        if declared:
            state = "SCANNED" if scanned == declared else "INCOMPLETE"
            incomplete |= state == "INCOMPLETE"
        else:
            state = "MANIFEST_ONLY" if hint_present else "NOT_APPLICABLE"
        by_family[family] = {
            "state": state,
            "declared_manifests": len(declared),
            "recognized_manifests": len(scanned),
        }

    # NuGet is not yet configured with a verified analyzer mapping.
    dotnet_hints = any(
        n == "packages.lock.json" or n.endswith(".csproj") for _, n in hints
    )
    by_family["dotnet-nuget"] = {
        "state": "UNVERIFIED" if dotnet_hints else "NOT_APPLICABLE",
        "declared_manifests": int(dotnet_hints),
        "recognized_manifests": 0,
    }
    return {
        "schema": 1,
        "status": "INCOMPLETE" if incomplete else "PASS",
        "scope": "dependency target recognition only, not language/code or vulnerability coverage",
        "families": by_family,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True, type=Path)
    p.add_argument("--inventory", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    try:
        data = summarize(args.workspace,
                         json.loads(args.inventory.read_text(encoding="utf-8")))
    except (OSError, TypeError, ValueError) as exc:
        data = {"schema": 1, "status": "ERROR", "reason": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(data, sort_keys=True))
    return 0 if data["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
