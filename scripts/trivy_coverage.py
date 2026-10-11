#!/usr/bin/env python3
"""Interpret the actual Trivy JSON target inventory, not just an empty SARIF."""
import json
from pathlib import Path


class InventoryError(ValueError):
    pass


def assess_inventory(data):
    if not isinstance(data, dict) or not isinstance(data.get("SchemaVersion"), int):
        raise InventoryError("Trivy JSON schema missing")
    results = data.get("Results", [])
    if not isinstance(results, list):
        raise InventoryError("Trivy Results is not an array")
    targets = []
    for item in results:
        if not isinstance(item, dict) or not isinstance(item.get("Target"), str):
            raise InventoryError("Trivy target record is malformed")
        if not item["Target"].strip():
            raise InventoryError("Trivy target name is empty")
        targets.append(item["Target"])
    if not targets:
        return "NOT_APPLICABLE", 0
    return "SCANNED", len(set(targets))


def read_inventory(path):
    with Path(path).open(encoding="utf-8") as source:
        return assess_inventory(json.load(source))


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("json_report")
    args = p.parse_args()
    state, n = read_inventory(args.json_report)
    print(f"{state}: {n} Trivy target(s)")
