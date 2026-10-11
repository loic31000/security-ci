#!/usr/bin/env python3
"""Create a readable Markdown report from jscpd, Radon and Lizard outputs."""
import argparse
import html
import json
from pathlib import Path
from defusedxml import ElementTree as ET


def safe(value):
    return html.escape(" ".join(str(value or "").split())[:250], quote=False).replace("|", "\\|")


def lizard_complexity(xml_path):
    """Count real Lizard XML function CCN values by the CCN label, not by tag guesses."""
    import math

    tree = ET.parse(xml_path)
    groups = tree.findall(".//measure[@type='Function']")
    if not groups:
        raise ValueError("Lizard: Function measure missing")
    high = total = 0
    for measure in groups:
        labels = [label.text for label in measure.findall("./labels/label")]
        if "CCN" not in labels:
            raise ValueError("Lizard: CCN label missing")
        index = labels.index("CCN")
        for item in measure.findall("./item"):
            values = item.findall("./value")
            if index >= len(values) or values[index].text is None:
                raise ValueError("Lizard: CCN field missing")
            ccn = float(values[index].text)
            if not math.isfinite(ccn) or ccn < 0:
                raise ValueError("Lizard: invalid CCN value")
            total += 1
            high += ccn >= 15
    return high, total


def render(root):
    root = Path(root)
    lines = ["# Rapport de maintenabilité", "",
             "Ces indicateurs aident à prioriser les refactorings ; ils ne prouvent pas une faille de sécurité.", ""]
    jp = root / "jscpd-report.json"
    if jp.exists():
        data = json.loads(jp.read_text())
        blocks = data.get("duplicates", [])
        lines += [f"## Duplications jscpd : {len(blocks)} bloc(s)", "",
                  "Deux portions de code similaires peuvent rendre la maintenance plus difficile.", ""]
        for i, duplicate in enumerate(blocks[:100], 1):
            a, b = duplicate.get("firstFile", {}), duplicate.get("secondFile", {})
            lines.append(f"{i}. `{safe(a.get('name', '?'))}:{a.get('start', 'N/A')}` et `{safe(b.get('name', '?'))}:{b.get('start', 'N/A')}`")
        if len(blocks) > 100:
            lines.append(f"Autres duplications : {len(blocks)-100}. Consulter le JSON.")
    else:
        lines += ["## Duplications : rapport indisponible", ""]
    cc = root / "python-complexity.json"
    if cc.exists():
        data = json.loads(cc.read_text())
        records = [(path, item) for path, items in data.items() if isinstance(items, list) for item in items if item.get("complexity", 0) >= 11]
        records.sort(key=lambda t: t[1].get("complexity", 0), reverse=True)
        lines += ["", f"## Complexité Python Radon : {len(records)} fonction(s) >= 11", "",
                  "Une valeur élevée indique davantage de chemins logiques à tester.", ""]
        for path, item in records[:100]:
            lines.append(f"- `{safe(path)}:{item.get('lineno', 'N/A')}` : **{safe(item.get('name', '?'))}**, complexité {item.get('complexity')}")
    mi = root / "python-maintainability.json"
    if mi.exists():
        data = json.loads(mi.read_text())
        low = [(p, v.get("mi")) for p, v in data.items() if isinstance(v, dict) and v.get("mi", 100) < 20]
        lines += ["", f"## Maintenabilité Python Radon : {len(low)} fichier(s) avec indice < 20", ""]
        for path, score in low[:100]:
            lines.append(f"- `{safe(path)}` : indice {score}")
    xml = root / "lizard.xml"
    if xml.exists():
        high, total = lizard_complexity(xml)
        lines += ["", f"## Complexité multi-langage Lizard : {high} fonction(s) >= 15 sur {total} mesurées", "",
                  "Le détail des fonctions et fichiers se trouve dans lizard.xml."]
    lines += ["", "Rapports sources : fichiers JSON/XML dans le même artifact.", ""]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("directory")
    p.add_argument("output")
    a = p.parse_args()
    Path(a.output).write_text(render(a.directory), encoding="utf-8")


if __name__ == "__main__":
    main()
