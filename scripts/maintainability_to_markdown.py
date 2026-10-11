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


def _duplication_report(root):
    jp = root / "jscpd-report.json"
    if not jp.exists():
        return ["## Duplications : rapport indisponible", ""]
    data = json.loads(jp.read_text())
    blocks = data.get("duplicates", [])
    lines = [f"## Duplications jscpd : {len(blocks)} bloc(s)", "",
             "Deux portions de code similaires peuvent rendre la maintenance plus difficile.", ""]
    for index, duplicate in enumerate(blocks[:100], 1):
        a, b = duplicate.get("firstFile", {}), duplicate.get("secondFile", {})
        lines.append(f"{index}. {safe(a.get('name', '?'))}:{a.get('start', 'N/A')} et "
                     f"{safe(b.get('name', '?'))}:{b.get('start', 'N/A')}")
    if len(blocks) > 100:
        lines.append(f"Autres duplications : {len(blocks)-100}. Consulter le JSON.")
    return lines


def _python_complexity_report(root):
    path = root / "python-complexity.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    records = [(p, item) for p, items in data.items() if isinstance(items, list)
               for item in items if item.get("complexity", 0) >= 11]
    records.sort(key=lambda row: row[1].get("complexity", 0), reverse=True)
    lines = ["", f"## Complexité Python Radon : {len(records)} fonction(s) >= 11", "",
             "Une valeur élevée indique davantage de chemins logiques à tester.", ""]
    for p, item in records[:100]:
        lines.append(f"- {safe(p)}:{item.get('lineno', 'N/A')} : "
                     f"**{safe(item.get('name', '?'))}**, complexité {item.get('complexity')}")
    return lines


def _python_maintainability_report(root):
    path = root / "python-maintainability.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    low = [(p, v.get("mi")) for p, v in data.items()
           if isinstance(v, dict) and v.get("mi", 100) < 20]
    lines = ["", f"## Maintenabilité Python Radon : {len(low)} fichier(s) avec indice < 20", ""]
    for p, score in low[:100]:
        lines.append(f"- {safe(p)} : indice {score}")
    return lines


def _lizard_report(root):
    path = root / "lizard.xml"
    if not path.exists():
        return []
    high, total = lizard_complexity(path)
    return ["", f"## Complexité multi-langage Lizard : {high} fonction(s) >= 15 sur {total} mesurées", "",
            "Le détail des fonctions et fichiers se trouve dans lizard.xml."]


def render(root):
    root = Path(root)
    lines = ["# Rapport de maintenabilité", "",
             "Ces indicateurs aident à prioriser les refactorings ; ils ne prouvent pas une faille de sécurité.", ""]
    for section in (_duplication_report, _python_complexity_report,
                    _python_maintainability_report, _lizard_report):
        lines.extend(section(root))
    lines.extend(["", "Rapports sources : fichiers JSON/XML dans le même artifact.", ""])
    return "\\n".join(lines)



def main():
    p = argparse.ArgumentParser()
    p.add_argument("directory")
    p.add_argument("output")
    a = p.parse_args()
    Path(a.output).write_text(render(a.directory), encoding="utf-8")


if __name__ == "__main__":
    main()
