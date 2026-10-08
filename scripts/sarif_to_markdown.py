#!/usr/bin/env python3
"""Convert a scanner SARIF report into a developer-readable Markdown report."""
import argparse
import html
import json
import os
from pathlib import Path
from urllib.parse import quote, unquote, urlparse


def clean(value, limit=1000):
    """Escape Markdown/HTML; never render raw SARIF as executable HTML."""
    value = " ".join(str(value or "").split())[:limit]
    return html.escape(value, quote=False).replace("|", "\\|").replace("[", "\\[").replace("]", "\\]")


def location_for(result, repo, sha):
    locations = result.get("locations") or []
    for loc in locations:
        physical = loc.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        uri = unquote(artifact.get("uri") or "")
        parsed = urlparse(uri)
        if parsed.scheme or uri.startswith("/") or "\\" in uri:
            continue
        path = Path(uri)
        if not uri or ".." in path.parts:
            continue
        line = (physical.get("region") or {}).get("startLine")
        suffix = f"#L{int(line)}" if isinstance(line, int) and line > 0 else ""
        url = f"https://github.com/{repo}/blob/{sha}/{quote(uri, safe='/')}{suffix}" if repo and sha else ""
        return uri, line, url
    return "Emplacement non renseigné", None, ""


def render(data, scanner, repo="", sha=""):
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF: liste runs absente ou vide")
    title = {"semgrep": "Analyse du code", "trivy": "Dépendances et configuration",
             "gitleaks": "Secrets potentiels", "zizmor": "Workflows GitHub Actions"}.get(scanner, scanner)
    lines = [f"# Rapport {scanner}", "", f"**Contrôle :** {title}.", "",
             "Ces résultats sont des alertes à examiner, pas des vulnérabilités confirmées.",
             "Le rapport SARIF original reste disponible pour les outils.", ""]
    records = []
    for run in runs:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rid = str(result.get("ruleId") or "Règle non précisée")
            rule = by_id.get(rid, {})
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "non précisée"
            raw_message = (result.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text") or ""
            # Secret scanners can place credential values in messages. Never reproduce them.
            message = ("Secret potentiel détecté ; ouvrir le rapport SARIF (valeurs à traiter comme sensibles)."
                       if scanner == "gitleaks" else raw_message)
            uri, line, url = location_for(result, repo, sha)
            records.append((rid, level, message, uri, line, url))
    lines.extend([f"**Nombre de signalements : {len(records)}**", ""])
    if not records:
        lines.extend(["Aucune alerte remontée dans le périmètre analysé.", ""])
    for index, (rid, level, message, uri, line, url) in enumerate(records, 1):
        lines.extend([f"## {index}. {clean(rid, 180)}", "",
                      f"- **Gravité SARIF :** {clean(level, 80)}",
                      f"- **Fichier :** `{clean(uri, 320)}`",
                      f"- **Ligne :** {line if line else 'non renseignée'}"])
        if url:
            lines.append(f"- **Voir le code :** [ouvrir dans GitHub]({url})")
        lines.extend([f"- **Explication :** {clean(message) or 'Aucune description fournie par le scanner.'}",
                      "- **À faire :** vérifier le contexte et confirmer ou écarter l'alerte avant une correction.", ""])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif")
    parser.add_argument("markdown")
    parser.add_argument("--scanner", required=True)
    args = parser.parse_args()
    destination = Path(args.markdown)
    try:
        data = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
        content = render(data, args.scanner, os.environ.get("GITHUB_REPOSITORY", ""),
                         os.environ.get("GITHUB_SHA", ""))
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        content = (f"# Rapport {args.scanner}\\n\\n"
                   "**Rapport non disponible :** impossible de lire un SARIF valide. "
                   "Consulter le journal du scanner et le rapport brut éventuel.\\n")
        print(f"Impossible de convertir le SARIF : {type(exc).__name__}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
