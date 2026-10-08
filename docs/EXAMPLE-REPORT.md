# Exemple de lecture d'un rapport

> Exemple fictif, sans vulnérabilité confirmée et sans donnée sensible.

Dans **Actions → Exécution → Artifacts**, téléchargez `security-semgrep-...`
puis ouvrez `semgrep.md`.

## 1. Vérifier le signalement

- **Règle** : `example.rule`
- **Gravité** : warning
- **Fichier** : `src/example.py`
- **Ligne** : 12
- **Explication** : le scanner signale une construction de requête potentiellement risquée.

## 2. Examiner le code

Ouvrez le fichier et la ligne indiqués par le lien GitHub du rapport.
Vérifiez si l'entrée vient réellement d'une source non fiable et si la
protection attendue est présente. Le résultat peut être un faux positif.

## 3. Documenter la décision

Notez « confirmé », « à vérifier » ou « faux positif » avec une justification.
Le mode `enforce: false` laisse passer les alertes ; `enforce: true` les
bloque. Ni l'un ni l'autre n'autorise automatiquement un déploiement.

Les autres artifacts `security-trivy-*`, `security-gitleaks-*`,
`security-zizmor-*` et `maintainability-*` contiennent également leurs
rapports lisibles en `.md`, accompagnés des résultats techniques originaux.
