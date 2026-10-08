# Security CI

Workflow GitHub Actions réutilisable pour auditer le code, les dépendances,
les secrets, l'infrastructure déclarative et les workflows GitHub Actions.

| Contrôle | Outil | Périmètre des alertes |
|---|---|---|
| SAST | Semgrep CE | Règles `p/security-audit` |
| SCA / IaC | Trivy | HIGH et CRITICAL |
| Secrets | Gitleaks CLI | Historique Git accessible, secrets masqués |
| GitHub Actions | zizmor | MEDIUM et HIGH, analyse hors ligne |
| Maintenabilité | jscpd + Radon | Duplications multi-langage ; complexité et maintenabilité Python |

## Utilisation

Le fichier `.github/workflows/security-audit.yml` peut être appelé depuis
un autre dépôt. Il analyse le dépôt appelant, pas uniquement `security-ci`.

Exemple à installer **seulement après accord dans chaque projet** :

```yaml
name: Security
on:
  pull_request:
  push:
    branches: [main] # adapter à la branche principale du projet
  workflow_dispatch:
  schedule:
    - cron: '0 4 * * 1'
permissions:
  contents: read
jobs:
  security:
    uses: loic31000/security-ci/.github/workflows/security-audit.yml@REMPLACER_PAR_SHA_COMMIT
    with:
      enforce: false
```

Remplacer le marqueur par le SHA complet d'un commit validé de ce dépôt.
Le marqueur est volontairement inutilisable : aucun projet n'est installé
automatiquement. Aucun secret ni `secrets: inherit` n'est nécessaire.

## Modes et résultats

- `enforce: false` : les alertes sont rapportées sans faire échouer le contrôle.
- `enforce: true` : toute alerte retenue fait échouer le contrôle correspondant.
- Les erreurs techniques et rapports absents/incomplets font échouer le contrôle
  dans les deux modes. Une exécution verte en mode rapport peut contenir des alertes.
- Résumés : **Actions → exécution → Summary**.
- Rapports détaillés : artifacts `security-*` (SARIF) et `maintainability-*` (JSON), conservés 7 jours.
- Pas de publication automatique dans **Security → Code scanning** ni de
  commentaire sur les PR.

Dans `security-ci`, les push sur `main` et les PR déclenchent un audit du dépôt
central. Un lancement manuel est également disponible dans Actions, avec le choix
du mode. Les autres dépôts nécessitent leur propre workflow appelant.

Les protections de branches se configurent séparément : un contrôle en échec
ne bloque pas automatiquement la fusion. Le mode strict concerne les alertes
présentes, pas uniquement les nouvelles alertes introduites par une PR.

## Limites et maintenance

Les runners standards GitHub sont gratuits pour les dépôts publics ; les dépôts
privés consomment le quota de leur propriétaire. Un workflow central public ne
rend pas gratuites les exécutions appelées depuis des dépôts privés. Le stockage
des artifacts a ses propres limites.

Les actions sont figées par SHA et les scanners par version. Go utilise la dernière
révision corrective de la branche 1.25. Les dépendances transitives des installations
Python ne sont pas verrouillées par hash. Les règles Semgrep téléchargées et les
bases CVE Trivy évoluent : les résultats ne sont pas parfaitement reproductibles.

L'analyse ne lance ni les scripts d'installation ni les tests du projet. Trivy
analyse les manifests/lockfiles qu'il prend en charge : un résultat sans alerte
ne prouve pas que toutes les dépendances ont été couvertes. Les fichiers ignorés,
les configurations des scanners et les exclusions du dépôt affectent le périmètre.
Les alertes et leurs corrections doivent être examinées avant d'activer le mode strict.

Gitleaks masque les secrets dans ses résultats ; les autres rapports peuvent contenir
des extraits de code. zizmor fonctionne hors ligne : les contrôles nécessitant
l'API GitHub ne sont pas exécutés. Aucun scanner ne garantit l'absence de faille.

Une première mesure de dette technique est intégrée avec jscpd (duplications multi-langage) et Radon (complexité et maintenabilité Python). Les métriques sont informatives, sans quality gate, et les fichiers JSON sont disponibles dans l'artifact `maintainability-*`. SonarQube, les métriques de complexité des autres langages, la couverture, les tests et le DAST restent à intégrer. Les versions et règles doivent être mises à jour et
validées régulièrement dans ce dépôt central.
