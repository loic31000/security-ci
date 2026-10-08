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

## Lire les descriptions des audits

Chaque contrôle de sécurité affiche maintenant une phrase simple dans le résumé GitHub Actions, juste avant son tableau **État / Alertes / Mode** :

- **Semgrep** : analyse le code et signale des problèmes de sécurité potentiels.
- **Trivy** : détecte des vulnérabilités connues dans les dépendances et des erreurs de configuration, de sévérité élevée ou critique.
- **Gitleaks** : recherche des secrets potentiels dans l'historique Git, sans afficher leur valeur.
- **zizmor** : inspecte les workflows GitHub Actions et signale des pratiques risquées.

Le reste de l'affichage et les règles de décision sont inchangés. Une alerte
n'est pas nécessairement une faille confirmée ; le mode rapport ne la bloque pas,
le mode strict la bloque. Les artifacts SARIF apportent les détails.

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


## Qualité multi-langage et tests opt-in

Le job maintainability produit maintenant un fichier `lizard.xml` pour la complexité
multi-langage, en complément des rapports jscpd et Radon. Ces mesures sont
informatives et ne constituent pas une estimation financière de dette technique.

Un dépôt appelant peut activer les tests en passant une commande adaptée à sa
stack. La commande s'exécute **dans le dépôt appelant**, sans secrets hérités :
ne l'activez que pour un projet de confiance, après revue de ses scripts.

```yaml
jobs:
  security:
    uses: loic31000/security-ci/.github/workflows/security-audit.yml@REMPLACER_PAR_SHA_COMMIT
    permissions:
      contents: read
    with:
      enforce: false
      test_command: 'npm ci && npm run test -- --coverage'
      coverage_paths: |
        coverage/
```

Autres exemples à adapter après inspection du projet :
Python `python -m pip install -r requirements.txt && python -m pytest --cov=. --cov-report=xml`;
Go `go test ./... -coverprofile=coverage.out`.
La CI ne devine pas les commandes de test et ne prétend pas mesurer une
couverture si aucun rapport n'est généré. Les tests échoués font échouer
leur job ; l'absence de `test_command` désactive le job sans valider de tests.

## Déploiement

Le script `scripts/rollout.sh` prépare des Pull Requests de déploiement
sans modifier directement les branches principales. Il est en simulation
par défaut ; `--apply` est nécessaire pour écrire. Il n'installe pas
automatiquement de commandes de tests inconnues. Passer un SHA de référence
du workflow central après validation et fusion.

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

Une première mesure de dette technique est intégrée avec jscpd (duplications multi-langage) et Radon (complexité et maintenabilité Python). Les métriques sont informatives, sans quality gate, et les fichiers JSON sont disponibles dans l'artifact `maintainability-*`. SonarQube, les fonctions de complexité des autres langages (Lizard) et un job de tests configurable sont disponibles. La couverture exige une configuration propre à chaque projet ; SonarQube et le DAST restent à intégrer. Les versions et règles doivent être mises à jour et
validées régulièrement dans ce dépôt central.
