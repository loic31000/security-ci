# Security CI

Workflow GitHub Actions réutilisable pour auditer le code, les dépendances,
les secrets, l'infrastructure déclarative et les workflows GitHub Actions.

| Contrôle | Outil | Périmètre des alertes |
|---|---|---|
| SAST | Semgrep CE | Règles `p/security-audit` |
| SCA / IaC | Trivy | HIGH et CRITICAL |
| Secrets | Gitleaks CLI | Historique Git accessible, secrets masqués |
| GitHub Actions | zizmor | MEDIUM et HIGH, analyse hors ligne |
| Maintenabilité | jscpd + Radon + Lizard | Copies exactes suffisamment longues ; complexité Python et multi-langage |

## Lire les descriptions des audits

Chaque contrôle de sécurité affiche maintenant une phrase simple dans le résumé GitHub Actions, juste avant son tableau **État / Alertes / Mode** :

- **Semgrep** : analyse le code et signale des problèmes de sécurité potentiels.
- **Trivy** : détecte des vulnérabilités connues dans les dépendances et des erreurs de configuration, de sévérité élevée ou critique.
- **Gitleaks** : recherche des secrets potentiels dans l'historique Git, sans afficher leur valeur.
- **zizmor** : inspecte les workflows GitHub Actions et signale des pratiques risquées.

## Fiabilité des résultats et faux positifs

**Un outil automatique ne peut pas garantir zéro faux positif, ni détecter
100 % des vulnérabilités.** Les résultats affichés sont des **détections à
confirmer**, jamais des « failles prouvées » sans vérification humaine.

- Les rapports SARIF sont contrôlés avant toute conclusion : version 2.1.0,
  analyse réussie, identité du scanner, liste de résultats présente et
  structure cohérente. Les erreurs techniques sont **bloquantes**, même en mode rapport.
- Le compteur d'alertes actives ne retient que les résultats SARIF de type
  `fail` et de niveau `warning` ou `error`. Les résultats `pass`,
  `review`, `open`, `informational`, `note` et `none` sont identifiés
  séparément comme **non bloquants**, sans les appeler « vulnérabilités ».
- Une suppression SARIF explicitement **acceptée** est exclue des alertes
  actives, mais reste traçable dans l'artifact. Une suppression en cours
  d'examen ou rejetée reste active. Une suppression ne démontre pas que
  le code est sécurisé : elle doit être justifiée et revue.
- En mode `enforce: true`, ce sont les **alertes actives du scanner** qui
  bloquent la CI, pas nécessairement des failles exploitables confirmées.
  En mode rapport, elles restent visibles sans blocage.
- Pour **jscpd**, l'analyse privilégie les blocs **exactement identiques**,
  d'au moins 10 lignes et 100 tokens (`--mode strict`). Les copies
  intentionnelles, modèles générés et code répétitif légitime restent
  possibles ; elles ne sont jamais appelées automatiquement « défauts ».
  Radon et Lizard mesurent des indices de complexité, **pas des bugs**.

Pour transformer une détection en vulnérabilité confirmée, il faut reproduire
le comportement ou vérifier le chemin d'exploitation, le contexte, la version
affectée et l'impact. Les vulnérabilités de dépendances ne sont pas
nécessairement atteignables. Un rapport sans signalements ne prouve pas
que tous les fichiers, dépendances et chemins d'exécution ont été examinés.

Les rapports Markdown distinguent désormais les alertes à vérifier, les
exclusions acceptées et les autres entrées SARIF. L'artifact SARIF brut
reste disponible pour la traçabilité.

## Cibles Trivy et dépendances du moteur

L'analyse Trivy du dépôt appelant produit **deux rapports complémentaires** :
le SARIF des signalements et un inventaire JSON `trivy-targets.json`. Un
inventaire JSON contenant zéro cible est affiché comme
**« AUCUNE CIBLE RECONNUE : couverture non établie »**, et non comme une
preuve que les dépendances ne contiennent aucune vulnérabilité. Une erreur
d'inventaire bloque toujours le job. Les résultats restent filtrés aux niveaux
HIGH/CRITICAL du scanner ; la présence d'une CVE n'est pas une exploitation
confirmée.

Pour le moteur `security-ci` lui-même, le workflow
`.github/workflows/engine-dependencies.yml` résout dans un environnement de
CI isolé les versions des outils Python (Semgrep, zizmor, Radon, Lizard,
defusedxml), des dépendances npm de jscpd et du module Go de Gitleaks. Il
génère les manifests `requirements.txt`, `package-lock.json` et `go.mod`,
puis les soumet à Trivy. Il vérifie qu'au moins une cible a réellement été
reconnue et **indique les familles non couvertes**. Les avis CVE restent
informatifs jusqu'à revue humaine ; les erreurs techniques, inventaires
absents et scans sans cibles échouent.

Ces dépendances sont **résolues au moment de l'exécution**. Une analyse du
moteur peut différer d'un runner à l'autre ; elle n'est pas une preuve de
chaîne d'approvisionnement entièrement reproductible. Ne jamais présenter
un rapport sans vulnérabilités comme une garantie de sécurité.

## Rapports de sécurité lisibles pour les développeurs

Chaque analyse de sécurité conserve le **SARIF** (pour les outils) et produit
également un **rapport Markdown** téléchargeable dans le même artifact
`security-<scanner>-<run_id>-<tentative>` :

- `semgrep.md` : règle, gravité, fichier, ligne, explication et lien GitHub.
- `trivy.md` : vulnérabilité ou erreur de configuration, gravité, emplacement et explication.
- `gitleaks.md` : emplacement d'un secret potentiel, sans reproduire les valeurs sensibles.
- `zizmor.md` : risque dans un workflow GitHub Actions, avec chemin, ligne et explication.

Ouvrir **Actions → exécution → Artifacts**, télécharger l'archive du
scanner puis ouvrir le fichier `.md` pour lire les résultats.
Si le scanner ne fournit ni ligne ni emplacement, le rapport l'indique
plutôt que de les inventer. Les signalements doivent être confirmés
avant correction. Un rapport Markdown n'est pas un audit manuel.

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
      # Exemple bloquant tant qu'une vraie commande adaptée au dépôt n'est pas fournie :
      test_command: 'echo "Configurer les tests du projet" >&2; exit 1'
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

Un audit **hebdomadaire** est également programmé chaque lundi (04 h 17 UTC)
sur la branche par défaut, ainsi qu'un audit des dépendances du moteur
(05 h 23 UTC). Les exécutions planifiées ne déclenchent aucun
déploiement vers un autre dépôt. ShellCheck vérifie les scripts Bash
de `security-ci` et échoue sur les avertissements de qualité.

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

Un dépôt appelant doit configurer les tests en passant une commande adaptée à sa
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
couverture si aucun rapport n'est généré. **Sans `test_command`, le job échoue**
dans un dépôt appelant pour éviter une validation trompeuse ; les tests échoués
font aussi échouer le job. Seul `security-ci` lui-même exécute ses tests
unitaires intégrés lorsque la commande n'est pas fournie.

### Mode de certification stricte par rapport de tests JUnit

Les dépôts appelants peuvent activer la vérification d'un **rapport JUnit XML**
en complément de la commande de tests. Ce mode ne change pas les projets
existants : il est volontairement **opt-in**.

```yaml
jobs:
  security:
    uses: loic31000/security-ci/.github/workflows/security-audit.yml@REMPLACER_PAR_SHA_COMMIT
    permissions:
      contents: read
    with:
      test_command: 'python -m pip install pytest && python -m pytest tests -q --junitxml=reports/junit.xml'
      require_test_report: true
      test_report_path: 'reports/junit.xml'
```

La certification échoue si le fichier est absent, situé hors du dépôt,
ancien (non réécrit pendant ce job), trop volumineux, invalide, ou contient
zéro `testcase`, un échec, une erreur ou un test ignoré. Son parseur XML
utilise `defusedxml`. **Ce contrôle atteste la présence d'un rapport
structuré cohérent ; il ne peut pas empêcher un script malveillant de
fabriquer un faux rapport.** N'activer la commande que sur du code de
confiance. Le chemin est relatif à la racine du dépôt appelant.

## Lire les rapports de maintenabilité, tests et couverture

En plus des quatre scanners de sécurité, le résumé GitHub Actions explique :

| Mesure | Description simple | Interprétation |
|---|---|---|
| **jscpd** | Blocs exactement identiques de 10 lignes et 100 tokens au moins. | Un bloc répété peut être intentionnel et n'est pas automatiquement un défaut. |
| **Radon (Python)** | Fonctions avec une complexité cyclomatique d'au moins 11 et fichiers dont l'indice de maintenabilité est inférieur à 20. | Indicateurs à examiner, sans blocage de sécurité. |
| **Lizard** | Complexité sur plusieurs langages ; valeurs d'au moins 15 signalées. | Aide à identifier le code difficile à suivre ou tester. |
| **Tests du projet** | Affiche si la commande de tests du projet a réussi ou échoué. | Commande obligatoire pour un dépôt appelant ; son absence fait échouer le job. |
| **Couverture optionnelle** | Lit le pourcentage de lignes depuis `coverage.xml` au format Cobertura quand il est présent à la racine. | Un rapport manquant affiche « non disponible » et non « 0 % ». |

Les données complètes sont conservées 7 jours dans les artifacts
`maintainability-*` (JSON et XML) et, si configuré, `coverage-*`.
Le taux indiqué ne porte que sur les fichiers et tests présents dans le rapport.
Les seuils de complexité sont informatifs et **ne bloquent pas** les fusions.
Ce résumé n'installe pas d'outil de tests propre à une stack : la commande vient
exclusivement du dépôt appelant.

## Rapport de maintenabilité lisible

L'artifact `maintainability-*` contient maintenant `maintainability.md`,
en plus de `jscpd-report.json`, des fichiers Radon JSON et de `lizard.xml`.
Le Markdown récapitule les duplications, les fichiers et lignes des blocs
identifiés lorsque ces informations existent, les fonctions Python complexes,
les faibles indices de maintenabilité et les mesures Lizard.
Les détails complets restent dans les fichiers originaux.

Les générateurs Markdown sont testés automatiquement sur les Pull Requests
et sur `main` par `.github/workflows/report-tests.yml`. Les tests couvrent
notamment la localisation, la protection des valeurs sensibles Gitleaks,
les chemins malveillants, les rapports vides et les métriques de maintenance.

## Déploiement

Le script `scripts/rollout.sh` prépare des Pull Requests **en brouillon**, sans
modifier directement les branches principales. Chaque dépôt doit disposer d'une
**commande de tests réelle**, déclarée volontairement dans un fichier JSON local :

```json
{
  "loic31000/mon-projet": "npm ci && npm test"
}
```

Pour simuler, puis proposer des PR uniquement sur les dépôts configurés :

```bash
./scripts/rollout.sh SHA_COMPLET_DU_WORKFLOW '' test-commands.json
./scripts/rollout.sh SHA_COMPLET_DU_WORKFLOW --apply test-commands.json
```

Remplacer le marqueur par le SHA Git complet **validé** du workflow central.
Sans commande pour un dépôt, celui-ci est **ignoré** ; `--apply` refuse de
fonctionner sans fichier de configuration. Les commandes doivent tenir sur une
ligne et être examinées avant utilisation. Ne jamais inclure de secret dans ce
fichier, ni fusionner les PR sans vérifier leur CI. Une simulation ne modifie rien.
Le script n'installe pas de dépendances inconnues et ne fusionne aucune PR.

## Participer et signaler un problème

- [Guide de contribution](CONTRIBUTING.md) : règles des Pull Requests et tests.
- [Politique de signalement de sécurité](SECURITY.md) : évitez de publier des secrets.
- [Exemple de lecture d'un rapport](docs/EXAMPLE-REPORT.md).

## Préparation de la première version

Le projet est distribué sous **licence MIT** (voir [LICENSE](LICENSE)).
La première version stable `v1.0.0` n'a pas encore été publiée.

Une fois les tests vérifiés, documenter les changements
dans les notes de version, créer un tag sur un commit validé, puis publier la
release GitHub. Ne pas taguer une version stable avant ces étapes.

## Limites et maintenance

Les runners standards GitHub sont gratuits pour les dépôts publics ; les dépôts
privés consomment le quota de leur propriétaire. Un workflow central public ne
rend pas gratuites les exécutions appelées depuis des dépôts privés. Le stockage
des artifacts a ses propres limites.

Les actions sont figées par SHA et les scanners par version. Go utilise la dernière
révision corrective de la branche 1.25. Les dépendances transitives des installations
Python ne sont pas verrouillées par hash. Les règles Semgrep téléchargées et les
bases CVE Trivy évoluent : les résultats ne sont pas parfaitement reproductibles.

L'analyse de sécurité ne lance pas les scripts d'installation. Le job de tests exécute uniquement la commande explicitement fournie par le dépôt appelant. Trivy
analyse les manifests/lockfiles qu'il prend en charge : un résultat sans alerte
ne prouve pas que toutes les dépendances ont été couvertes. Les fichiers ignorés,
les configurations des scanners et les exclusions du dépôt affectent le périmètre.
Les alertes et leurs corrections doivent être examinées avant d'activer le mode strict.

Gitleaks masque les secrets dans ses résultats ; les autres rapports peuvent contenir
des extraits de code. zizmor fonctionne hors ligne : les contrôles nécessitant
l'API GitHub ne sont pas exécutés. Aucun scanner ne garantit l'absence de faille.

Une première mesure de dette technique est intégrée avec jscpd (duplications multi-langage) et Radon (complexité et maintenabilité Python). Les métriques sont informatives, sans quality gate, et les fichiers JSON sont disponibles dans l'artifact `maintainability-*`. Lizard mesure la complexité de plusieurs langages, et un job de tests configurable est disponible. La couverture exige une configuration propre à chaque projet ; SonarQube et le DAST restent à intégrer. Les versions et règles doivent être mises à jour et
validées régulièrement dans ce dépôt central.
