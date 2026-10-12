# Security CI

**Des audits de sécurité directement dans les Pull Requests GitHub, sans installer quatre scanners à la main.**

Security CI est un workflow GitHub Actions **réutilisable** : on ajoute un fichier YAML dans son propre dépôt et on obtient des rapports sur son code. Le projet est en préparation de sa première version stable ; **`v1.0.0` n'est pas publiée**.

> **Essai uniquement :** le registre externe Semgrep peut encore empêcher
> l'audit de démarrer (voir [incident #29](https://github.com/loic31000/security-ci/issues/29)).
> Le workflow présenté ici n'est pas encore qualifié pour un contrôle
> obligatoire de production ; aucun résultat vert isolé ne prouve sa stabilité.

Il lance les contrôles suivants :

| Contrôle | Ce qu'il cherche |
| --- | --- |
| **Semgrep** | Problèmes de sécurité possibles dans le code |
| **Trivy** | Vulnérabilités de dépendances et configurations risquées, niveaux HIGH/CRITICAL |
| **Gitleaks** | Secrets potentiellement présents dans l'historique Git |
| **zizmor** | Risques dans les workflows GitHub Actions |
| **Qualité (complément)** | Duplications, complexité du code et résultats des tests de votre projet |

> **À retenir :** une alerte est un **signalement à vérifier**, pas une faille confirmée. Et un audit vert ne garantit pas que tout a été couvert.

## 1. Avant de commencer

Il faut :
- Un dépôt sur GitHub, avec **GitHub Actions activé**.
- Une **vraie commande qui lance les tests** de votre projet (par exemple `go test ./...`, `npm ci && npm test`).
- L'autorisation d'ajouter un workflow au dépôt. Nous conseillons de le faire dans une **Pull Request**, avant toute activation sur la branche principale.

Pas besoin d'installer Semgrep, Trivy, Gitleaks ou zizmor dans le dépôt. L'exemple ne demande pas de secret GitHub ni de `secrets: inherit`.

## 2. Installer Security CI en 4 étapes

**Étape 1 -** Dans votre dépôt GitHub, créez une branche de travail, puis ouvrez **Add file → Create new file**. Dans le nom du fichier, saisissez :

```text
.github/workflows/security.yml
```

**Étape 2 -** Collez cet exemple **pour un projet Go** :

```yaml
name: Security
on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    uses: loic31000/security-ci/.github/workflows/security-audit.yml@a5500d705a59c7e34dfdfdb1f12db600ea10ad82
    with:
      enforce: false
      test_command: 'go test ./...'
```

La longue référence après `@` est un **commit précis déjà validé**, pour éviter qu'une mise à jour du moteur modifie silencieusement vos audits. Ce n'est **pas** une version publiée.

**Étape 3 -** Adaptez **uniquement `test_command`** à votre projet :

| Votre projet | Exemple de commande, à adapter |
| --- | --- |
| Go | `go test ./...` |
| Node.js / npm | `npm ci && npm test` (nécessite un `package-lock.json` et un script `test`) |
| Python | `python -m pip install -r requirements.txt && python -m pytest` (nécessite `pytest` dans les dépendances installées) |

Vérifiez d'abord que cette commande fonctionne sur votre projet. La commande est exécutée **dans le dépôt audité**, dans un job séparé ; Security CI ne peut pas deviner comment installer ou tester votre application. **Sans `test_command`, le job de tests d'un dépôt externe échoue.** Ne mettez jamais `true` ou une commande fictive pour le faire passer au vert.

**Étape 4 -** Enregistrez le fichier, ouvrez une **Pull Request** et consultez ses contrôles dans l'onglet **Checks**. Vous pouvez aussi ouvrir **Actions → Security** et lancer `workflow_dispatch` sur une branche où ce workflow existe.

L'ajout du workflow ne modifie pas vos fichiers applicatifs et ne déploie rien. Les protections de branche et le blocage des fusions restent des réglages GitHub distincts.

## 3. Lire le premier résultat

Dans votre dépôt : **Actions → choisissez l'exécution Security → Summary** (ou **Pull Request → Checks**).

Vous y verrez plusieurs jobs : `Audit - semgrep`, `Audit - trivy`, `Audit - gitleaks`, `Audit - zizmor`, puis les contrôles de tests et de maintenabilité.

Pour examiner une alerte en détail :

1. Sur la page de l'exécution, descendez jusqu'à **Artifacts**.
2. Téléchargez l'archive du scanner concerné : `security-semgrep-*`, `security-trivy-*`, `security-gitleaks-*` ou `security-zizmor-*`.
3. Ouvrez le fichier **`semgrep.md`**, **`trivy.md`**, **`gitleaks.md`** ou **`zizmor.md`**. Il donne les détails disponibles (gravité, fichier, emplacement, explication). Le `*.sarif` sert au diagnostic technique.
4. Ouvrez le fichier concerné, vérifiez le contexte et décidez si l'alerte est réelle, à approfondir ou un faux positif. **N'appliquez pas aveuglément une correction.**

Les archives `maintainability-*` contiennent notamment `maintainability.md` pour les duplications et la complexité. Les artifacts sont conservés **7 jours**. Consultez aussi l'[exemple de lecture d'un rapport](docs/EXAMPLE-REPORT.md).

### Que veut dire le statut affiché ?

| Situation | Interprétation et action |
| --- | --- |
| **Vert, aucune alerte** | Pas d'alerte remontée **dans le périmètre réellement analysé** ; vérifiez la couverture. |
| **Vert, avec des alertes** | Normal avec `enforce: false` : ouvrez les rapports et vérifiez les signalements. |
| **« AUCUNE CIBLE RECONNUE » / `MANIFEST_ONLY`** | Le scanner n'a pas prouvé qu'il avait couvert les dépendances de cette stack : contrôlez les manifests et verrous. |
| **Rouge : alerte** | Avec `enforce: true`, une alerte active peut faire échouer le job. Vérifiez sa pertinence. |
| **Rouge : erreur technique** | Un scanner, son inventaire ou son rapport n'a pas pu être validé. **Ce n'est pas une vulnérabilité prouvée**, et l'échec ne doit pas être ignoré. |
| **Rouge : tests du projet** | La commande de tests manque, ne fonctionne pas ou les tests échouent. Corrigez la commande ou le projet, pas le contrôle d'audit. |

**Important pour Trivy :** il ne suffit pas qu'un fichier `package.json`, `Cargo.toml` ou un manifeste de build existe pour considérer ses dépendances auditées. Regardez `stack-coverage.json` et `trivy-targets.json` dans l'archive Trivy. Un manque de couverture n'est pas « zéro faille ».

## 4. Problèmes fréquents

**« Tests du projet : NON VALIDÉS »**  
Renseignez `test_command` avec la commande réellement utilisée par votre dépôt. Si la commande a besoin de dépendances, installez-les explicitement dedans. Regardez le log du job de tests.

**Semgrep échoue alors que je n'ai rien changé**  
Le registre des règles peut renvoyer un format ou une version **différente de celle approuvée**. Par sécurité, Security CI refuse ces règles et échoue, y compris en mode non bloquant. Consultez le log du job et, s'il existe, `semgrep-registry-drift.json` dans l'archive Semgrep. Une relance peut parfois réussir mais **ne résout pas l'instabilité du fournisseur** ; voir [incident #29](https://github.com/loic31000/security-ci/issues/29).

**Trivy ne reconnaît aucune dépendance**  
Vérifiez la présence de manifests/verrous exploitables et l'inventaire `stack-coverage.json`. L'absence de cible reconnue ne certifie pas que les dépendances sont sûres.

**Une alerte me semble incorrecte**  
Examinez la règle, le fichier et le contexte. Les résultats automatiques peuvent être des faux positifs ; documentez la justification d'une éventuelle exclusion.

**J'ai un échec de permission ou le workflow ne démarre pas**  
Vérifiez que GitHub Actions est autorisé dans le dépôt, que le fichier est bien dans `.github/workflows/` et que la référence après `@` est un SHA complet. Le workflow réutilisable doit être accessible depuis le dépôt appelant.

## 5. Personnaliser après le premier essai

Commencez en **mode rapport** (`enforce: false`), puis activez les blocages **après avoir examiné les alertes** :

```yaml
with:
  enforce: true
  test_command: 'go test ./...'
```

- **`enforce: false`** : les alertes sont affichées, mais ne font pas à elles seules échouer les jobs de scan.
- **`enforce: true`** : les alertes actives bloquent le job concerné. Cela ne configure **pas** automatiquement la protection des branches.
- **Dans les deux cas** : les erreurs techniques, inventaires invalides et tests échoués restent bloquants.

Pour vérifier aussi un **rapport de tests JUnit XML réellement produit** :

```yaml
with:
  enforce: false
  test_command: 'python -m pip install -r requirements.txt && python -m pytest --junitxml=reports/junit.xml'
  require_test_report: true
  test_report_path: 'reports/junit.xml'
```

Adaptez les dépendances et le chemin à votre projet. Le rapport doit être **nouveau, valide et contenir au moins un vrai test réussi**. Vous pouvez aussi fournir `coverage_paths` pour archiver des rapports de couverture produits par vos tests. Security CI ne génère pas automatiquement la couverture d'un langage.

## 6. Aller plus loin

- [Référence technique et maintenance](docs/technical-reference.md) - formats SARIF, règles, dépendances verrouillées, preuves des scanners, options avancées et limites.
- [Exemple commenté de rapport](docs/EXAMPLE-REPORT.md) - vérifier une alerte sans confondre détection et vulnérabilité confirmée.
- [Critères de préparation d'une version stable](docs/release-readiness.md) - la version `v1.0.0` **n'est pas publiée**.
- [Feuille de route](docs/stack-expansion-roadmap.md) - **nouvelles fonctionnalités gelées** ; priorité à la simplicité et à la stabilité.
- [Contribuer](CONTRIBUTING.md) · [Signaler une faille de sécurité](SECURITY.md) · [Licence MIT](LICENSE).

**Limites à connaître :** l'outil n'est pas un audit humain, n'assure ni 100 % de détection ni zéro faux positif. Il n'envoie pas automatiquement de résultats dans GitHub Code scanning et ne commente pas les PR. Les runners GitHub et les artifacts peuvent générer des coûts ou consommer des quotas, notamment dans les dépôts privés.
