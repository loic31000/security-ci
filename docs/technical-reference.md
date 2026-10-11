# Référence technique et maintenance de Security CI

> Ce document s'adresse aux personnes qui **maintiennent le moteur** ou doivent
> auditer précisément ses garanties. Pour installer le workflow et comprendre
> les résultats, commencez par le [guide utilisateur](../README.md).
>
> Les fonctionnalités sont **gelées avant la première release** : corriger
> uniquement des problèmes démontrés et simplifier l'expérience utilisateur.
> La release `v1.0.0` n'est pas publiée.

## Fonctionnement général

`.github/workflows/security-audit.yml` est un workflow GitHub Actions
réutilisable (`workflow_call`). Il exécute, dans des jobs isolés, Semgrep,
Trivy, Gitleaks et zizmor. Un job de tests exécute **uniquement la commande
fournie par le dépôt appelant**. La maintenabilité est mesurée à part via
jscpd, Radon et Lizard : **les métriques de complexité sont informatives**.

Le moteur est exécuté sur le **dépôt appelant**, pas automatiquement sur
d'autres dépôts. Pour un dépôt externe, `test_command` est obligatoire.
La commande doit être revue, car elle s'exécute dans le contexte du code du
dépôt appelant. Aucune clé ni `secrets: inherit` n'est nécessaire pour
l'intégration de base.

### Paramètres `workflow_call`

| Paramètre | Défaut | Effet |
| --- | --- | --- |
| `enforce` | `false` | Les alertes actives font échouer les scanners en mode strict ; les erreurs techniques échouent dans tous les modes. |
| `test_command` | vide | Commande réelle de tests ; obligatoire pour un dépôt externe. |
| `require_test_report` | `false` | Active une vérification stricte de rapport JUnit XML. |
| `test_report_path` | vide | Chemin relatif du JUnit XML créé par les tests. |
| `coverage_paths` | vide | Chemins de rapports de couverture à conserver, sans générer la couverture. |

Le contrôle JUnit exige un fichier récent, dans le workspace, valide,
avec au moins un testcase et aucun test échoué, en erreur ou ignoré.
Ce mécanisme est une preuve de cohérence, **pas** une attestation
cryptographique du code de tests.

Le mode `enforce: false` est un **mode rapport**, pas un mode tolérant aux
erreurs de configuration. Les protections des branches GitHub sont
indépendantes du statut du job et ne sont pas modifiées par le moteur.

## Scanner, formats et décisions

Chaque scanner produit un rapport **SARIF 2.1.0** ; le parseur vérifie la
cohérence des résultats, des règles et des exécutions. Une erreur technique
ou une notification de configuration de niveau `error` rend le résultat
inexploitable, même si la liste des findings est vide.

L'évaluation distingue notamment :
- Les résultats actifs de niveau warning/error et type fail.
- Les entrées pass, review, open, informational, note ou none, sans
  les présenter comme des alertes actives.
- Les suppressions acceptées (exclues des alertes actives mais conservées
  pour traçabilité) des suppressions en cours ou rejetées (restant actives).

Un résultat SARIF avec zéro alerte **ne prouve pas la couverture intégrale**
des chemins de code, des dépendances ou de la configuration. Les
détections automatiques nécessitent une revue humaine avant de parler de
vulnérabilité confirmée.

### Trivy : inventaire de cibles

Le rapport `trivy-targets.json` est une **preuve de reconnaissance de
cibles** distincte du SARIF. `stack-coverage.json` indique quels manifests
étaient présents et lesquels Trivy a effectivement reconnus :
Go, Python requirements, npm, pnpm, Maven, Gradle verrouillé, Rust/Cargo,
Ruby/Bundler et PHP/Composer.

Une cible absente ou non reconnue ne compte jamais comme « zéro CVE ».
`MANIFEST_ONLY` signifie qu'un fichier de build/manifeste est présent
**sans preuve d'analyse de dépendances résolues** (ex. `Cargo.toml`,
`package.json` sans verrou). Les indices .NET/NuGet sont `UNVERIFIED`
sans calibration réelle. Les inventaires malformés ou partiels sont
bloquants, pas maquillés en résultats propres.

Trivy affiche les avis HIGH/CRITICAL et les risques de configuration
dans son périmètre. Une CVE relevée n'est pas nécessairement exploitable.

### Semgrep : intégrité du registre

La configuration distante est
`https://semgrep.dev/c/p/security-audit`. L'empreinte approuvée
(SHA-256 exact, format YAML, **225 identifiants uniques**) est enregistrée
dans `locks/semgrep-security-audit.json`, puis contrôlée par
`scripts/verify_semgrep_bundle.py` **avant toute exécution de règles**.

Jusqu'à trois tentatives bornées sont autorisées pour récupérer les octets
approuvés. Si le fournisseur sert un autre format, une autre révision ou
une réponse invalide, le job **échoue sans utiliser ces règles**.
L'artifact peut contenir `semgrep-registry-drift.json` : format, compteurs
et empreintes, **sans texte des règles**.

L'[incident #29](https://github.com/loic31000/security-ci/issues/29)
suit les réponses intermittentes du registre. Le fait que des objets de
règles JSON/YAML aient pu être comparés dans les essais passés n'autorise
**aucune autre représentation**. Les scripts de recherche ont été retirés
des exécutions courantes pour conserver un workflow simple. Ne pas
redistribuer les contenus soumis à la licence Semgrep Rules dans le dépôt,
des issues ou des artifacts.

### Gitleaks et zizmor

Gitleaks recherche des secrets potentiels dans l'historique Git
accessible ; ses résultats sont masqués. L'historique effectivement
accessible et les exclusions influencent la couverture. Le moteur construit
Gitleaks depuis un module Go verrouillé (`locks/gitleaks/go.mod` et
`go.sum`) plutôt que de télécharger arbitrairement des binaires.

zizmor analyse les workflows GitHub Actions **hors ligne**. Les
vérifications qui demanderaient l'API GitHub ne sont pas exécutées ; ne
pas présenter l'analyse comme exhaustive.

## Rapports et conservation

Chaque archive `security-<scanner>-<run_id>-<tentative>` peut contenir :
- Le rapport `<scanner>.md`, lisible par le développeur.
- Le SARIF brut `<scanner>.sarif` pour la traçabilité.
- Les preuves spécifiques disponibles, par exemple
  `precision-<scanner>.json`, `trivy-targets.json`,
  `stack-coverage.json` ou `semgrep-registry-drift.json`.

Les résultats de qualité sont conservés dans les artifacts
`maintainability-*` : `maintainability.md`, jscpd, Radon et
`lizard.xml`. Les `coverage-*` éventuels proviennent exclusivement
des tests du dépôt appelant.

Les artifacts sont conservés **7 jours** ; Security CI ne publie pas
automatiquement de résultats dans **Security → Code scanning** et ne
commente pas automatiquement les PR. Les rapports de scanners autres que
Gitleaks peuvent contenir des extraits de code : vérifier les droits
d'accès aux artifacts avant de les partager.

## Contrôles de précision et de non-régression

Les workflows GitHub de ce dépôt exécutent des **contrôles positifs et
négatifs** du scanner réel, sur des fixtures synthétiques isolées :

| Outil | Contrôle positif | Contrôle négatif |
| --- | --- | --- |
| Semgrep | Appel à `eval` potentiellement risqué | Fonction Python bénigne |
| Gitleaks | Faux token de démonstration | Documentation sans secret |
| zizmor | Workflow volontairement risqué | Workflow aux droits minimaux |
| jscpd | Deux blocs réellement identiques | Fonctions distinctes |
| Trivy | Ancienne dépendance synthétique avec avis | Cibles et données bénignes vérifiées dans les canaris appropriés |

Pour Semgrep, Gitleaks et zizmor, les tests de calibration vérifient des
fixtures avec rapports SARIF réels, des fichiers attendus et des résultats
actifs, ainsi que l'absence de signalement sur les contre-exemples.
Cela mesure **ces seules fixtures** : ni taux de faux positifs global, ni
absence de faux négatifs en production.

Le workflow `.github/workflows/report-tests.yml` contrôle les
générateurs Markdown, le validateur JUnit et la parité entre certaines
versions des scripts réellement épinglées et celles testées.
`.github/workflows/engine-dependencies.yml` audite les dépendances
installées du moteur indépendamment des dépendances du dépôt source.
Le workflow principal s'exécute sur PR, push `main`, manuellement
et le lundi à 04:17 UTC ; le workflow de dépendances planifié est
déclenché le lundi à 05:23 UTC.

## Verrous et chaîne d'approvisionnement

- `locks/python-tools.txt` verrouille les dépendances Python du moteur,
  avec installations en `pip --require-hashes --only-binary=:all:`.
- `locks/gitleaks/go.mod` et `go.sum` figent la résolution Go,
  vérifiable via `go mod verify`, `GOSUMDB` et build `-mod=readonly`.
- `locks/jscpd/package-lock.json` contraint la version npm et les
  intégrités d'archives ; installation avec `npm ci --ignore-scripts`.
- `locks/engine-manifest-sha256.json` protège les empreintes des
  manifests issus de la résolution du moteur.
- Les actions GitHub et certains scripts/lockfiles chargés dans les
  workflows sont épinglés à des commits exacts.

Le workflow d'audit des dépendances moteur génère `engine.cdx.json`
(SBOM CycloneDX), `engine-provenance.json` et les manifests complets.
Il exige des cibles effectivement reconnues en Python, npm et Go et
refuse des inventaires absents. Une dérive des manifests/empreintes
nécessite une revue, mais ne prouve pas une attaque.

Ni le SBOM, ni l'intégrité de téléchargement, ni les règles Semgrep
approuvées ne garantissent l'absence de CVE, l'atteignabilité d'une
dépendance ou la couverture exhaustive.

## Déploiement contrôlé dans d'autres dépôts

Le script `scripts/rollout.sh` aide à préparer des **Pull Requests
en brouillon** dans des dépôts autorisés, sans les fusionner. Il requiert
une vraie commande de tests par dépôt dans un fichier JSON local :

```json
{
  "loic31000/mon-projet": "npm ci && npm test"
}
```

```bash
./scripts/rollout.sh SHA_COMPLET_DU_WORKFLOW '' test-commands.json
./scripts/rollout.sh SHA_COMPLET_DU_WORKFLOW --apply test-commands.json
```

La première commande ne modifie pas le dépôt distant ; `--apply`
prépare les PR de dépôts explicitement configurés. Une commande absente
entraîne l'exclusion du dépôt concerné, pas une fausse validation.
Ne jamais inclure de secrets ou fusionner automatiquement ces PR.

## Release et limites

Le [document de qualification](release-readiness.md) exige notamment :
les dix contrôles du commit candidat, de vrais rapports JUnit,
les canaris positifs/négatifs, des inventaires de dépendances,
un essai sur la branche **non fusionnée** de `local-agents` et une revue
humaine des alertes restantes. `scripts/release_readiness.py` vérifie la
complétude d'un **JSON de preuves fourni** ; il ne contacte pas GitHub,
ne signe aucune attestation et ne publie rien.

La [feuille de route](stack-expansion-roadmap.md) documente les
investigations et limites de couverture. **L'extension à d'autres
stacks est gelée pour la stabilisation**. Aucun changement de CyberHub,
des protections de branches ou de `v1.0.0` n'est prévu sans accord
explicite séparé.

Un runner GitHub public est soumis aux limites du service. Les dépôts
privés consomment les quotas de leur propriétaire. Les téléchargements
de règles Semgrep, bases Trivy, dépôts de paquets et disponibilité des
services externes peuvent modifier le résultat ou bloquer un audit.
Un audit automatisé n'est pas une garantie de sécurité ni un substitut
à une revue humaine.
