# Feuille de route : calibration des scanners puis couverture multi-stacks

## Priorité actuelle — fiabilité démontrable (P0)

La CI doit vérifier la **qualité du moteur d'audit**, et non attribuer automatiquement
des vulnérabilités confirmées aux projets analysés.

La calibration utilise les vrais outils Semgrep, Gitleaks et zizmor sur des
fixtures synthétiques **isolées du dépôt appelant** :

1. Un exemple étiqueté **détectable** doit produire une alerte active à l'emplacement attendu.
2. Un exemple étiqueté **bénin** doit produire zéro résultat brut, même informatif.
3. SARIF absent/invalide, configuration/scan en erreur, résultat supprimé ou
   signalement dans un mauvais fichier doivent être rejetés.
4. Les preuves JSON ne contiennent ni code, ni texte d'alerte, ni potentiel secret.
   Elles mesurent le nombre de **fixtures** TP/TN/FP/FN, pas un taux de précision
   ou de rappel généralisable à des projets réels.
5. Le code du validateur réellement utilisé dans le workflow réutilisable
   doit être identique à celui testé, via une comparaison des commits épinglés.

Ces contrôles **ne prétendent pas** mesurer les faux négatifs à l'échelle d'un
programme, l'exploitabilité ni une couverture parfaite. Les mises à jour des
règles Semgrep et bases CVE peuvent modifier les résultats légitimement.

La seconde campagne de calibration exécute désormais **deux paires
positives/négatives par scanner**, avec bilan agrégé et identité SARIF vérifiée.
Les deux exemples positifs peuvent partager une même classe de règle : cela
prouve la robustesse de l'intégration, pas deux familles de vulnérabilités.

La prochaine étape consiste à diversifier les catégories de règles et les
fixtures indépendantes en nombre suffisant pour mesurer séparément : les chemins positifs, les faux signalements
sur code bénin, les erreurs de configuration, les exclusions et les changements
de versions, avec revue humaine de tout échec inattendu.

## Diagnostic de provenance Semgrep — blocage P0

Lorsque les trois tentatives du registre échouent à obtenir les **225 règles
à l'empreinte SHA-256 approuvée**, le scan reste en **échec technique**.
L'artifact d'échec `security-semgrep-*` peut maintenant contenir
`semgrep-registry-drift.json` avec seulement : SHA approuvé/observé,
taille, format observé (YAML/JSON/inconnu), nombre d'IDs lus,
nombre d'IDs distincts et empreinte d'IDs triés. Une réponse JSON peut
être examinée **pour le diagnostic seulement** : elle ne correspond pas à
l'empreinte du profil YAML approuvé et ne sera jamais exécutée.
**Aucun texte de règle, message, identifiant de règle ou extrait de code
n'est reproduit.** Cette preuve sert à différencier la dérive des règles,
les réponses malformées et les problèmes d'infrastructure. Elle **ne
constitue jamais une nouvelle approbation** du registre. Le profil original
n'est pas conservé dans les artifacts.

L'[incident #29](https://github.com/loic31000/security-ci/issues/29) doit
être qualifié avant changement du SHA de référence. Les conditions de la
licence Semgrep Rules interdisent de redistribuer les règles dans le dépôt.
La stabilité du registre reste une limite de disponibilité indépendante
de la précision des scanners.

## Étape suivante — étendre les stacks sans créer de faux « zéro alerte » (P1)

Ordre proposé, **à réévaluer avec les usages réels** :

| Lot | Écosystèmes / manifests | Preuves minimales requises |
| --- | --- | --- |
| A | Java / Kotlin : Maven `pom.xml`, Gradle `*gradle.lockfile` (un simple `build.gradle` ne prouve pas la couverture de dépendances) | Inventaire reconnu par le scanner, fixture vulnérable et saine, traçage version/règle |
| B | .NET / C# : `*.csproj`, `packages.lock.json` | Dépendances résolues et cible identifiée ; tests sur lock absent/incomplet |
| C | Rust : `Cargo.toml`, `Cargo.lock` | Dépendances avec versions réelles, canary positif et négatif |
| D | Ruby : `Gemfile.lock`, PHP : `composer.lock` | Cibles reconnues distinctement ; tests d'avis et cas hors périmètre |
| E | IaC : Terraform HCL, Kubernetes, Dockerfile, GitHub Actions | Distinction configuration valide/risquée, couverture par langage et exclusions |

Semgrep et Trivy savent déjà analyser **certains** fichiers de ces langages :
ajouter leur nom à une liste n'établit **aucune** couverture réelle. Toute
activation d'une famille devra établir :

- Reconnaissance effective des manifests et nombre de cibles, avec
  `SCANNED`, `NOT_APPLICABLE`, `UNSUPPORTED` et `ERROR` distincts ;
- Règles pertinentes et versions/outils vérifiés avant de les utiliser ;
- Contrôles positifs et négatifs sur plusieurs cas, dont un cas de lock absent
  et un cas de mauvais chemin ou de résultat incomplet ;
- Sorties SARIF et, lorsque pertinent, SBOM validés et suffisamment renseignés
  pour une revue, sans fuite d'identifiants ;
- Comparaison d'un essai sur branche isolée avec une baseline connue, sans
  fusionner des changements dans le dépôt d'essai.

## Preuves généralisées de couverture des dépendances — phase P0/P1

Le job Trivy du workflow réutilisable produit désormais un artifact
`stack-coverage.json` fondé sur les **noms des manifests du dépôt appelant**
et les **cibles réellement reconnues** dans `trivy-targets.json`.
Pour chaque famille reconnue (Go modules, Python requirements, npm, pnpm,
Maven `pom.xml`, Gradle lock, Cargo.lock, Gemfile.lock, composer.lock),
le script distingue :

- `SCANNED` : tous les manifests de cette famille ont la cible Trivy
  exacte et l'analyseur de dépendances attendu ;
- `INCOMPLETE` : au moins un manifest existe sans cible/analyseur
  correspondant, et le contrôle échoue pour ne pas produire un faux vert ;
- `NOT_APPLICABLE` : aucun manifest pertinent trouvé ;
- `MANIFEST_ONLY` : exemple `build.gradle`, `Cargo.toml` ou
  `package.json` sans verrou reconnu, ne valant **pas couverture** ;
- `UNVERIFIED` : .NET `*.csproj` ou `packages.lock.json` présents,
  mais aucun analyseur NuGet validé à cette étape.

Les cibles générées, dépendances dans les fichiers ignorés (vendor,
node_modules, .audit-*), symlinks et chemins inappropriés ne peuvent pas
démontrer une couverture. Seuls les **comptages par famille** sont archivés,
sans chemins de fichiers ni texte de détection. Un `SCANNED` ne signifie
ni « pas de vulnérabilité » ni « toutes les dépendances transitives vues ».
Le code effectif est épinglé par SHA et comparé au script testé sur PR.
Les familles non encore vérifiées restent explicitement hors couverture,
notamment les projets .NET sans preuve NuGet.

## Règles de livraison

Les améliorations du moteur passent par PR et ses contrôles GitHub Actions,
puis validation post-fusion. Aucun changement de CyberHub ni des protections
de `main`. `local-agents` reste uniquement un banc de validation sur sa
branche `audit/security-ci-fp-validation-20261011`, jamais fusionnée et
sans correction de son code applicatif. Pas de tag `v1.0.0` sans décision
de qualification explicite et preuves vérifiées.
