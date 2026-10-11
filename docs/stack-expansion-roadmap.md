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

### Lot A.1 — expérimentation Java/Gradle (pas encore couverture générale)

Le job de dépendances du moteur expérimente maintenant **Trivy v0.70.0**
sur deux verrous Gradle générés dans le runner : une dépendance
`log4j-core:2.14.1` volontairement exposée aux avis connus et une
dépendance de démonstration bénigne `slf4j-api:2.0.17`. Les deux rapports
JSON doivent **reconnaître exactement `gradle.lockfile` comme cible** ;
l'outil doit identifier l'ancienne version de Log4j en HIGH/CRITICAL et
ne produire aucun avis sur la fixture bénigne. Le garde
`scripts/java_gradle_probe.py` rejette un inventaire absent, une cible
mal nommée, un mauvais type d'analyse ou un paquet/version erroné.
Les rapports et le bilan JSON sont conservés comme preuves.

**Aucune de ces observations ne prouve** la couverture Java/Kotlin
source, Maven, les dépendances transitives ou les failles exploitables.
Seul le comportement de Trivy sur ces deux verrous isolés est évalué.
Le lot A.2 restera consacré à Maven `pom.xml` et à ses particularités
de résolution distant/locale. Un blocage réseau Maven ne doit jamais
être décrit comme un scan réussi ou zéro alerte.

## Règles de livraison

Les améliorations du moteur passent par PR et ses contrôles GitHub Actions,
puis validation post-fusion. Aucun changement de CyberHub ni des protections
de `main`. `local-agents` reste uniquement un banc de validation sur sa
branche `audit/security-ci-fp-validation-20261011`, jamais fusionnée et
sans correction de son code applicatif. Pas de tag `v1.0.0` sans décision
de qualification explicite et preuves vérifiées.
