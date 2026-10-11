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

La prochaine étape consiste à ajouter des fixtures indépendantes en nombre
suffisant pour mesurer séparément : les chemins positifs, les faux signalements
sur code bénin, les erreurs de configuration, les exclusions et les changements
de versions, avec revue humaine de tout échec inattendu.

## Étape suivante — étendre les stacks sans créer de faux « zéro alerte » (P1)

Ordre proposé, **à réévaluer avec les usages réels** :

| Lot | Écosystèmes / manifests | Preuves minimales requises |
| --- | --- | --- |
| A | Java / Kotlin : Maven `pom.xml`, Gradle `*.gradle`, verrous si présents | Inventaire reconnu par le scanner, fixture vulnérable et saine, traçage version/règle |
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

## Règles de livraison

Les améliorations du moteur passent par PR et ses contrôles GitHub Actions,
puis validation post-fusion. Aucun changement de CyberHub ni des protections
de `main`. `local-agents` reste uniquement un banc de validation sur sa
branche `audit/security-ci-fp-validation-20261011`, jamais fusionnée et
sans correction de son code applicatif. Pas de tag `v1.0.0` sans décision
de qualification explicite et preuves vérifiées.
