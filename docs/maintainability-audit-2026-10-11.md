# Audit de maintenabilité et de périmètre - 11 octobre 2026

Périmètre : `loic31000/security-ci`, référence de départ
`8508be81ed1027ee5ba5c44001643021d6c5706c`.
Sources : arbre Git suivi, scripts Python/workflows/tests et **artifact CI réel**
`maintainability-38167722910-1` (ID `11712553511`) issu du
[run Security Audit 38167722910](https://github.com/loic31000/security-ci/actions/runs/38167722910).

## Résultats vérifiés

| Sujet | Constat | Décision |
| --- | --- | --- |
| Duplication jscpd | **97/97 clones** identifiés dans le rapport initial impliquent au moins un checkout généré (`.audit-*` ou `.git`). Le taux affiché de **51,2 %** mélange des copies temporaires et non du code réellement maintenu. | Exclure **uniquement les dossiers créés par le moteur** ainsi que `.git`. Conserver les contrôles positifs et négatifs. Le prochain rapport CI fait foi pour le nombre de vraies duplications. |
| Complexité Lizard | **211 fonctions** mesurées, dont **96** associées à des checkouts générés. Parmi **12 fonctions CCN >= 15**, **7** concernent les sources principales. | Appliquer les mêmes exclusions de dossiers aux fichiers analysés, et refuser un rapport qui inclurait encore ces copies. |
| Complexité Radon | **18 fonctions Python CC >= 11** dans les sources principales. Cette mesure ne présentait pas la même contamination : 29 fichiers Python analysés, aucun sous `.audit-*`. | Ne pas modifier Radon ni abaisser les seuils pour améliorer artificiellement les scores. |
| Documentation | **16 tirets cadratins** relevés dans README/roadmap/notes d'essai/critères de release ; aucune entité HTML d'espace encodé relevée dans les textes suivis examinés. | Remplacer par `-` dans ces documents et protéger par un test de style. |
| Fonctions potentiellement inutilisées | Lecture des points d'entrée `main`, imports entre scripts, références CLI dans les workflows et tests. **Aucune fonction morte démontrée** par cette inspection. | **Ne rien supprimer sans preuve d'absence d'utilisation runtime et dans les workflows SHA-pinnés.** Les scripts de QA manuelle restent utiles hors CI. |

**Attention** : `jscpd` était configuré avec des seuils stricts
(10 lignes, 100 tokens). Le rapport initial ne démontre pas une absence
universelle de duplication : il prouve que **tous les 97 signalements
affichés étaient contaminés par des copies de checkout**.
La duplication réelle après exclusion doit être mesurée sur la CI corrigée.

## Points de maintenance à traiter par priorité

1. **P0 - fiabilité des métriques** : ne plus compter les copies temporaires
   du moteur comme si elles appartenaient au projet. La CI doit vérifier
   l'absence de chemins générés dans les rapports jscpd et Lizard.
2. **P1 - grosses fonctions à comprendre avant de refactorer** :
   `release_readiness.validate` (Radon **52**),
   `scanner_precision._active_results` (**39**) et
   `semgrep_drift_metadata.inspect_payload` (**29**).
   Ce sont des zones de risque de maintenance, **pas des bugs démontrés**.
   Préserver les tests adversariaux et les décisions fail-closed avant
   toute extraction de fonctions.
3. **P1 - passages complexes sur les chemins de cibles** :
   `stack_coverage.expected_manifests` et `stack_coverage.summarize`
   (Radon **18** chacune), puis les rendus et sondes Java.
   Ne pas étendre les stacks avant d'avoir établi les besoins réels.
4. **Scalabilité / temps de CI** : plusieurs checkouts SHA-pinnés et
   installations de dépendances sont répétés sur les jobs. Ils
   garantissent l'intégrité, mais augmentent les fichiers parcourus,
   le temps runner et le bruit dans les métriques. Écarter les
   copies du champ d'analyse ne change **ni ces garanties ni la durée
   réelle des téléchargements**. Toute optimisation de jobs doit être
   une PR distincte avec preuves de temps et de non-régression.

## Ce qui n'a pas été fait

- Aucune suppression de fonction sur une simple heuristique de nom.
- Aucun changement de scanner, de couverture, de verrou ou de politique
  d'exécution Semgrep. Son [incident fournisseur #29](https://github.com/loic31000/security-ci/issues/29)
  reste indépendant de cet audit.
- Aucune modification de dépôt appelant, branche protégée, CyberHub
  ou publication de `v1.0.0`.

Le gel fonctionnel reste actif. Les scores de complexité servent à
**prioriser des revues ciblées**, et non à justifier une refonte générale
du moteur.
