# Préparation d'une première version stable — critères vérifiables

Ce document prépare une future version `v1.0.0` de **security-ci**, sans créer
de tag, de release GitHub ou de déploiement.

## Critères de qualification

1. Le commit exact candidat est connu et **tous les 10 jobs GitHub Actions** du
   moteur ont terminé avec succès : quatre scanners, ShellCheck, actionlint,
   maintenabilité, tests du projet, rapports et dépendances Python/Node/Go.
2. Au moins **58 cas de tests JUnit réellement exécutés** et validés avec
   preuve du workflow Report generator tests. Des tests factices ou sautés
   ne constituent pas une preuve.
3. Les contrôles positifs de **Semgrep, Gitleaks, zizmor, jscpd et Trivy**
   montrent des détections sur des exemples synthétiques isolés.
4. Les quatre contrôles **négatifs** de Semgrep, Gitleaks, zizmor et jscpd
   analysent des exemples légitimes et produisent **zéro signalement**.
   Cela ne démontre ni que les scanners n'ont aucun faux positif, ni qu'une
   exécution sur un projet réel est entièrement saine.
5. L'audit des dépendances reconnaît **les trois cibles Python, Node et Go**,
   conserve l'intégralité des manifests et un SBOM CycloneDX non vide, et
   documente les alertes éventuelles comme **candidates à vérifier**. La
   revue humaine des avis CVE est obligatoire ; le nombre d'alertes n'est
   pas transformé automatiquement en critère « zéro faille ».
6. Une exécution réelle de `security-ci` sur
   **`loic31000/local-agents`**, effectuée sur une branche
   `audit/security-ci-...` **qui n'a jamais été fusionnée**, est documentée
   avec commit, URL GitHub Actions, résultat des vrais tests et analyse
   différenciant les alertes et les problèmes d'outillage.
7. Les instructions d'intégration, les versions et les verrous de
   dépendances sont explicites. Aucune règle de protection de branche ne
   change sans une demande séparée du propriétaire.

## Vérificateur de complétude

Le script `scripts/release_readiness.py` accepte un JSON de preuves contenant
les dix statuts GitHub, les nombres de tests et cibles, les cinq contrôles
positifs, les quatre négatifs, les URL exactes des exécutions et l'essai
externe non fusionné :

```bash
python3 scripts/release_readiness.py --evidence chemin/vers/preuves-verifiees.json
```

Une pièce absente, un test inexécuté ou une branche externe fusionnée est
traitée comme **non prêt**. Le JSON doit être construit **à partir de données
GitHub consultées, puis vérifiées manuellement** : ce contrôle de complétude
n'est pas un système d'attestation cryptographique. Les artefacts SARIF et
CycloneDX servent à étayer les valeurs, et non à masquer des alertes.

## Procédure de publication future

Examiner le diff de la dernière PR et les résultats sur `main` ;
examiner individuellement toute alerte restante et consigner les
justifications ; vérifier la version figée du workflow réutilisable par SHA,
le schéma des paramètres `workflow_call`, les droits GitHub minimaux et les
limitations documentées ; **alors seulement** envisager un tag signé ou
une release GitHub, dans une demande séparée.

Les résultats d'un scan ne garantissent pas l'absence de vulnérabilité. Une
mise à jour des règles Semgrep ou de la base Trivy peut légitimement modifier
les détections, sans que les changements ne soient automatiquement des bugs
ou des attaques.

**Hors périmètre permanent sans autorisation nouvelle :** CyberHub et
protection de `main`. L'essai local-agents n'est jamais fusionné.
