# Essai réel sur local-agents — branche strictement non fusionnable

**Objet :** évaluer le moteur `security-ci` sur un vrai projet
Go/Python/React, sans modifier ni fusionner `local-agents/main`.

- Dépôt cible : https://github.com/loic31000/local-agents
- Base : `main` au commit `dbf977807c0aa5edcb66b622798471b0e5abc5e6`
- Branche créée : `audit/security-ci-fp-validation-20261011`
- Fichier ajouté **uniquement sur cette branche** :
  `.github/workflows/security-ci-isolated-trial.yml`
- Commande de **vrais tests Go** prévue :
  `go test -v ./tests/unit -run "^TestBackendRouter_" -count=1`
- Exécution 1 : https://github.com/loic31000/local-agents/actions/runs/38129380823
- Exécution 2 avec un job de diagnostic direct :
  https://github.com/loic31000/local-agents/actions/runs/38129449946

## Résultat observé

**L'exécution externe n'est PAS validée.** Les deux exécutions ont échoué
avant l'attribution d'un runner : les jobs enregistrent une durée d'environ
une à deux secondes, un champ runner vide, **aucune étape exécutée**,
et aucun rapport de scanner ni de tests Go. Le job de diagnostic autonome
a échoué de la même manière.

C'est une **limitation d'exécution GitHub Actions non diagnostiquée** ;
les données disponibles ne permettent pas d'affirmer si elle vient
de paramètres du compte, de quotas/facturation ou des runners.
**Ce n'est ni une preuve de vulnérabilité du projet ni un résultat
« zéro alerte »**.

La branche de test reste en place pour un diagnostic ultérieur, **sans PR,
sans fusion, sans altération de `main`**. Une fois les runners utilisables,
mettre à jour le commit de Security CI vers le squash merge final,
déclencher une nouvelle exécution et examiner les rapports effectifs.

En conséquence, le critère de release `external_trial.status=success`
doit rester **non satisfait**. Ne pas publier de `v1.0.0` tant que cet
essai n'a pas été réellement exécuté et interprété.
