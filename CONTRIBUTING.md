# Contribuer à Security CI

Merci de contribuer à l'amélioration des audits et de leurs rapports.

## Avant de commencer

1. Ouvrir une issue expliquant le problème, ou discuter des changements importants avant de coder.
2. Créer une branche à partir de `main` dans votre fork.
3. Garder les modifications ciblées : un correctif ou une fonctionnalité par Pull Request.
4. Ne jamais ajouter de secrets, de rapports contenant des identifiants actifs ni de données privées.

## Vérifications locales

Les scripts de rapports ne nécessitent que Python 3 :

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

Toute évolution du format Markdown doit inclure des tests couvrant les localisations,
les rapports manquants ou invalides et l'absence de fuite de secrets.

## Pull Requests

Décrire le problème, le changement, les conséquences possibles et les tests effectués.
Les workflows GitHub Actions servent de validation ; un résultat vert en mode rapport
ne signifie pas absence de vulnérabilités. Ne pas demander de fusion si les tests
pertinents échouent.

## Portée des contributions

Les résultats Semgrep, Trivy, Gitleaks et zizmor sont indicatifs : éviter de
présenter chaque alerte comme une vulnérabilité prouvée. Ne pas supprimer
silencieusement les vérifications d'erreurs techniques ou l'anonymisation des secrets.
