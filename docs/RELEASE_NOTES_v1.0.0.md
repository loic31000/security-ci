# Projet de notes de version v1.0.0

> Brouillon : aucune release ni tag ne doit être publié avant validation finale.

## Première version stable

- Audit de sécurité réutilisable : Semgrep (code), Trivy (dépendances/configuration),
  Gitleaks (secrets) et zizmor (GitHub Actions).
- Rapports SARIF techniques et rapports Markdown lisibles pour les développeurs :
  règle, explication, gravité et emplacement lorsque renseigné.
- Mesures de maintenabilité jscpd, Radon et Lizard avec `maintainability.md`.
- Tests optionnels du projet appelant et collecte optionnelle de couverture.
- Deux modes : rapport (alertes informatives) et strict (alertes bloquantes) ;
  les erreurs techniques restent bloquantes.
- Tests automatisés des générateurs de rapports.
- Documentation publique, guide de contribution, politique de signalement
  et licence MIT.

## Installation

Installer un workflow appelant dans **un seul dépôt à la fois**, en épinglant
`security-audit.yml` à un SHA intégral validé (voir README).
Ne pas considérer une CI verte comme une autorisation de fusionner ou déployer.

## Limites connues

- Les scanners ne garantissent pas l'absence de vulnérabilités.
- En mode rapport, la CI peut être verte même en présence d'alertes.
- Les rapports et artifacts peuvent comporter des extraits de code :
  vérifier leur contenu avant partage.
- Les métriques de maintenabilité sont informatives.
- Les tests et la couverture demandent une configuration adaptée au projet.
- Les règles externes et bases de vulnérabilités peuvent évoluer.

## Avant publication

Vérifier les workflows sur `main` **après la fusion de la PR de préparation**,
relire la licence et les notes, choisir le commit stable puis créer le tag
`v1.0.0` et la release GitHub seulement après accord explicite.
