# 🕰️ Historique des versions

Index. Le détail de chaque version vit dans `docs/Version/`, un dossier par
version majeure et un fichier par version mineure.

> **Ordre inversé** : la version la plus récente est en haut, ici comme dans
> chaque fichier.

---

## [Cycle 2.1 — refactorisation](./Version/2.0/2.1.md)

Unification CLI/web derrière le registre d'actions, filtrage des lectures par domaine, sélecteur d'entités du portail.

Contient : 🚧 non publié, Alpha 2.1.0.

## [Alpha 2.0.0 « PIG » — 02/08/2026](./Version/2.0/2.0.md)

Deux audits de sécurité : élévation de privilèges RBAC, `ClientSoftwareID` figé, anti-rejeu API, sessions web.

Contient : Alpha 2.0.0.

## [Cycle 1.1 — 16/04/2025 → 20/07/2026](./Version/1.0/1.1.md)

GPO Linux, plugin LDAP puis LDAPS, portail web, début de l'API REST, clés publiques utilisateur.

Contient : Alpha 1.1.4, Alpha 1.1.3, Alpha 1.1.2, Alpha 1.1.1, Alpha 1.1.0.

## [Cycle 1.0 « ROCKET » — 06/03/2025 → 15/03/2025](./Version/1.0/1.0.md)

Premières versions : commandes serveur, administrateurs locaux, permissions et groupes.

Contient : Alpha 1.0.2, Alpha 1.0.1, Alpha 1.0.

---

## Convention

- Un dossier par version **majeure** : `docs/Version/1.0/`, `docs/Version/2.0/`.
- Un fichier par version **mineure** : `1.0.md`, `1.1.md`, `2.0.md`, `2.1.md`.
- Les correctifs d'une même mineure sont regroupés dans son fichier, du plus
  récent au plus ancien.
- Toute modification doit être consignée dans le fichier de la version en cours
  — voir `CONTRIBUTING.MD`. Une tâche terminée se déplace de
  `docs/Developement/TO-DO.md` vers `docs/Developement/DO/<version>/`.
