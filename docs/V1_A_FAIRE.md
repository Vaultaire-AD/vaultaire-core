# V1 — Ce qu’il reste à faire

Liste stricte des actions à mener pour une V1 propre. Aucun commentaire superflu.

---

## Code & build

- ~~Remplacer le module Go `DUCKY` par le module déclaré dans `go.mod`~~ → fait : module `vaultaire`, imports `vaultaire/serveur/...`.
- Rendre les chemins web (templates, static) configurables ou utiliser `embed` pour ne plus dépendre du répertoire de travail.
- ~~Corriger la typo : `GetUserIDByUserneme.go` → `GetUserIDByUsername.go`~~ → fait.
- ~~Unifier l’usage des logs~~ → fait : `Write_Log(level, content)` conservé ; `Write_LogCode(level, code, content)` + codes dans `logs/error_codes.go` (standard VLT-XXX).
- Vérifier que `SendMessage` côté serveur envoie bien au bon destinataire (connexion vs routage par `ClientSoftwareID`).

---

## Sécurité

- Supprimer ou externaliser les identifiants en dur (admin, vaultaire) : fichier protégé, variables d’environnement ou secret manager.
- Désactiver par défaut en prod : `debug`, `ldap_debug` ; documenter le passage en prod dans la config.
- Échapper le mot de passe dans `pam_login_custom_module.c` (chpasswd) pour éviter l’injection.
- Ne pas exposer le port Ducky (ex. 6666) sur Internet ; documenter la restriction (réseau interne / VPN).

---

## Configuration & déploiement

- Documenter un exemple de `serveur_conf.yaml` pour la prod (sans mots de passe ni clés).
- Rendre le chemin de `serveur_conf.yaml` et de `client_conf.yaml` / `client_software.yaml` configurables (flag, env ou config).
- Fournir un unit systemd (ou équivalent) pour vaultaire_client et le documenter.
- Vérifier que la CI (Go build, tests) passe sur une branche propre.

---

## Base de données

- Vérifier les migrations / schéma : une seule source de vérité (scripts SQL ou outil de migration) pour créer/mettre à jour les tables.
- S’assurer que le nettoyage des sessions (`CleanUpExpiredSessions`) et la suppression des entrées à la déconnexion (Ducky, close session) sont cohérents.

---

## Tests

- ~~Package de tests critiques~~ → fait : `vaultaire/serveur/testrunner`. Lancer avec **`vaultaire --test`** (ou `./vaultaire_serveur --test`). Tests : SanitizeInput, SplitArgsPreserveBlocks, ParsePermissionContent, ExecuteCommand (help, inconnu), optionnel DB.Ping si DB initialisée.
- Ajouter des tests unitaires pour les commandes create, get, update, delete (user, group, permission), et pour `DidUserCanLogin` (avec DB de test ou mock).
- Ajouter des tests pour les handlers DNS (create_zone, add_record, validation).
- Tester le flux PAM (check SSH) de bout en bout dans un environnement dédié (ou script d’intégration).

---

## Documentation

- Mettre à jour le README racine : structure du repo, prérequis, commandes de build/run, lien vers Setup et MAN.
- Documenter le déploiement type : install serveur, création client (`create -c`, `-join`), déploiement client (fichiers YAML, binaire, PAM, sshd).
- Aligner la doc (MAN, WIKI_Manual) avec le comportement réel des commandes et de l’API.
- Mettre à jour `Version_History.md` et définir un numéro de version V1 (tag Git).

---

## Nettoyage

- Supprimer ou archiver le code mort et les fichiers de démo (clés, configs avec secrets).
- Vérifier qu’il n’y a qu’un seul emplacement pour les assets web (éviter la duplication `cmd/` vs racine).
- Corriger les noms de fichiers ou de symboles offensants ou non professionnels s’il en reste.
