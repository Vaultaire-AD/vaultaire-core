# Guide de Contribution - Vaultaire Core

Bienvenue dans le dépôt Vaultaire Core ! Ce guide explique comment organiser votre travail, collaborer efficacement et respecter les bonnes pratiques du projet.

## Project Status

Vaultaire Core is currently in **ALPHA**.

- Linux integration: partial (Rocky Linux only at the moment)
- SSH first-login: work in progress
- LDAP: functional with TLS (tested with Keycloak, pfSense)
- Known issues: username@domain handling (being patched)

⚠️ Not production-ready.
---

## 1. Workflow Git & gestion des branches

Nous utilisons un modèle inspiré de **Gitflow** adapté :

- **`main`**  
  Branche stable de production.  
  *Ne pas pousser directement sur `main`. Toutes les modifications doivent passer par `preprod` puis être fusionnées via PR.*

- **`preprod`**  
  Environnement de préproduction pour tests finaux.  
  Fusionner ici depuis la branche `dev` après revue et tests.

- **`dev`**  
  Branche active de développement pour intégrer les nouvelles fonctionnalités.  
  Travailler principalement ici en fusionnant vos branches de fonctionnalités.

- **Branches de travail**  
  - **Features** : `feature/<description>-<numero-issue-du-project>`  
  - **Correctifs urgents** : `hotfix/<description>-<numero-issue-du-project>`  
  - **Expérimentations** : `experiment/<description>-<numero-issue-du-project>`

---

## 2. Création et gestion des branches

- **Créer une branche à partir de `dev`** pour toute nouvelle fonctionnalité ou correction.  
- Nommez clairement votre branche, par exemple :  
  - `feature/ajout-authentification-ssh-19`  
  - `hotfix/correction-bug-ldap-26`  
- **Faire des commits atomiques et bien nommés** (ex : `fix: corrige l’erreur de connexion LDAP`)  
- Poussez la branche sur le dépôt distant régulièrement.

## 2.1 Commits atomiques et messages clairs

Un **commit atomique** signifie que chaque commit :  
- Réalise une seule modification cohérente et complète (ex : correction d’un bug précis, ajout d’une fonctionnalité unique).  
- Ne mélange pas plusieurs sujets différents dans le même commit.  
- Facilite la lecture, la compréhension et le retour arrière si besoin.

### Pourquoi c’est important

- **Relecture plus simple** : chaque modification est ciblée et isolée.  
- **Gestion des versions** : possibilité de revenir précisément sur un changement sans casser d’autres parties.  
- **Historique clair** : les messages de commit reflètent bien ce qui a été fait.  
- **CI efficace** : tests automatisés associés à des changements précis.

### Exemple de messages de commit

Nous utilisons un format simple inspiré de [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) :  
```git
<type>[optional scope]: <description>
```

#### Types courants :

- **feat** : ajout d’une nouvelle fonctionnalité  
- **fix** : correction d’un bug  
- **docs** : modification ou ajout dans la documentation  
- **style** : modification de formatage, indentation, espaces, sans changement fonctionnel  
- **refactor** : modification du code sans ajout ni correction de fonctionnalité  
- **test** : ajout ou correction de tests  
- **chore** : tâches diverses, mise à jour des dépendances, scripts, etc.

#### Exemples :

- `feat(auth): ajout support clé SSH pour authentification`  
- `fix(ldap): corrige erreur de connexion en cas de timeout`  
- `docs: mise à jour du guide d’installation`  
- `style: correction indentation dans main.go`  
- `refactor(dns): simplification des fonctions de résolution`  
- `test: ajout tests unitaires pour gestion GPO`  
- `chore: mise à jour version Go vers 1.20`

### Bonnes pratiques

- Faites un commit **par fonctionnalité ou correction**.  
- Regroupez les changements qui vont ensemble logiquement.
- Ne pas oublier de crée les fichier de [test](./docs/write-test.md)
- Évitez les commits avec des dizaines de fichiers modifiés pour des raisons très différentes.  
- Rédigez un message clair et concis, en anglais ou français selon votre préférence d’équipe.  
- Utilisez l’impératif dans la description (ex : "Ajoute", "Corrige", "Mets à jour").  
- Si nécessaire, ajoutez une description plus détaillée dans le corps du commit (séparée par une ligne vide).

---

Cette rigueur dans les commits rendra la collaboration et la maintenance du projet bien plus fluides.


---

## 3. Pull Requests (PR)

- Ouvrez une PR **vers la branche `dev`** quand votre fonctionnalité est prête.  
- Assurez-vous que :  
  - Les tests passent (unitaires, lint)  
  - Le code respecte les conventions (formatage, commentaires)  
  - La documentation est mise à jour si besoin  
- Demandez une revue de code à au moins un autre membre de l’équipe.  
- Corrigez les retours avant fusion.

---

## 4. Tests et CI

- Tous les tests unitaires doivent être ajoutés ou mis à jour pour couvrir votre code.  
- La CI lancera automatiquement linting, tests et build.  
- En cas d’échec, corrigez avant de fusionner.

---

## 5. Documentation

- Mettez à jour la documentation dans `docs/` selon les évolutions.  
- Ajoutez des guides ou explications pour toute nouvelle fonctionnalité importante.  
- N’oubliez pas de mettre à jour le fichier `docs/Version_History.md` avec votre username svp.

---

## 6. Bonnes pratiques

- Communiquez régulièrement sur l’avancement.  
- Evitez les gros commits non détaillés.  
- Gardez les PRs aussi petites et ciblées que possible.  
- Respectez les deadlines et les priorités du backlog.

---

Merci pour votre contribution !  
Votre rigueur garantit la qualité et la pérennité de Vaultaire.

---

*Vaultaire Team*
