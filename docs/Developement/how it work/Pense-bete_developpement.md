[⌂ Documentation](../../README.md) › [how it work](./README.md) › Pense-bête

# Pense-bête — ajouter une fonctionnalité ou corriger un défaut

À lire en une minute, avant de commencer et avant de commiter. Les détails sont
ailleurs ; ici, seulement l'ordre des gestes et ce qu'on oublie.

---

## 1. Journaliser la tâche

Une entrée dans [`TO-DO.md`](../TO-DO.md), **avant** d'écrire du code. Numéro
neuf, pris au compteur « prochain libre » en tête du fichier — et ce compteur
est mis à jour dans le même geste. L'entrée dit le **contexte** et ce qui est
attendu, pas la solution.

Rien de ce qui est traité ne doit être absent de ce fichier : c'est là qu'on
regarde pour savoir ce qui a été décidé, et une tâche faite sans entrée ne
laisse aucune trace de son pourquoi.

## 2. Traiter la tâche

- Le **commentaire dit pourquoi**, le code dit comment. Un bloc non évident
  porte au-dessus de lui la décision qu'il applique et ce qu'elle écarte.
- **Français** partout : commentaires, messages d'erreur, journaux, documentation.
- Un défaut trouvé en chemin et non traité **repart en TO-DO** sous un numéro
  neuf. On ne l'écrit pas « pour plus tard » dans un commentaire.
- Traitement partiel : ce qui reste prend un numéro **neuf** — jamais l'ancien,
  qui se lirait comme une tâche entière non commencée.

## 3. Les tests

- Un test par règle que le code promet, et son message d'échec nomme la
  **conséquence**.
- `cd src/<module> && go test ./...` sur chaque module touché, plus
  `ducky-network-sdk-service` si le protocole bouge. `-race` dès qu'il y a des
  goroutines.
- `gofmt -l .` doit être **vide**. L'intégration continue le vérifie ; elle ne
  lance aucun test (TO-DO 75), donc ce passage-là n'est fait que par vous.
- Un test-sentinelle qui rougit se traite, il ne se contourne pas. Voir
  [`Tests.md`](./Tests.md).

## 4. Mettre à jour les documents impactés

Dans le même passage que le code — pas « après ».

| Si vous avez touché à… | Mettez à jour |
|---|---|
| une action, un droit | [`Utilisation/Actions_et_Permissions.md`](../../Utilisation/Actions_et_Permissions.md), [`Utilisation/MAN.md`](../../Utilisation/MAN.md) |
| une commande `vlt` | [`Utilisation/MAN.md`](../../Utilisation/MAN.md), et la formation si le geste est enseigné |
| une trame Ducky | le chapitre de [`ducky-network/`](./ducky-network/README.md) correspondant |
| le cluster, le proxy, le relais | [`docs/proxy/`](../../proxy/README.md) et `ducky-network/04-cluster/` |
| les GPO | [`GPO.md`](./GPO.md) |
| le schéma de base | [`Base_de_donnees.md`](./Base_de_donnees.md) |
| un déploiement, un conteneur | le `README.md` du dossier dans `deployments/` |
| une dépendance (ajout, retrait, montée de version) | `./automatisation/dependances.sh`, et l'explication dans [`dependances.roles`](../dependances.roles) |
| un mot de vocabulaire | [`Utilisation/Lexique.md`](../../Utilisation/Lexique.md) |
| une nouvelle page de doc | l'index [`docs/README.md`](../../README.md) |

Règle du lecteur, pas du sujet : « comment ça marche » va dans
`how it work/`, « que taper » dans `Utilisation/`, « comment l'exploiter » dans
`exploitation/`. Un même sujet peut avoir une page dans chacun.

## 5. Clore la tâche

Trois gestes, toujours dans le même passage :

1. **Retirer** l'entrée de `TO-DO.md` et l'écrire dans
   `DO/<version en cours>/<version>.md` : ce qui a été fait, ce qui a été
   mesuré, ce qui n'a **pas** été traité.
2. **Renuméroter** ce qui reste (numéro neuf) et mettre à jour le compteur.
3. **Consigner** en haut de `docs/Version/<majeure>/<mineure>.md`, en une ligne
   qui parle à un exploitant, pas à un compilateur.

Si ce n'est pas encore validé sur une vraie machine, ajoutez la manœuvre à
[`exploitation/A_TESTER.md`](../../exploitation/A_TESTER.md) : « FAIT-IA » veut
dire *écrit*, pas *validé*.

## 6. Commiter

Branche de travail (`feature/…`, `hotfix/…`) — jamais directement sur `main` ni
`preprod` ; voir [`CONTRIBUTING.MD`](../../../CONTRIBUTING.MD). Le message dit
le **quoi** et le **pourquoi**, et cite le numéro de tâche.

---

## Ce qu'on oublie le plus souvent

- Le compteur « prochain libre » de `TO-DO.md`.
- La ligne dans `Version/<…>.md` : sans elle, le changement n'existe pour
  personne en dehors du code.
- Le **relevé** des défauts croisés en chemin : c'est ainsi qu'ils se perdent.
- `gofmt`, parce que rien ne le rappelle avant l'intégration continue.
- La page de formation quand le geste enseigné change.
- Un changement de version de série : la procédure est dans
  [`exploitation/Changement_de_version.md`](../../exploitation/Changement_de_version.md).
