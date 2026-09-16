# TO-DO — Vaultaire

> **Ce fichier ne contient que ce qui reste à faire.** Une tâche terminée le quitte.

## Convention

Trois gestes, dans le même passage que le code :

1. **Supprimer** l'entrée d'ici et l'écrire dans `DO/<version en cours>/<version>.md`, avec ce qui a été fait, ce qui a été mesuré, et ce qui n'a pas été traité.
2. **Re-numéroter le reste** : une partie non traitée revient ici sous un numéro **neuf** — jamais l'ancien, qui se lirait comme une tâche entière non commencée.
3. **Consigner** le changement en haut de `docs/Version/<majeure>/<mineure>.md`.

`DO/` est l'archive, `Version/` le compte rendu, ce fichier la liste de courses.

**Numérotation.** Les numéros sont uniques et croissants : le prochain libre est **54**. Avant la 49, des numéros ont servi plusieurs fois (par exemple trois « 12 » dans `DO/2.1/2.1.md`) ; pour les citer sans ambiguïté, écrire la version et le titre : « 2.1 #12 — create permission ».

**Statut.** « FAIT-IA » veut dire *écrit*, pas *validé*. Tant qu'un point figure dans `docs/exploitation/A_TESTER.md`, il n'a pas été compilé ni exécuté sur une vraie machine.

---

## Vue d'ensemble

| #  | Domaine | Sujet | État |
|----|---------|-------|------|
| 38 | DUCKY / PROXY | Relais TCP Ducky puis LDAP/S (lots 4 et 5) | À faire — spécifié |
| 33 | GPO | La dérive du scope utilisateur n'est jamais scannée | À faire |
| 22 | SELINUX | Domaine dédié pour l'agent | En cours |
| 49 | RÉVOCATION | Retenter les révocations poussées en échec | À faire |
| 50 | GPO | Déclencher un cycle hors du tour horaire | À faire |
| 51 | GPO | Intervalle de rafraîchissement configurable | À faire |
| 52 | GPO | Signature des politiques par le core | À faire |
| 53 | GPO | Persister les rapports d'application en base | À faire |
| 8  | LDAP | Mode synchro avec un annuaire existant | Idée |
| 40 | AGENT-UPDATE | Mettre à jour le parc de clients | Idée — à trancher |

---

## Réseau Ducky

### 38. [DUCKY] [PROXY] Le relais — il ne reste que lui

**Contexte.** Reste des points 9 et 10 (découverte de service et proxy). Les lots 0 à 3, puis 6 et 7 sont traités (voir `DO/2.1/2.1.md`, entrées 47 et 48) : l'affinité nœud ↔ groupe trie la liste servie, et une clé d'enrôlement porte les groupes de naissance d'un service. Les lots 4 et 5 n'en dépendent pas : le tri décide de **qui** on joint, le relais de ce qui se passe **une fois joint**.

**Aujourd'hui** le proxy est visible du cluster et connaît ses cores, mais **ne transporte aucun octet**.

**Spécification :** `how it work/Protocole_Ducky.md`, section « Le relais ». Les arbitrages 2, 5 et 6 y sont rendus et validés.

- **Lot 4 — relais TCP Ducky.**
  - Le proxy transporte les octets **sans les lire** et ne termine **pas** la session (arbitrage 2) : depuis le point 29, le mot de passe transite dans le tunnel, un proxy qui déchiffrerait deviendrait un point de collecte des mots de passe du parc.
  - Si tous ses cores sont injoignables, le proxy **refuse franchement**. Le client essaie alors le suivant de sa liste — un core, puisqu'ils y figurent toujours. Un proxy qui ferait attendre deviendrait un trou noir.
  - Code réseau neuf sur le chemin des mots de passe : même soin que le reste de la catégorie 02.
- **Lot 5 — relais LDAP/S.** Dépend du lot 4. Le SAN du certificat du core doit couvrir les proxies, sinon le client TLS refuse.

---

## GPO

### 33. [GPO] La dérive du scope utilisateur n'est jamais scannée

**Constat.** `scanMachineDrift` n'existe que pour le scope machine (`vaultaire_client/gpo/cycle.go`). `RunUserCycle` applique les GPO utilisateur à l'ouverture de session mais ne vérifie jamais l'état laissé par la session précédente.

**Pourquoi c'est important.** Les fichiers du scope utilisateur vivent dans son `HOME`, le seul endroit où il édite librement sans être root. La dérive la plus probable est donc celle qui n'est pas surveillée.

**À faire.** Ajouter `scanUserDrift` dans `RunUserCycle`, symétrique de l'existant, à l'ouverture de session. Il doit respecter le mode enforce/audit de chaque module (point 34, fait). La correction reste **différée au cycle suivant**, comme côté machine : réappliquer dans le home pendant que l'utilisateur travaille écraserait ce qu'il vient d'éditer.

### 50. [GPO] Déclencher un cycle hors du tour horaire

**Constat.** Un cycle machine ne part qu'au démarrage du service puis toutes les heures. Il n'existe pas d'équivalent de `gpupdate /force`. Trois cas attendent donc jusqu'à une heure :

- l'administrateur veut forcer l'application **depuis le core** ;
- le tunnel vient de **se reconnecter** après une coupure ;
- le cycle précédent a **échoué** et devrait être retenté plus tôt.

**À faire.** Une trame du core qui demande un cycle, un cycle lancé à la reconnexion, et une nouvelle tentative rapprochée (avec backoff) après un échec.

### 51. [GPO] Intervalle de rafraîchissement configurable

**Constat.** `MachineRefreshInterval` est une constante (`1 * time.Hour`, `vaultaire_client/gpo/cycle.go`). Le point 13 a sorti les autres durées d'exploitation du code ; celle-ci n'a pas suivi.

**À faire.** La rendre réglable, de préférence depuis le core (`Reglages_de_duree.md`) pour qu'elle suive la même logique que le mode de dérive : la décision ne vient pas de la machine.

### 52. [GPO] Signature des politiques par le core

**Constat.** Le champ `Signature` du manifeste existe (`vaultaire_client/gpo/policy.go`) mais n'est ni rempli ni vérifié. Le tunnel Ducky protège déjà le transport ; la signature protégerait la politique elle-même (état local, relais futur du point 38).

**À faire.** Signer au core, vérifier sur l'agent avant application, refuser une politique non signée une fois la migration faite.

### 53. [GPO] Persister les rapports d'application en base

**Constat.** Les rapports d'application sont seulement journalisés. La conformité (dérive) a sa page ; le résultat d'une application, non.

**À faire.** Les stocker côté core et les afficher sur la page du client, par exemple avec une rétention bornée comme les métriques de nœuds (point 43).

---

## Sécurité et authentification

### 22. [EN COURS] [SELINUX] Politique pour les clients

**Contexte.** Le module NSS lit désormais un fichier et ouvre un socket. Sous `sshd_t`, SELinux refuse : d'où « Invalid user » sans aucun journal Vaultaire, alors que `getent` lancé à la main réussit. Détails : `docs/exploitation/selinux.md`.

**Fait.** `deployments/selinux/` : `collect.sh`, `vaultaire.te`, `vaultaire.fc`, `install.sh`.

**Reste à faire.** Un domaine dédié pour l'agent — il tourne aujourd'hui en `unconfined_service_t`.

### 49. [RÉVOCATION] Retenter les révocations poussées en échec

**Origine.** Reste noté dans `DO/2.0/2.0.md` (kill switch) et jamais reporté ici.

**Constat.** La révocation poussée ne touche que les machines connectées au moment du déclenchement. Une machine absente récupère ses ordres en attente à sa reconnexion (`revocation_manager/trames.go`), mais une machine **connectée dont le push a échoué** attend elle aussi la reconnexion suivante, qui peut ne jamais venir tant que le tunnel tient.

**À faire.** Une tâche de fond côté core qui renvoie périodiquement les ordres en attente aux clients connectés.

---

## Idées à cadrer

### 8. [LDAP] Mode synchro avec un annuaire existant

Relier Vaultaire à un AD déjà en place pour bénéficier de ses fonctionnalités sans migrer l'annuaire.

### 40. [AGENT-UPDATE] Mettre à jour le parc de clients

**Question.** Comment mettre à jour les agents, y compris sans accès Internet ?

**Pistes :**

- **Dépôt (Nexus)** ordonné par le core — la plus simple ; le dépôt n'a pas besoin d'authentification, ce n'est pas un service sensible à consulter. **Piste privilégiée.**
- Téléchargement **via le réseau Ducky**.
- Un nouveau service, **`vlt-upm`** (Vaultaire Update Manager), pour les parcs sans Internet — fonctionnement à définir.

Dans tous les cas, le pilotage passe par l'interface web d'administration.
