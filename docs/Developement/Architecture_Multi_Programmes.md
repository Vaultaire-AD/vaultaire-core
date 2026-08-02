# Architecture multi-programmes — enrôlement et cloisonnement

**Statut : note de conception. Rien n'est implémenté, aucune trame n'est
modifiée.** Ce document fige une discussion d'architecture pour qu'elle ne soit
pas à refaire. Les questions encore ouvertes sont rassemblées en fin de fichier.

Conformément à la règle du projet — *toute évolution du protocole passe d'abord
par la documentation, puis par une validation* — la proposition de trames n'est
pas rédigée ici. Elle viendra quand les questions ouvertes seront tranchées.

---

## 1. Le besoin

Vaultaire se compose aujourd'hui de **deux programmes** : le core
(`vaultaire_serveur`) et l'agent (`vaultaire_client`). L'objectif est d'en
ajouter d'autres — proxy, webserver, webserver admin — déployés en conteneurs.

Deux contraintes structurantes, posées d'emblée :

- **Aucun programme autre que le core n'a d'accès à la base de données.** Toute
  lecture ou écriture passe par une trame Ducky adressée au core.
- **Pas d'installation manuelle.** Un conteneur ne peut pas être enregistré par
  un `vlt create -c` lancé par un administrateur : il doit s'enrôler seul, à sa
  première connexion.

Il n'existe rien aujourd'hui pour ça.

---

## 2. La proposition retenue — clés d'amorçage

Reprise du mécanisme de NetBird : une **clé d'amorçage** (*setup key*) unique,
créée par un administrateur, porteuse de propriétés — nombre d'usages, durée de
validité, **type de programme autorisé**. La clé est transmise au conteneur par
un fichier monté. À sa première connexion, le programme génère sa propre paire
de clés, s'enregistre auprès du core en présentant la clé d'amorçage et sa clé
publique, puis persiste son identité.

Une clé « proxy » ne peut enrôler que des proxys.

### Ce que ça règle au passage

**C'est le correctif manquant du point 11 de l'audit** (`Audit_Serveur.md`).
Aujourd'hui `04_01` enregistre un hôte **sans aucune authentification**, parce
qu'aucun mécanisme d'enrôlement n'existe. Les deux sujets ne sont pas voisins,
ils sont le même : l'enrôlement est précisément ce qui manque à `04_01`.

Les deux doivent donc être traités ensemble, et l'actuel `register_host` doit
**disparaître** plutôt que cohabiter avec le nouveau chemin.

---

## 3. La clé d'amorçage n'est pas un identifiant

C'est un **jeton porteur à usage d'enrôlement**. La distinction a des
conséquences pratiques.

### Transport : fichier, pas variable d'environnement

Dans un conteneur, une variable d'environnement est lisible par
`docker inspect`, par `kubectl get pod -o yaml`, dans les manifestes versionnés
et dans les dumps de diagnostic. Un fichier monté en lecture seule
(`VAULTAIRE_SETUP_KEY_FILE`) est nettement plus contenu. L'env var reste
acceptable en repli, mais documentée comme mode dégradé.

### Propriétés à porter

| Propriété | Pourquoi |
|-----------|----------|
| Compteur d'usages | Pas seulement « unique » ou « illimité » — voir §4 |
| Date d'expiration | Une clé oubliée cesse d'être une porte ouverte |
| Type de programme autorisé | Une clé proxy n'enrôle que des proxys |
| Révocation immédiate | Corollaire du fait que c'est un jeton porteur |
| **Journalisation de chaque usage** | Une clé permanente dont personne ne voit les usages est morte du point de vue de la détection |

### Le risque résiduel

La clé reste montée en permanence dans le conteneur. **Qui compromet le
conteneur obtient une clé d'enrôlement valide** et peut faire apparaître un
programme pirate dans le cluster. Deux atténuations peu coûteuses :

- le programme **ne lit le fichier de clé que s'il n'a pas déjà d'identité**
  sur son volume — sinon il n'y touche jamais ;
- le core journalise chaque enrôlement avec l'IP source, ce qui rend un
  enrôlement inattendu visible immédiatement.

---

## 4. Persistance de l'identité du programme — **tranché**

**Décision :** le programme écrit sa paire de clés dans un fichier de
configuration, au même titre que ses autres fichiers.

- **Conteneur avec volume persistant** → il retrouve son identité au
  redémarrage et **ne se réenrôle pas**.
- **Conteneur détruit puis recréé** → il s'enrôle comme un **nouveau**
  programme, sans aucun souvenir de l'ancien.

### La conséquence, qui tombe sur la clé d'amorçage

Si un conteneur détruit se réenrôle comme neuf, la clé doit rester valide et
réutilisable aussi longtemps que le déploiement existe. **La propriété « usage
unique » devient donc inutilisable pour tout ce qui est conteneurisé** — elle ne
servira qu'aux programmes installés à la main.

On la garde, mais en sachant que le cas courant sera « N usages, expire le … ».
D'où le compteur d'usages plutôt qu'un simple drapeau, et d'où l'importance de
la journalisation : c'est le seul contrôle qui reste sur une clé à longue durée
de vie.

---

## 5. Cycle de vie et nettoyage automatique — **tranché**

Le réenrôlement à chaque destruction produit des identités mortes. Il faut donc
purger les programmes qui ne communiquent plus.

### Deux seuils, pas un

| État | Délai | Effet |
|------|-------|-------|
| **Hors ligne** | quelques minutes sans battement de cœur | on cesse de lui envoyer du travail, **l'identité reste** |
| **Purgé** | plusieurs jours | l'identité disparaît |

Deux questions différentes — « puis-je lui envoyer du travail ? » et
« existe-t-il encore ? » — méritent deux réponses.

Le **délai de purge est une propriété du type de programme**, déclarée dans le
même catalogue en dur que les capacités (§7) : un proxy autoscalé peut être
purgé en une heure, un webserver admin éteint le week-end ne doit pas l'être.

### L'état à ne pas oublier : identité purgée, volume revenu

Un programme dont l'identité a été purgée mais dont le volume persistant
réapparaît présente une clé que le core ne connaît plus.

Si le core répond « authentification refusée », **le conteneur retente en
boucle**. Il faut une réponse distincte — *identité inconnue, réenrôle-toi* —
sur laquelle le programme efface son état local et repasse par la clé
d'amorçage. C'est un crashloop en production si on l'oublie.

### Purger un programme, c'est le révoquer

Le mécanisme existe déjà : le kill switch (catégorie `06`) sait écrire un ordre
durable, le pousser, fermer les sessions, et rejouer à la reconnexion. **Un
proxy compromis doit pouvoir être coupé par le même bouton qu'un compte
compromis**, avec la même trace.

Construire un second mécanisme de coupure pour les programmes garantit qu'il
divergera du premier.

À reprendre à l'identique : dans `user_revocation`, le nom est stocké en **texte
sans clé étrangère**, pour que l'historique survive à la suppression de
l'identité. Même chose ici — nom et type conservés après purge.

---

## 6. Une seule table d'identité

Il existe déjà **deux** tables pour des principaux non humains :

| Table | Contenu | Manque |
|-------|---------|--------|
| `id_logiciels` | `public_key`, `logiciel_type`, `computeur_id`, `hostname`, `serveur` | — |
| `cluster_nodes` | `hostname`, `role`, `status`, `version_code`, `capabilities`, `last_heartbeat` | **aucune clé** |

`id_logiciels` est littéralement « un programme non humain avec une clé ». Un
proxy est un `logiciel_type` de plus, pas une espèce nouvelle.

**Ne pas créer une troisième table.** Avec deux tables d'identité, le kill
switch, le RBAC et l'audit devront chacun regarder à deux endroits — et l'un des
deux sera oublié.

**Direction proposée :** `id_logiciels` reste l'identité et la clé ;
`cluster_nodes` devient un **état d'exécution** qui la référence (statut,
dernier battement, version, capacités déclarées).

---

## 7. Capacités par type de programme — **tranché**

**Décision : les capacités d'un type de programme se déclarent dans le code, pas
en base.**

Un proxy peut faire exactement N choses, énumérées dans un catalogue — même
principe que le catalogue de modules GPO.

Contrairement à un utilisateur, un programme n'a **aucun besoin de souplesse** :
un proxy fait des choses de proxy. L'avantage est qu'on ne peut pas « accorder
par erreur `write:delete:user` au proxy », parce que ce n'est pas exprimable. Si
la liste vit en base, quelqu'un le fera un jour — et un conteneur se compromet
plus facilement qu'un contrôleur de domaine.

---

## 8. Le cloisonnement des trames — **le point central**

Le catalogue de capacités ne concerne **pas seulement les nouveaux programmes**.
Les clients traditionnels aussi doivent être limités aux trames qui les
concernent.

### Ce qui ne va pas aujourd'hui

La sécurité du protocole repose sur **un seul axe : l'ordre des trames**.
`CheckIntegrity` dit quelle trame peut suivre laquelle. C'est une machine à
états écrite en `if`, et c'est exactement par là que le trou `04_01` est passé :

- une transition autorisée de trop — `01_01 → 04_01` ;
- plus une ligne qui **désarme le contrôle** pour tout le reste de la session
  (`TrameIsSafe = true`).

### Ce qui manque : un second axe

Non pas une transition de plus, mais **quel principal a le droit d'émettre
quelle trame**. Une petite table déclarative à deux dimensions :

- le **type de principal** — client, proxy, webserver, webserver admin, non
  authentifié ;
- l'**état** — avant ou après authentification.

Esquisse :

| Principal | Peut émettre | Ne peut pas |
|-----------|--------------|-------------|
| Non authentifié | `askkey`, `01_01`, trame d'enrôlement | tout le reste |
| Client traditionnel | `02`, `03`, `05` ; reçoit `06` | `04` |
| Proxy | `04`, relais | `03` |
| Webserver / admin | à définir | — |

### Trois bénéfices

**Le trou `04_01` se ferme par construction**, pas par un correctif ponctuel :
un principal non authentifié n'a plus accès qu'à l'enrôlement.

**Une barrière sous le RBAC.** Même si quelqu'un accordait par erreur
`write:delete:user` à un proxy en base, la trame qui porte cette commande serait
rejetée au dispatcher **avant** que le RBAC ne soit consulté. Deux barrières
indépendantes, dont l'une n'est pas modifiable depuis l'interface.

**Ça se lit d'un coup d'œil.** On voit *tout* ce qu'un proxy compromis peut
tenter, sur une page. Aujourd'hui, répondre à cette question demande de relire
un enchaînement de conditions.

---

## 9. Topologie en étoile — **tranché**

**Décision : le core reste l'unique ancre de confiance et le seul plan de
contrôle.** Les programmes ne communiquent pas directement entre eux.

Trois raisons :

- en pair-à-pair, chaque programme devrait valider l'identité de chaque autre,
  donc porter un magasin de confiance et savoir vérifier une révocation ;
- la **révocation** devient le point dur : couper un proxy compromis supposerait
  de prévenir tous ses pairs, pas seulement le core ;
- rien ne prouve aujourd'hui que l'étoile ne suffit pas.

### Si un jour le débit pose problème

La bonne réponse ne sera pas « pair-à-pair » mais **plan de contrôle centralisé,
plan de données direct** : le core délivre un jeton court que A présente à B, et
B le vérifie avec la clé publique du core sans appeler personne. C'est ce que
fait NetBird.

**Ne pas construire ce courtier avant d'avoir mesuré le besoin.**

---

## 10. Le piège de la dépendance synchrone

Si un proxy doit demander au core « cet utilisateur a-t-il le droit ? » par une
trame **à chaque requête**, la latence et la disponibilité du core deviennent
celles du proxy.

Il faudra un cache côté proxy avec TTL court, et une **invalidation poussée par
le core** — mécanisme qui existe déjà, c'est celui du kill switch. À concevoir
en même temps que les trames, pas après.

---

## 11. Catégorie de trames

**Ne pas créer un `07`. Redéfinir le `04`.**

La catégorie s'appelle déjà « Cluster / Service discovery » et son
`register_host` actuel est précisément ce que l'enrôlement doit remplacer. Le
`04` deviendrait **« cycle de vie d'un programme »** : enrôlement,
authentification, battement de cœur, retrait.

Ça garde la sémantique, et surtout ça **force à supprimer le chemin non
authentifié** au lieu de le laisser cohabiter avec le nouveau.

---

## 12. Questions ouvertes

À trancher avant de rédiger la proposition de protocole.

### A. RBAC en plus des capacités de type ?

Un programme enrôlé peut-il se voir attribuer des permissions RBAC **en
supplément** de ses capacités de type — pour restreindre un proxy à un domaine,
par exemple — ou bien le type suffit-il ?

*Enjeu :* si oui, il faut une entrée dans la matrice des permissions pour les
principaux non humains, et le kill switch doit savoir les lire.

### B. Rétroactivité sur le client existant

Le catalogue de trames par type s'applique-t-il **rétroactivement à l'agent
actuel** ?

*Enjeu :* si oui, il faut vérifier que l'agent en production n'émet rien hors de
sa liste, sous peine de **casser le parc à la mise à jour**. C'est un travail de
recensement à faire avant, pas pendant.

### C. Reste à cadrer

- Format exact de la clé d'amorçage et de son stockage en base.
- Contenu du catalogue de capacités pour chacun des trois nouveaux types.
- Ce que `cluster_nodes` conserve une fois l'identité déportée dans
  `id_logiciels`.
- Délais de purge par défaut, par type.

---

## 13. Récapitulatif des décisions

| # | Sujet | Décision |
|---|-------|----------|
| 1 | Enrôlement | Clé d'amorçage type NetBird, fichier monté, clé générée par le programme |
| 2 | Persistance | Fichier de configuration ; volume persistant = pas de réenrôlement ; conteneur détruit = nouvelle identité |
| 3 | Usage unique | Conservé, mais inadapté au conteneur — compteur d'usages à la place |
| 4 | Nettoyage | Purge automatique des programmes muets, **deux seuils**, délai par type |
| 5 | Purge | Passe par le flux de révocation existant, pas un second mécanisme |
| 6 | Identité | Une seule table — `id_logiciels` ; `cluster_nodes` devient l'état d'exécution |
| 7 | Capacités | **En dur dans le code**, par type de programme |
| 8 | Trames | Liste blanche par type de principal × état, **y compris pour le client traditionnel** |
| 9 | Topologie | **Étoile.** Pas de pair-à-pair |
| 10 | Catégorie | Redéfinir `04`, supprimer `register_host` |

---

## Voir aussi

- [`Audit_Serveur.md`](./Audit_Serveur.md) §11 — le trou `04_01`, que ce
  chantier referme
- [`Audit_Permissions.md`](./Audit_Permissions.md) §1-2 — même sujet, analyse
  reportée vers `Audit_Serveur.md`
- [`Tableau_Protocole_Réseau.md`](./Tableau_Protocole_Réseau.md) — état actuel
  des catégories de trames
- [`Permissions.md`](./Permissions.md) — modèle RBAC, pour la question A
