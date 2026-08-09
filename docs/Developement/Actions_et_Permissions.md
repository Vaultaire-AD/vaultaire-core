# Actions et permissions

Référence des actions métier de Vaultaire, du droit que chacune exige, et du
périmètre sur lequel ce droit est vérifié.

Ce document a deux usages, et il faut les distinguer.

**Pendant la migration** — la colonne « État » suit ce qui passe par le registre
d'actions et ce qui appelle encore la base directement. Une ligne non migrée
n'est pas cassée : elle fonctionne, mais son contrôle de droits vit encore dans
le handler, avec le risque de diverger de l'autre façade.

**Après la migration** — le tableau répond à la question « de quel droit ai-je
besoin pour faire ceci ? », et sa réciproque « qu'est-ce que ce droit permet ? ».
C'est la référence à consulter avant de déléguer.

> **Ce document doit être mis à jour à chaque action ajoutée, renommée, ou dont
> la clé ou la portée change.** Une ligne périmée est pire qu'une ligne absente :
> elle sera lue comme vraie.

---

## Comment lire ce tableau

### La clé RBAC

Un droit s'écrit `catégorie:action:objet` — par exemple `write:create:user`. Une
poignée d'actions ne rentrent pas dans ce moule et portent une clé spéciale :
`write:dns`, `write:mfa`, `read:log`, `write:killswitch`.

Certaines actions n'ont **aucune clé RBAC**. Ce n'est pas un oubli : elles sont
réservées aux membres du groupe protégé (`vaultaire`). Voir plus bas.

### La portée

C'est la question **« sur quels domaines ce droit est-il exigé ? »**, et c'est ce
qui rend la délégation possible. Détenir `write:create:user` sur le domaine
`paris` ne permet pas de créer un compte dans `lyon`.

| Portée | Le droit est exigé sur… |
|---|---|
| **Globale** | `*` — le droit doit être détenu globalement |
| **Utilisateur** | les domaines du compte visé |
| **Groupe** | les domaines du groupe visé |
| **Groupe + utilisateur** | l'union des deux |
| **Groupe + machine** | l'union des deux |
| **Machine** | les domaines de la machine visée |
| **Permission** | les domaines de la permission visée |

Le contrôle exige le droit sur **tous** les domaines listés, pas sur un seul.
Un délégué de `paris` seul ne peut pas agir sur une entité présente dans `paris`
et `lyon`.

**Pourquoi certaines actions sont globales.** Une création n'a pas de cible dont
déduire un domaine — le compte n'existe pas encore. Un certificat, une zone DNS,
une politique de mot de passe n'appartiennent à aucun domaine : ce qu'ils
engagent dépasse tout périmètre délégué.

### Le groupe protégé

Certaines actions exigent l'appartenance au groupe `vaultaire` **au lieu** ou
**en plus** d'une clé RBAC.

Au lieu : quand l'objet visé n'est pas une entité de l'annuaire et ne porte donc
aucun domaine — un certificat TLS, la politique de mot de passe. Aucune clé ne
les couvre, et aucune délégation par domaine ne s'y appliquerait proprement.

En plus : quand l'opération accorde un pouvoir qui dépasse ce qu'une clé
ordinaire devrait emporter. Émettre une clé d'enrôlement pour un type qui porte
l'assertion d'identité permet d'agir au nom de n'importe quel utilisateur.

Quand les deux sont exigés, **les deux** le sont — jamais l'un ou l'autre.

---

## Le tableau

Légende de l'état :

- **Registre** — passe par `core/action`, contrôle unique et partagé
- **Handler** — contrôle encore dans le handler, à migrer
- **—** — la façade n'expose pas cette action

| Action | Droit exigé | Portée | Groupe protégé | CLI | Web |
|---|---|---|---|---|---|
| **Utilisateurs** |
| `user.create` | `write:create:user` | Globale | — | Registre — `create -u` | **Registre** |
| `user.update` | `write:update:user` | Utilisateur | — | — | **Registre** |
| `user.change_password` | `write:update:user` | Utilisateur | — | Registre — `update -u -p` | **Registre** |
| `user.delete` | `write:delete:user` + `write:killswitch` | Utilisateur | — | Registre — `delete -u` | **Registre** |
| `user.add_key` | `write:update:user` | Utilisateur | — | Registre — `add -u -k` | — |
| `user.remove_key` | `write:update:user` | Utilisateur | — | Registre — `remove -u -k` | — |
| `user.reset_mfa` | `write:mfa` | Groupes de l'utilisateur | — | Registre — `mfa -u <user> --reset` | **Registre** |
| **Groupes** |
| `group.create` | `write:create:group` | Globale | — | Registre — `create -g` | **Registre** |
| `group.delete` | `write:delete:group` | Groupe | — | Registre — `delete -g` | **Registre** |
| `group.add_user` | `write:add:user` | Groupe + utilisateur | — | Registre — `add -u -g` | **Registre** |
| `group.remove_user` | `write:delete:user` | Groupe + utilisateur | — | Registre — `remove -u -g` | **Registre** |
| `group.add_client` | `write:add:client` | Groupe + machine | — | Registre — `add -c -g` | **Registre** |
| `group.remove_client` | `write:delete:client` | Groupe + machine | — | Registre — `remove -c -g` | **Registre** |
| `group.add_permission` | `write:add:permission` | Groupe | — | Registre — `add -gu -p` | **Registre** |
| `group.remove_permission` | `write:delete:permission` | Groupe | — | Registre — `remove -gu -p` | **Registre** |
| `group.add_client_permission` | `write:add:permission` | Groupe | — | Registre — `add -gc -p` | **Registre** |
| `group.remove_client_permission` | `write:delete:permission` | Groupe | — | Registre — `remove -gc -p` | **Registre** |
| `group.add_gpo` | `write:add:gpo` | Groupe | — | Handler — `add -gpo` | **Registre** |
| `group.remove_gpo` | `write:delete:gpo` | Groupe | — | Handler — `remove -gpo` | **Registre** |
| `group.set_mfa_required` | `write:mfa` | Groupe | — | Registre — `mfa -g --require/--optional` | **Registre** |
| **Machines** |
| `client.create` | `write:create:client` | Globale | — | Registre — `create -c` | **Registre** |
| `client.update` | `write:update:client` | Machine | — | — | **Registre** |
| `client.delete` | `write:delete:client` | Machine | — | Registre — `delete -c` | **Registre** |
| **Permissions** |
| `permission.create` | `write:create:permission` | Globale | — | Registre — `create -p` | **Registre** |
| `permission.delete` | `write:delete:permission` | Permission | — | Registre — `delete -p` | **Registre** |
| `permission.update_action` | `write:update:permission` | Permission | — | Handler — `update -pu` | Handler |
| `client_permission.create` | `write:create:permission` | Globale | — | — | **Registre** |
| `client_permission.update` | `write:update:permission` | Permission | — | — | **Registre** |
| `client_permission.delete` | `write:delete:permission` | Permission | — | — | **Registre** |
| **Enrôlement** |
| `enroll.create_key` | `write:create:client` | Globale | **si assertion d'identité** | Registre — `enroll create` | **Registre** |
| `enroll.revoke_key` | `write:create:client` | Globale | — | Registre — `enroll revoke` | **Registre** |
| **DNS** |
| `dns.create_zone` | `write:dns` | Globale | — | **Registre** — `dns zone create` | **Registre** |
| `dns.add_record` | `write:dns` | Globale | — | **Registre** — `dns record add` | **Registre** |
| `dns.delete_record` | `write:dns` | Globale | — | **Registre** — `dns record delete` | **Registre** |
| `dns.delete_zone` | `write:dns` | Globale | — | **Registre** — `dns zone delete` | — |
| `dns.delete_ptr` | `write:dns` | Globale | — | **Registre** — `dns ptr delete` | — |
| **Certificats et politique** |
| `certificate.delete` | *(aucune clé)* | Globale | **oui** | — | **Registre** |
| `authpolicy.set_password_policy` | *(aucune clé)* | Globale | **oui** | Registre — `mfa policy` | **Registre** |

**38 actions.** CLI : 29 sur le registre. Web : 32 sur le registre.

**Les deux façades sont branchées** hors périmètre exclu. `web_admin_pages.go`
est passé de 32 écritures directes à zéro.

### Hors périmètre

Les **GPO** ont été exclues de la refonte par décision : leur logique est
spécifique et ne se plie pas au modèle « une action, des paramètres nommés ».
Elles gardent leur contrôle dans les handlers, sur les domaines de la GPO visée.

Le **profil de l'utilisateur courant** — son mot de passe, son second facteur,
ses clés — n'est pas une action d'administration : elle ne vise pas un tiers, ne
relève d'aucune délégation, et son contrôle est l'authentification elle-même.

---

## Comment les droits se combinent

### Les droits viennent des groupes, jamais du compte

Un utilisateur ne détient aucun droit en propre. Il appartient à des groupes, et
ce sont les groupes qui portent les permissions.

Conséquence pratique : **ajouter quelqu'un à un groupe lui donne tout ce que ce
groupe possède**. C'est pourquoi `group.add_user` exige le droit sur les domaines
du groupe *et* de l'utilisateur — l'opération engage les deux.

### Une permission porte des domaines

Une permission ne dit pas seulement « peut créer des utilisateurs » ; elle dit
« peut créer des utilisateurs **dans ces domaines** ». C'est ce qui permet de
confier `paris` à quelqu'un sans lui ouvrir `lyon`.

La valeur spéciale `all` vaut tous les domaines, présents et futurs — y compris
ceux qui n'existent pas encore au moment où on l'accorde.

### Le contrôle exige tous les domaines de la cible

Si un compte appartient à `paris` **et** `lyon`, agir dessus demande le droit sur
les deux. Un délégué de `paris` seul est refusé.

Ce point a son importance : un compte rattaché à plusieurs domaines n'est
administrable que par quelqu'un qui les couvre tous. C'est délibéré — sans quoi
le domaine le plus faiblement gardé déciderait pour les autres.

### Le groupe protégé

Le groupe `vaultaire` est le groupe d'amorçage. Son appartenance ne se délègue
pas par une permission : elle se constate.

Il ouvre les actions qui n'appartiennent à aucun domaine et celles dont la portée
dépasse tout périmètre. En faire un droit RBAC ordinaire reviendrait à permettre
qu'un délégué se l'accorde.

---

## Suivi de la migration

### Ce qui reste, côté CLI

| Commande | Écritures directes | Motif |
|---|---|---|
| `add -gpo`, `remove -gpo`, `create -gpo`, `delete -gpo` | 4 | GPO, hors périmètre |
| `certificate regenerate` | 1 | remplacement interne, pas une action d'administration |

**Le CLI est terminé** hors périmètre exclu : plus aucune écriture directe dans
les commandes portées.

### Ce qui reste, côté web

| Fichier | Écritures directes | Motif |
|---|---|---|
| `web_admin_gpo.go` | 8 | GPO, hors périmètre |
| `web_admin_gpo_restrictions.go` | 3 | GPO, hors périmètre |
| `web_profil.go` | 2 | profil de l'utilisateur courant |

Une exception subsiste dans `web_admin_pages.go` : `update_permission_action`
manipule la grammaire interne des permissions RBAC — `nil`, `all`, ajout ou
retrait d'un domaine avec propagation. Elle mérite ses propres actions plutôt
qu'une traduction hâtive, et garde donc son contrôle sur les domaines de la
permission. C'est le pendant de `update -pu` côté ligne de commande.

### Comment cet état est vérifié

`web_serveur/web_action_test.go` lit les sources et refuse toute écriture en base
depuis le paquet web, hors exemptions nommées et justifiées. Il passe désormais :
`web_admin_pages.go` ne contient plus aucune écriture directe.

Les exemptions sont dans `fichiersExemptes`, chacune avec sa raison. Un second
test refuse une exemption sans justification écrite.

---

## Vérifications automatiques

Le registre refuse au démarrage :

- une action **sans aucun contrôle déclaré** — ni clé RBAC, ni appartenance au
  groupe protégé ;
- une action **sans portée** — le contrôle ne porterait sur aucun domaine, donc
  sur rien ;
- **deux actions du même nom** — la définition retenue dépendrait de l'ordre des
  fichiers.

Une exigence conditionnelle (`ExigeSuperadminSi`) **ne compte pas** comme
contrôle déclaré : sa condition peut être fausse, et l'action tournerait alors
sans vérification.

`core/action/actions_clients_perms_test.go` vérifie l'inventaire complet du
catalogue réel — celui que le serveur emploie, pas une reconstruction.
