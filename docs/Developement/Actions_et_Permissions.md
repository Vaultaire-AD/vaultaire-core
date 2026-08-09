# Actions et permissions

Référence des actions métier de Vaultaire, du droit que chacune exige, et du
périmètre sur lequel ce droit est vérifié.

**La migration est terminée.** Toute action d'administration passe par le
registre `core/action`, qui porte sa clé RBAC, sa portée et son contrôle — une
seule fois, pour la ligne de commande comme pour l'interface web.

Ce tableau répond donc à deux questions : « de quel droit ai-je besoin pour
faire ceci ? » et sa réciproque « qu'est-ce que ce droit permet ? ». C'est la
référence à consulter avant de déléguer.

> **Ce document doit être mis à jour à chaque action ajoutée, renommée, ou dont
> la clé ou la portée change.** Une ligne périmée est pire qu'une ligne absente :
> elle sera lue comme vraie.

---

## Comment lire ce tableau

### La clé RBAC

Un droit s'écrit `catégorie:action:objet` — par exemple `write:create:user`.

Les objets de l'annuaire sont `user`, `group`, `client`, `permission`, `gpo`.
Ce qui n'en est pas un porte une **clé spéciale**, à deux segments :

| Clé | Ce qu'elle gouverne |
|---|---|
| `read:log` | consultation des journaux |
| `write:dns` / `read:dns` | modification / consultation du DNS |
| `write:mfa` | second facteur d'un tiers |
| `write:killswitch` | révocation d'urgence d'un compte |
| `read:cluster` / `write:cluster` | état du cluster / réglages |
| `read:certificate` / `write:certificate` | certificats TLS du serveur |
| `read:enrollment` | consultation des clés d'enrôlement |
| `write:server` | réglages d'exploitation (debug, purge des sessions) |

**Pourquoi des clés spéciales et non des objets RBAC.** Un journal, un nœud de
cluster, un certificat n'appartiennent à aucun domaine : la délégation par
domaine n'a rien à quoi s'appliquer. Les déclarer objets engendrerait six clés
chacun — `read:get:cluster`, `write:add:cluster`… — dont une ou deux auraient un
sens. **Une clé qui n'accorde rien est indiscernable d'un oubli.**

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

Pour une **écriture**, le droit est exigé sur **tous** les domaines listés. Un
délégué de `paris` seul ne peut pas modifier une entité présente dans `paris` et
`lyon`.

Pour une **lecture**, un seul suffit — la même entité lui est visible. Voir
« Voir et agir ne s'exigent pas pareil » plus bas : c'est la nuance qui rend la
délégation utilisable.

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
- **—** — la façade n'expose pas cette action

**Toutes les lignes sont au registre.** Plus aucun contrôle d'accès ne vit dans
un handler côté ligne de commande ; côté web, seules les restrictions du
catalogue GPO et le profil personnel restent à part, chacune pour une raison
écrite plus bas.

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
| `group.add_gpo` | `write:add:gpo` | **Groupe + GPO** | — | **Registre** — `add -gpo` | **Registre** |
| `group.remove_gpo` | `write:delete:gpo` | **Groupe + GPO** | — | **Registre** — `remove -gpo` | **Registre** |
| `group.set_mfa_required` | `write:mfa` | Groupe | — | Registre — `mfa -g --require/--optional` | **Registre** |
| **Machines** |
| `client.create` | `write:create:client` | Globale | — | Registre — `create -c` | **Registre** |
| `client.update` | `write:update:client` | Machine | — | — | **Registre** |
| `client.delete` | `write:delete:client` | Machine | — | Registre — `delete -c` | **Registre** |
| **Permissions** |
| `permission.create` | `write:create:permission` | Globale | — | Registre — `create -p` | **Registre** |
| `permission.delete` | `write:delete:permission` | Permission | — | Registre — `delete -p` | **Registre** |
| `permission.update_action` | `write:update:permission` | Permission | — | **Registre** — `update -pu` | **Registre** |
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
| **Lectures** — toutes en portée souple ¹ |
| `user.list` ² | `read:get:user` | Globale | — | **Registre** — `get -u` | **Registre** |
| `user.get` | `read:get:user` | Utilisateur | — | **Registre** — `get -u <compte>` | **Registre** |
| `user.list_keys` | `read:get:user` | Utilisateur | — | **Registre** — `get -u <compte> -k` | — |
| `group.list` ² | `read:get:group` | Globale | — | **Registre** — `get -g` | **Registre** |
| `group.get` | `read:get:group` | Groupe | — | **Registre** — `get -g <groupe>` | **Registre** |
| `group.list_users` ² | `read:get:user` | Groupe | — | **Registre** — `get -g -u`, `get -u -g` | — |
| `group.list_clients` ² | `read:get:client` | Groupe | — | **Registre** — `get -g -c` | — |
| `client.list` ² | `read:get:client` | Globale | — | **Registre** — `get -c` | **Registre** |
| `client.get` | `read:get:client` | Machine | — | **Registre** — `get -c <id>` | — |
| `permission.list` ² | `read:get:permission` | Globale | — | **Registre** — `get -p -u` | **Registre** |
| `permission.get` | `read:get:permission` | Permission | — | **Registre** — `get -p -u <nom>` | — |
| `client_permission.list` ² | `read:get:permission` | Globale | — | **Registre** — `get -p -c` | — |
| `client_permission.get` | `read:get:permission` | Permission | — | **Registre** — `get -p -c <nom>` | — |
| `gpo.list` ² | `read:get:gpo` | Globale | — | **Registre** — `get -gpo` | — |
| `gpo.get` | `read:get:gpo` | GPO | — | **Registre** — `get -gpo <nom>` | — |
| **GPO — écritures** |
| `gpo.create` | `write:create:gpo` | Globale | — | **Registre** — `create -gpo` | **Registre** |
| `gpo.update` | `write:update:gpo` | GPO | — | — | **Registre** |
| `gpo.delete` | `write:delete:gpo` | GPO | — | **Registre** — `delete -gpo` | **Registre** |
| `gpo.add_module` | `write:update:gpo` | GPO | — | — | **Registre** |
| `gpo.update_module` | `write:update:gpo` | GPO | — | — | **Registre** |
| `gpo.delete_module` | `write:update:gpo` | GPO | — | — | **Registre** |
| **Sessions — qui est connecté** |
| `session.list_users` ² | `read:status:user` | Globale | — | **Registre** — `status -u` | — |
| `session.get_user` | `read:status:user` | Utilisateur | — | **Registre** — `status -u <compte>` | — |
| `session.list_users_by_group` ² | `read:status:user` | Groupe | — | **Registre** — `status -u -g` | — |
| `session.list_clients` ² | `read:status:client` | Globale | — | **Registre** — `status -c` | — |
| `session.list_clients_by_group` ² | `read:status:client` | Groupe | — | **Registre** — `status -c -g` | — |
| `session.list_clients_by_type` ² | `read:status:client` | Globale | — | **Registre** — `status -c <type>` | — |
| **Serveur — cluster et certificats** ³ |
| `cluster.list_nodes` | `read:cluster` | Globale | — | **Registre** — `cluster list` | — |
| `cluster.get_purge_delay` | `read:cluster` | Globale | — | **Registre** — `cluster purge-delay` | — |
| `cluster.set_purge_delay` | `write:cluster` | Globale | — | **Registre** — `cluster purge-delay <h>` | — |
| `certificate.list` | `read:certificate` | Globale | — | **Registre** — `certificate list` | — |
| `certificate.get` | `read:certificate` | Globale | — | **Registre** — `certificate show` | — |
| `certificate.regenerate` | `write:certificate` | Globale | — | **Registre** — `certificate regenerate` | — |
| **Conformité GPO et arborescence** |
| `gpo.list_compliance` ² | `read:get:gpo` | Globale | — | **Registre** — `gpo status`, `gpo drift` | — |
| `gpo.get_compliance` | `read:get:gpo` | Machine | — | **Registre** — `gpo status <machine>` | — |
| `domain.list_tree` ² | `read:get:group` | Globale | — | **Registre** — `eyes -g` | — |
| `domain.list_groups` | `read:get:group` | Domaine | — | **Registre** — `eyes -g <domaine>` | — |
| **DNS, enrôlement, réglages** ³ |
| `dns.list_zones` | `read:dns` | Globale | — | **Registre** — `dns zone list` | — |
| `dns.list_records` | `read:dns` | Globale | — | **Registre** — `dns zone show` | — |
| `enroll.list_keys` | `read:enrollment` | Globale | — | **Registre** — `enroll list`, `show` | — |
| `server.set_debug` | `write:server` | Globale | — | **Registre** — `update -debug` | — |
| `server.clear_sessions` | `write:server` | Globale | — | **Registre** — `clear` | — |
| **Certificats et politique** |
| `certificate.delete` | *(aucune clé)* | Globale | **oui** | — | **Registre** |
| `authpolicy.set_password_policy` | *(aucune clé)* | Globale | **oui** | Registre — `mfa policy` | **Registre** |

**80 actions au catalogue. Plus aucun contrôle d'accès hors du registre côté
ligne de commande.**

³ **Sept clés RBAC nouvelles** — voir ci-dessous.

---

### Sept droits neufs — toutes les clés empruntées sont rendues

Ces objets n'avaient pas de clé qui leur corresponde, et les commandes
empruntaient donc celle des machines :

| Commande | Clé empruntée | Clé désormais |
|---|---|---|
| `cluster list` | `read:get:client` sur `*` | `read:cluster` |
| `cluster purge-delay <h>` | `write:update:client` sur `*` | `write:cluster` |
| `certificate list` / `show` | `read:get:client` sur `*` | `read:certificate` |
| `certificate regenerate` | `write:create:client` sur `*` | `write:certificate` |
| `dns zone list` / `show` | `write:dns` — un droit d'**écriture** | `read:dns` |
| `enroll list` / `show` | `read:get:client` sur `*` | `read:enrollment` |
| `update -debug` | `write:update:user` | `write:server` |
| `clear` (sessions expirées) | `write:update:user` | `write:server` |

Les deux dernières sont les plus parlantes : **régler le mode debug ou vider une
table de sessions n'a rien d'une modification de compte.** La clé accordait
beaucoup plus que ce que la commande fait, et son nom ne laissait pas deviner
qu'elle ouvrait ces deux-là.

Les lectures DNS étaient gardées par `write:dns` — le droit de *modifier* le
DNS. Voir quels noms le serveur résout n'a rien à voir avec le pouvoir de les
changer : on veut pouvoir confier la première à un support de niveau 1.

**Ce qui ne change pas :** l'émission et la révocation d'une clé d'enrôlement
restent sur `write:create:client`. Émettre une clé, c'est accorder le droit
d'ajouter un programme au cluster — donc de créer un client. Seule la
consultation méritait d'être séparée.

Deux conséquences, opposées et également gênantes.

**Trop large.** Régénérer le certificat LDAPS change l'empreinte que tout le
parc a importée dans son magasin de confiance : les clients cessent de se
connecter jusqu'à réimport. Confier cela à quiconque peut créer une machine est
disproportionné.

**Trop étroit.** Lire le certificat *public*, ou consulter l'état du cluster,
exigeait le droit de lire toutes les machines de tous les domaines. Une équipe
d'astreinte à qui l'on veut donner la vue du cluster recevait avec elle
l'annuaire des postes.

Ce sont des **actions spéciales** et non des objets RBAC — comme `read:log`,
`write:dns`, `write:mfa`, `write:killswitch`. Ni un nœud ni un certificat
n'appartient à un domaine : les déclarer objets engendrerait six clés chacun
dont deux auraient un sens, et une clé qui n'accorde rien est indiscernable
d'un oubli.

> **⚠ Fail-closed : à faire après mise à jour**
>
> Ces quatre clés ne sont accordées à personne. `vlt cluster` et
> `vlt certificate list` répondront « permission refusée » en nommant la clé
> manquante, jusqu'à ce que vous l'accordiez :
>
> ```
> update -pu <permission> read:cluster all
> update -pu <permission> write:cluster all
> update -pu <permission> read:certificate all
> update -pu <permission> write:certificate all
> update -pu <permission> read:dns all
> update -pu <permission> read:enrollment all
> update -pu <permission> write:server all
> ```
>
> Le groupe protégé les reçoit automatiquement : `EnsureSuperadminActions`
> passe à chaque démarrage sur `permission.AllActionKeys()`, qui les contient
> — vérifié.

---

### Une validation perdue en route, retrouvée par le balayage

`validateDNSRecordInput` vivait dans `command_dns`. Le portage des actions DNS
l'a laissée derrière : le fichier est resté, **sans plus aucun appelant**, et
c'est un balayage des fonctions orphelines qui l'a montré — plusieurs lots plus
tard.

Entre-temps, `dns record add www A pas-une-ip` était **accepté**. La donnée
partait en base et l'enregistrement ne résolvait rien. Un type inconnu —
`AAAA` — s'écrivait aussi, pour n'être jamais servi.

C'est le pire genre de défaut : la ligne **existe** dans la table, le
comportement n'y est pas, et rien ne relie les deux. Le symptôme observé — « ce
nom ne résout pas » — arrive des jours plus tard, sur une machine, et n'oriente
vers rien.

La validation est maintenant dans l'action, donc sur le chemin des deux
façades, avec deux vérifications de plus que l'originale :

- un `A` qui porte une **IPv6** est refusé (`net.ParseIP` seul l'acceptait) ;
- un **CNAME circulaire** est refusé — il faisait boucler le résolveur.

`TypesDNSAcceptes` est exporté pour que le formulaire web bâtisse sa liste
déroulante sur la même source. Une liste recopiée dans le gabarit aurait
divergé au premier ajout.

Six tests la couvrent, dont un qui vérifie que l'action **appelle** la
validation — les cinq autres passeraient sur un code où elle ne le ferait pas,
ce qui est exactement ce qui venait d'arriver.

---

### `gpo status` : un refus devenu une vue partielle

La commande exigeait `read:get:gpo` sur `*`, avec ce motif : *« un rapport
filtré par domaine donnerait une vue partielle présentée comme complète — pire
qu'un refus »*.

Le raisonnement tenait tant qu'aucun filtre ne pouvait le dire. Le registre
annonce désormais le nombre d'entrées masquées : une vue partielle qui
**s'annonce** partielle vaut mieux qu'un refus. Le délégué voyait auparavant
zéro machine, la sienne comprise.

**Sur quoi porte le filtre.** Une ligne de conformité décrit une **machine** —
son identifiant, la portée appliquée, les modules en échec. Elle ne nomme
aucune GPO : le rapport agrège ce que la machine a reçu. Le filtre porte donc
sur les domaines de la machine, avec la clé `read:get:gpo`. Ce qui revient à
« je vois la conformité GPO des machines de mes domaines » — l'intention
appliquée à ce que la donnée permet de distinguer.

---

### `eyes` : le même droit que `get -g`

`eyes -g` montre les mêmes groupes que `get -g`, en arbre au lieu d'un tableau.
Il exigeait pourtant `write:eyes` — un droit d'**écriture** pour une commande
qui ne fait que lire, et un droit distinct pour la même information.

Il exige maintenant `read:get:group`, et l'arborescence est **réduite au
périmètre**. Un délégué de paris voyait auparavant la structure de toute
l'organisation — quels domaines existent, comment ils s'emboîtent — ce que la
liste des groupes ne lui montrait pas.

`write:eyes` reste dans le vocabulaire mais n'est plus interrogée : l'ôter
ferait échouer la relecture des permissions qui la portent déjà. Son retrait
est une modification à part.

---

### Les GPO respectent-elles le RBAC ? — vérifié en propre

Une GPO ne porte pas une donnée d'annuaire : elle porte des règles sudo, des
fichiers déposés en root, des restrictions de shell, appliqués à tout le parc
visé. C'est l'objet dont le contrôle a le plus de conséquences.

`--test` vérifie six propriétés qui leur sont propres, sur les **10 actions
GPO** du catalogue :

| Vérification | Ce qu'elle empêche |
|---|---|
| Clé spécifique aux GPO | Une action GPO gardée par `write:update:group` laisserait quiconque administre un groupe modifier les règles poussées sur ses machines |
| Déléguables par domaine | Exiger le groupe protégé retirerait les GPO aux délégués sans que la table des permissions le montre |
| Écritures strictes | Une écriture qui se contente d'un domaine rend la portée extensible |
| **Portée non extensible** | Un délégué de paris ne peut pas modifier une GPO couvrant paris **et** lyon — sinon il pousse des règles sudo sur un parc étranger |
| Lecture reste déléguée | Durcir la lecture priverait un délégué de la vue de son propre parc |
| Actions présentes | Un catalogue sans action GPO ne les contrôlerait plus du tout |

Trois mutations éprouvées : clé détournée vers `write:update:group`,
`gpo.add_module` rendu souple, `gpo.delete` réservé au groupe protégé. Les
trois sont détectées.

---

### Ce qui reste hors du registre — inventaire exact

**Côté CLI — plus rien.** Aucun `CheckPermissions*` ne subsiste hors du
registre. Une seule écriture directe demeure, dans `certificate regenerate` :
elle remplace un certificat en base, et l'action `certificate.regenerate` porte
sa clé et sa portée tout en lui déléguant l'exécution. C'est le seul cas du
catalogue, et il est nommé pour qu'on le retrouve.

**Côté web** — trois points, chacun pour une raison :

- `web_admin.go:40` — la porte d'entrée `web_admin` elle-même. Ce n'est pas une
  action mais la condition d'accès aux pages.
- `web_profil*.go` — l'utilisateur agit sur son propre compte. Hors périmètre
  par décision : cela ne vise pas un tiers et ne relève d'aucune délégation.
- `web_admin_gpo_restrictions.go` — le catalogue des valeurs autorisées, de
  portée serveur. Seule exemption **d'administration** de `fichiersExemptes` ; les
  quatre autres (`web_profil.go`, `web_profil_mfa.go`, `web_login.go`,
  `web_login_mfa.go`) portent sur le compte de l'appelant ou sur
  l'authentification, antérieure à toute autorisation.

`verifierDroit` a disparu de `command_create`. Son commentaire annonçait :
« sa disparition signalera que le portage est complet ». Son dernier appelant
était `create -gpo`.

---

### Lier une GPO : la portée s'est élargie

`group.add_gpo` et `group.remove_gpo` exigeaient le droit sur les domaines du
**groupe** seul. Ils exigent maintenant l'**union** groupe + GPO.

La manœuvre que cela ferme : un délégué de paris lie une GPO de lyon à l'un de
ses groupes. La GPO couvre alors paris **et** lyon, et l'administrateur de lyon
ne peut plus modifier sa propre GPO sans le droit sur paris.

Ce n'est pas une élévation de privilège — c'est un **verrouillage** : on prive
autrui de son objet sans jamais toucher à ses droits. Plus discret, et sans
trace évidente.

**À vérifier chez vous :** un délégué qui rattachait à ses groupes des GPO
venues d'un autre domaine perdra cette possibilité.

¹ **Portée souple** — le droit sur **un seul** des domaines de la cible suffit.
Obligatoire pour toute lecture, interdite à toute écriture ; les deux sens sont
vérifiés par `--test`.

² **Liste filtrée** — la réponse est réduite au périmètre de l'appelant.

---

### Voir et agir ne s'exigent pas pareil

C'est la nuance la plus importante du modèle, et elle n'était écrite nulle part.

| | Domaines exigés | Pourquoi |
|---|---|---|
| **Écriture** | **tous** ceux de la cible | Mon geste porte aussi sur les domaines où je n'ai rien à faire |
| **Lecture** | **un seul** suffit | Une entité de mon périmètre m'est légitimement visible |

Un compte présent dans `paris` et `lyon` est **visible** par le délégué de
paris — il fait partie de son périmètre, et le lui cacher l'empêcherait de
constater qu'il y est. Il n'est pas **modifiable** par lui, parce que la
modification toucherait aussi lyon.

Les deux façades appliquaient déjà cette distinction avant le registre —
`allowsAny` côté web, `CheckPermissionsMultipleDomains` côté ligne de commande.
Porter les lectures sans le champ `UnDomaineSuffit` les aurait **durcies d'un
coup**, sans que personne l'ait décidé : les délégués auraient cessé de voir
les entités à cheval sur deux domaines.

Le défaut du champ est `false`, donc l'exigence stricte : un oubli rend une
action plus sévère que voulu — visible et corrigeable — plutôt que plus
permissive, ce qui ne se verrait pas. Un test refuse toute **écriture** qui
déclarerait `UnDomaineSuffit`.

---

### Le filtrage des listes est dans le registre

Contrôler l'accès ne suffit pas pour une liste. `read:get:user` sur un seul
domaine autorise `get -u` — reste à décider **ce que la réponse contient**.

Ce filtrage vivait dans le serveur web et **nulle part ailleurs** : un délégué
de `compta` ouvrant `/admin/users` ne voyait que compta, mais tapant `get -u`
obtenait l'annuaire entier. Le contrôle des écritures était pourtant identique
des deux côtés ; seule la visibilité divergeait, et par la porte de derrière.

Il est maintenant déclaré sur l'action :

```go
Filtre func(donnees any, p Perimetre) (filtrees any, masquees int)
```

Trois propriétés qui comptent :

- **Le filtrage n'est pas un second contrôle d'accès.** Le contrôle décide si
  l'action a lieu ; le filtre décide ce que la réponse contient. Une lecture
  autorisée peut légitimement ne rien rendre.
- **Une entité à cheval reste visible.** Un compte dans `paris` et `lyon` est
  vu par le délégué de paris — même règle que `UnDomaineSuffit`, appliquée à la
  visibilité.
- **Le masquage est dit.** Le message porte le nombre d'entrées retirées. Une
  liste tronquée en silence se lit comme une liste complète, et c'est ainsi
  qu'on croit un annuaire vide alors qu'on n'en voit qu'une part.

**Le registre refuse au démarrage** une action `.list` qui ne déclare ni
`Filtre` ni `FiltreInutile`. Ce second champ est une justification **écrite** :
`user.list_keys` rend les clés d'un seul compte, qui n'ont pas de domaine
propre. La tentation, devant ce cas, est d'affiner la détection jusqu'à ce que
le test passe — c'est ajuster le test au code. Un champ obligatoire force à
écrire pourquoi, une fois, là où la décision se prend.

Un domaine **illisible** masque l'entité. Montrer dans le doute ferait de la
moindre panne de lecture une divulgation.

---

### Un refus qui n'avait pas lieu d'être

`get -c`, `get -p -u` et `get -p -c` exigeaient le droit sur `*`, c'est-à-dire
le droit **global**. Un délégué de paris — qui a pourtant le droit sur son
domaine — se voyait refuser la liste **entièrement**, tandis que l'interface
web la lui montrait filtrée.

La façade employée décidait donc non seulement de *ce qu'il voyait*, mais de
*s'il voyait quelque chose*.

Corrigé par le couple habituel : portée globale mais souple, plus un filtre. Le
délégué obtient sa part au lieu d'un refus.

Au passage, `lireActionsRBAC` a quitté `commandget` : la fiche d'une permission
montrait ses droits RBAC en ligne de commande, tandis que le web reconstruisait
sa propre matrice. Deux lectures, deux instants, deux réponses possibles à la
même question.

---

### Trois défauts de contrôle trouvés en portant les lectures

**1. `get -u <compte>` contrôlait les domaines de l'APPELANT**

```go
domainList, _ := permission.GetDomainListFromUsername(senderUsername)
```

Toutes les autres lectures — groupes, machines, permissions, GPO — emploient
les domaines de la **cible**. Un délégué de paris pouvait donc lire la fiche
d'un compte de lyon : son droit sur ses propres domaines suffisait, et la cible
n'entrait jamais dans la décision.

**2. `get -u -g <groupe>` et `get -u <compte> -k` ne vérifiaient RIEN**

La fonction qui les traite n'appelait aucun contrôle. La composition de
n'importe quel groupe et les clés publiques de n'importe quel compte étaient
lisibles par quiconque atteignait la ligne de commande.

**3. Les fiches web n'avaient qu'un contrôle « n'importe où »**

`/admin/users?user=…` et `/admin/groups?group=…` lisaient la base directement,
sous la seule protection de `checkWebAdminRBAC`, qui appelle
`permission.HasActionAnywhere`. Un délégué de paris ouvrant la fiche d'un
compte de lyon l'obtenait.

Les trois disparaissent du seul fait de passer par le registre : une action ne
peut pas oublier son contrôle, puisqu'elle ne l'écrit pas.

**Une note sur les codes de retour.** Les fiches web rendent désormais le même
`404` pour « introuvable » et pour « hors périmètre ». Répondre `403` sur une
entité hors périmètre confirmerait son existence à quelqu'un qui n'a pas le
droit de la connaître. Le refus reste journalisé côté serveur, où il est utile.

---

### La grammaire des permissions — trois écarts corrigés

`permission.update_action` est la dernière écriture à avoir rejoint le
registre, et la plus lourde : elle ne modifie pas une donnée, elle modifie **ce
que les gens ont le droit de faire**.

Elle vivait en double, et les deux copies avaient divergé — **chaque fois dans
le sens du moins strict côté ligne de commande** :

| | `update -pu` (avant) | Interface web | Retenu |
|---|---|---|---|
| Validation de la clé | forme `cat:action:objet` seulement | clé réellement administrable | **le strict** |
| Action globale par nature (`web_admin`) | domaine accepté | domaine refusé | **le strict** |
| Retrait d'un domaine absent | annonçait « retiré » | refusait | **le strict** |
| Échec d'écriture en base | journalisé, succès affiché | erreur affichée | **l'erreur** |

Le deuxième mérite d'être lu deux fois. `web_admin` ne s'évalue que sur `*` :
lui donner une liste de domaines la **refuse** au lieu de la restreindre. La
commande

```
update -pu <permission> web_admin -a 0 paris
```

retirait donc l'accès à l'interface d'administration à tous les groupes portant
cette permission — y compris à celui qui la tapait, qui n'avait alors plus
l'interface pour revenir en arrière. L'interface web l'interdisait déjà ; la
ligne de commande la contournait.

Les deux vocabulaires sont acceptés en entrée — `-a`/`-r` de la ligne de
commande, `add`/`remove` du web — et ramenés à un seul. Imposer un vocabulaire
unique aurait cassé les scripts existants, et l'échec ne se serait vu qu'à leur
prochaine exécution.

---

### Ce qui n'est PAS au registre

Une seule surface d'administration, et une raison écrite.

#### Restrictions du catalogue GPO

`web_admin_gpo_restrictions.go` reste hors du registre. Ces réglages ne visent
pas une GPO mais **le catalogue lui-même** — quelles valeurs un champ accepte,
sur tout le serveur. Leur portée n'est donc pas celle d'une GPO, et les
traduire dans la foulée aurait mêlé deux modèles dans le même lot.

C'est la seule exemption d'administration de `fichiersExemptes` ; les quatre
autres portent sur le compte de l'appelant ou sur l'authentification.

#### Lectures restantes

**Toutes les lectures d'annuaire** sont au registre, filtrage compris — 15
actions. Restent : `eyes` (arborescence des domaines), `status`, `cluster`, et
la **recherche globale** du web.

La recherche est le dernier appelant de `web_admin_scope.go`, qui ne décide
plus rien — il transmet au périmètre du registre. Elle parcourt quatre genres
d'entités dans une même réponse et ne se ramène donc pas à une action de liste.

### Hors périmètre, définitivement

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

`web_admin_pages.go` ne contient plus aucune écriture directe.

### Comment cet état est vérifié — et l'angle mort qu'il avait

`web_serveur/web_action_test.go` lit les sources et refuse toute écriture en
base depuis le paquet web, hors exemptions nommées et justifiées. Les
exemptions sont dans `fichiersExemptes`, chacune avec sa raison ; un second
test refuse une exemption sans justification écrite.

**Ce garde ne voyait pas ce qu'il devait voir.** Son expression reconnaissait
`Command_ADD_`, `Command_DELETE_`, `Command_Remove_` et `Command_UPDATE_` — mais
pas `Command_SET_`. Or `Command_SET_UserPermissionAction` est la fonction qui
écrit les droits RBAC : la seule qu'il fallait absolument attraper. Le paquet
web en contenait quatre appels ; le test passait au vert, et ce document
affirmait « zéro écriture directe ».

Ni `Add`, ni `Save`, ni `Reset`, ni `Mark`, ni `Drop` n'y figuraient non plus :
**dix-sept fonctions d'écriture** échappaient au filet.

La liste est désormais dérivée des noms réellement exportés par les paquets de
persistance, et `TestLaRegexVoitLesEcrituresConnues` l'éprouve sur un
échantillon de chaque famille — ainsi que sur des lectures, qu'elle ne doit pas
attraper. Un garde dont la couverture n'est pas elle-même testée donne la
tranquillité sans la garantie.

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

### Un angle mort de la matrice, et ce qui le ferme

La matrice substitue la résolution des domaines par une portée fixe — sans quoi,
faute de base, toutes retomberaient sur « droit global » et la délégation
resterait intestée.

Elle n'observe donc **jamais quelle portée une action déclare**. Passer
`gpo.update` de `porteeGPO` à `PorteeGlobale` ne faisait échouer aucun test. Or
c'est exactement la modification qui détruit la délégation.

`core/action/portees_declarees_test.go` compare l'**identité** de la fonction
de portée à un attendu écrit. Il ne dit pas que la portée est juste — il dit
qu'elle n'a pas changé sans qu'on le veuille, ce qui est la question qu'on peut
poser sans base. La couverture de sa table est vérifiée contre le catalogue,
dans les deux sens : une action sans attendu échoue, une entrée sans action
aussi.

Ce test a immédiatement relevé un écart dans ce que j'avais écrit :
`user.reset_mfa` porte sur les **groupes** de l'utilisateur et non sur ses
domaines — réinitialiser un second facteur lève une protection pour tous les
groupes dont le compte est membre.

**Le même angle mort existait sur la clé.** La matrice éprouve `d.CleRBAC` de
façon *relative* : elle l'accorde et vérifie que l'action passe. Elle ne regarde
jamais **quelle** clé c'est. Changer `server.set_debug` de `write:server` à
`write:update:user` ne faisait donc échouer aucun test — c'est-à-dire que le
défaut que ce lot corrige aurait pu revenir sans un mot.

`TestChaqueActionDeclareLaCleAttendue` compare désormais chaque clé à un attendu
écrit, couverture vérifiée dans les deux sens comme pour les portées.

### La matrice de droits — `--test`

`core/testrunner/run_rbac.go` éprouve **chaque action du catalogue réel** sur
quatre cas, sans base de données :

| Cas | Attendu |
|---|---|
| Aucun droit | refus, et refus **tracé** |
| Droit sur un autre domaine | refus |
| Droit sur le bon domaine | le contrôle passe |
| Droit sur un seul des deux domaines de la portée | refus |

Le balayage porte sur le catalogue et non sur une liste écrite à la main : une
action ajoutée demain est éprouvée sans que personne y pense. Une liste
manuelle aurait vieilli dès le premier ajout, et son silence aurait ressemblé à
un succès.

S'y ajoutent les invariants du socle : le groupe protégé ne se contourne pas en
accumulant des droits RBAC ; un exécuteur sans vérificateur refuse au lieu de
laisser passer ; une portée illisible refuse ; `Controler` n'exécute rien ; une
action refusée ne s'exécute pas.

Les doublures remplacent le vérificateur de droits, l'appartenance au groupe
protégé et la résolution des domaines. Ces tests tournent donc **toujours**, y
compris quand la base ne répond pas — c'est-à-dire aussi les jours où l'on a le
plus besoin de savoir si le contrôle tient.

Ce qu'ils **ne** couvrent pas : que `permission.CheckPermissionsAllDomains`
réponde juste. Ils vérifient que le registre pose la bonne question et respecte
la réponse, pas que la base y réponde correctement.

### Un défaut que ces tests ont révélé

`action.EnregistrerTout()` n'était appelée **que par les tests**. Le serveur
démarrait avec un catalogue vide : toute action, en ligne de commande comme sur
le web, répondait « action inconnue ». Tout se compilait, tout se testait, et
rien ne fonctionnait au premier clic.

Deux corrections, parce qu'une seule aurait laissé le défaut réapparaître :

1. `main` appelle `EnregistrerTout()` avant tout service ;
2. un catalogue vide est **signalé comme tel** au lieu de rendre « action
   inconnue » — les deux messages envoient chercher la faute à des endroits
   opposés.
