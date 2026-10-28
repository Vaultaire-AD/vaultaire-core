[⌂ Ducky Network](../README.md) › [Chapitre 4 — Cluster et découverte (04)](./README.md) › 4.1

# 4.1 — Nœuds et services : enregistrement et battement

[← Sommaire du chapitre](./README.md) · [Découverte de service et proxies →](./02-decouverte-et-proxies.md)

---

| Trame | Reçue par | Nom | Rôle |
|---|---|---|---|
| `04_01` | core | register_host | un **nœud** se déclare : hostname, fqdn, ip, rôle, domaine, port, empreinte |
| `04_02` | nœud | register_host_ack | accusé |
| `04_03` | core | list_cores | demande des nœuds joignables — contenu vide |
| `04_04` | client | list_cores_response | `<nombre>` puis `<host>\|<ip>\|<port>\|<rôle>\|<priorité>\|<empreinte>`, **ordonnée** par le core ; `<ip>` et `<port>` sont les valeurs EFFECTIVES |
| `04_05` | core | proxy_metrics | mesures d'un nœud : `hostname\|ip\|type\|valeur\|extra_json`, une ligne par battement (table `proxy_metrics`) |
| `04_06` | nœud | proxy_metrics_ack | accusé |
| `04_07` | core | host_heartbeat | battement d'un nœud |
| `04_08` | nœud | host_heartbeat_ack | accusé — ou `refus` puis le motif, quand le core ne connaît pas ce nœud : il rejoue alors `04_01` (TO-DO 109) |
| `04_09` | core | register_service | un **service** se déclare : version, point d'accès, capacités |
| `04_10` | service | register_service_ok | accusé |
| `04_11` | service | register_service_error | refus : code et message |
| `04_12` | core | service_heartbeat | battement d'un service |
| `04_13` | service | service_heartbeat_ack | accusé |
| `04_14` | core | service_deregister | sortie propre, sans réponse |
| `04_15` | core | list_services | **proxy et agent** : les services d'un type — contenu `<type>` (ex. `vaultaire_nexus`). Un **agent** n'obtient que `vaultaire_nexus` — ses dépôts de mise à jour (TO-DO 114) ; tout autre type lui rend une liste vide (`hosthandler.TypeDemandable`) |
| `04_16` | proxy | list_services_response | `<type>`, `<nombre>`, puis `<hôte:port>` par service en ligne et exposé, **ordonnés** (priorité, puis nom). Adresse déduite de l'URL déclarée en `04_09` |
| `04_17` | client | refresh_nodes | le core demande à une machine de redemander sa liste — contenu : le motif, aucune liste |
| `04_18` | core | relay_state | **proxy seulement** : compte rendu de ses relais (JSON) — voir [4.4](./04-relais-pilotes.md) |
| `04_19` | proxy | relay_config | la liste de relais que le core demande : `<mode>`, `<révision>`, JSON — voir [4.4](./04-relais-pilotes.md) |

Plage réservée : `04_01` à `04_19` — **pleine**. La trame suivante ouvrira `04_20`.

**Nœud ou service ?** Un nœud (`04_01`) est une MACHINE joignable par les
agents : core, proxy. Un service (`04_09`) est une FONCTION : l'interface web,
Nexus. Le catalogue sépare les deux : un proxy émet `04_01` mais pas `04_09`,
Nexus l'inverse.

---

## Enregistrement d'un service (04_09 à 04_14)

Un service n'a pas à se recréer : son identité et son type ont été posés une
fois pour toutes par l'enrôlement (`01_05` → `01_08`). Ces trames ne servent qu'à
dire **« je suis là, dans telle version, joignable ici »**. Elles sont réservées
aux clients de la famille service (`clienttype.IsService`).

Le rôle écrit dans `cluster_nodes` est le **type** figé à la poignée de main —
`vaultaire_web`, `vaultaire_nexus` —, jamais une valeur lue dans la trame.
Côté code : `ducky-network/host_handler/service_registry.go`.

### 04_09 — register_service (service → core)

```
04_09
serveur_central
<session_integrity_key>
<username_du_programme>
<client_software_id>
<version>
<endpoint>
<capabilities>
```

- `endpoint` : le point d'accès annoncé. Pour un service web, une URL
  (`https://nexus.acme.lan:8843`) ; la page Cluster de l'interface la rend
  cliquable quand elle commence par `http://` ou `https://`.
- `capabilities` : liste séparée par des virgules (ou JSON), **inventaire
  seulement**. Elle n'accorde aucun droit : ce que le service peut émettre est
  décidé par son type au catalogue.

### 04_10 — register_service_ok (core → service)

```
04_10
serveur_central
<session_integrity_key>
<client_software_id>
<type>
```

### 04_11 — register_service_error (core → service)

```
04_11
serveur_central
<session_integrity_key>
<code>
<message>
```

| Code | Quand |
|---|---|
| `invalid_request` | version ou point d'accès absent, capacités illisibles |
| `unknown_service` | le type n'est pas un service, session non liée, ou battement d'un service non enregistré — **rejouer `04_09`** |
| `server_error` | écriture en base impossible |

### 04_12 — service_heartbeat (service → core)

Contenu vide. Met à jour `last_heartbeat` de la ligne dont le service est
**propriétaire**. Sans battement depuis 3 minutes, le core marque le service
hors ligne (`MarkStaleServicesOffline`). Répond `04_13`, ou `04_11
unknown_service` si le core ne connaît pas le service (base réinstallée) : le
service rejoue alors `04_09` — au battement suivant, pas en boucle.

### 04_13 — service_heartbeat_ack (core → service)

En-tête seul.

### 04_14 — service_deregister (service → core)

Sortie propre à l'arrêt. Sans réponse. Sans elle, un arrêt planifié serait
indistinguable d'une panne pendant toute la fenêtre de battement.

### Purge des services partis

`PurgeDepartedServices` supprime, après le délai réglé (`vlt cluster
purge-delay`), la ligne **et le client** d'un service hors ligne. Un service
arrêté plus longtemps que ce délai doit être réenrôlé avec une nouvelle clé.
Le filtre porte sur `clienttype.ServiceNames()` : tout type service ajouté au
catalogue y entre sans rien écrire.

### Hors ligne, puis oublié — et rien entre les deux

`CleanupStaleNodes` (cadence `cluster_cleanup_seconds`) :

| Absence | Effet | Sur quoi |
|---|---|---|
| > 1 minute | `status = 'offline'` : le nœud quitte la liste servie aux agents | tous |
| > délai de purge (`vlt cluster purge-delay`, 24 h, 0 = jamais) | ligne **supprimée** — réglages d'exposition, de priorité et d'affinité compris | nœuds d'infrastructure seulement (tout rôle hors `ServiceNames()`) |

Les services ne sont **pas** supprimés ici : `PurgeDepartedServices` le fait,
avec leur client.

**L'oubli manuel** *(TO-DO 146)* — `cluster forget <nœud>` — retire la ligne sans
attendre, à deux conditions tenues dans la même transaction que le `DELETE` :
`status` différent de `online`, **et** dernier battement plus vieux que trois
battements du cluster (trois minutes au moins). Un nœud vivant se réinscrirait au
battement suivant ; un nœud « offline » depuis une seconde est peut-être en train
de revenir. Contrairement à l'oubli automatique, il retire aussi les relais que le
core demandait au nœud (`cluster_relays`, `cluster_relay_state`) : l'oubli est ici
une décision, et le compte rendu nomme tout ce qui part.

### Maintenance et purge *(TO-DO 147)*

**Maintenance** : colonne `maintenance` de `cluster_nodes`, filtrée par les deux
requêtes des listes (`04_04` pour les agents et les proxies — dont les cibles
`source: cores` des relais —, `04_16` pour les services). Le nœud continue de
battre et reste dans `cluster list` ; sa rotation et sa priorité ne sont pas
touchées. Garde-fou : le **dernier** core servi (en ligne, en rotation, pas en
maintenance) n'y passe qu'avec une confirmation explicite.

**Purge** d'un core en maintenance : le core qui reçoit la commande ne peut pas
la faire — les sessions vivent dans la mémoire du core visé. Elle est donc
**écrite** sur la ligne du nœud, et le core visé la lit à son battement :

1. une `04_17` à chaque machine qui tient un tunnel ici, qui **nomme** le nœud à
   quitter — une ligne `quitter <hôte:port>` par accès (TO-DO 216, voir
   `02-decouverte-et-proxies.md`). L'agent le quitte (`QuitterSiCourant`, après
   0 à 20 s) et le place en dernier pendant 15 minutes. Le core n'étant plus
   dans la liste, un agent qui ne lit pas ces lignes voit encore son nœud
   courant disparaître (`bascule.go`) — mais pas si la liste revient vide, ni
   à sa reconnexion, qui suit la liste en main : c'est ce que le 216 corrige ;
2. après une minute de grâce, ce qui reste — agents anciens, postes Windows,
   proxies, sessions de compte, poignées de main — est fermé une session à la
   fois, **étalé** (60 s par défaut, `--etalement`) ;
3. la fin et le nombre de sessions fermées **par la purge** sont écrits sur la
   ligne ; celles parties d'elles-mêmes ne sont pas comptées.

Les sessions du portail et de l'API ne sont pas des sessions Ducky : la purge
ne les touche pas. Un processus n'exécute qu'une fois une même demande, même si
l'écriture de la fin échoue — sinon la purge se rejouerait à chaque battement.

**Purge d'un proxy** *(TO-DO 176)*. Un proxy relaie en TCP : les sessions qu'il
porte vivent dans le registre des **cores**, et leur adresse source est celle du
proxy (vérifié le 15/10). La demande est écrite sur la ligne du proxy comme pour
un core ; **chaque core** la lit à son battement (`PurgesDeProxiesEnCours`, demandes
de moins de 15 minutes) et fait sa part avec le même purgeur, sur une vue de son
registre (`sessionmgr.VueParSource`) :

- les sessions retenues sont celles dont l'hôte source est l'adresse déclarée du
  proxy (`ip_address`), l'adresse **vue** (`adresse_vue`, réécrite par le core qui
  reçoit son `04_07`), ou la source de la session du proxy dans CE registre ;
- la session de contrôle du proxy (son `client_software_id`) est **exclue** : il
  continue de battre et de recevoir `04_19` ;
- sans aucune adresse connue, la vue est vide — on ne purge jamais tout un core
  faute d'avoir reconnu le proxy ;
- chaque core **additionne** ses fermetures à `purge_fermees` ; la fin écrite est
  celle de la dernière part. Une mémoire par proxy et par date de demande empêche
  un core de rejouer sa part.

Limite connue : derrière un NAT, les machines qui sortent par la même adresse que
le proxy sont fermées aussi ; elles se reconnectent.

La `04_17` de la purge d'un proxy nomme ses accès vus des agents
(`AccesPourAgents` : l'accès exposé, puis `ip_address:ducky_port`) : l'agent
relayé quitte le proxy et le met en dernier, même si sa liste revient vide
(TO-DO 216 — recette du 25/10 : le poste restait connecté par le proxy).

**La confiance des proxies suit la même adresse** *(TO-DO 184)*.
`core/proxiesconnus` — plafond Ducky de 1000 par adresse, en-tête PROXY v2 du
LDAPS — retient `adresse_vue` (et `ip_address` seulement tant qu'aucune adresse
n'a été vue), plus la source des sessions **authentifiées** du proxy dans le
registre du core qui répond. L'adresse d'exposition (`adresse_publique`) n'y
entre plus : elle est celle des clients, et derrière un NAT elle diffère de
celle que voit le core.

**Un core en maintenance accepte toujours les connexions** *(TO-DO 177,
tranché le 15/10 : on ne refuse pas)*. La maintenance retire le core des
**listes** ; elle ne ferme pas son écoute. Un agent qui ne connaît que son
fichier de configuration (agent ancien, liste jamais reçue) peut donc y revenir
après une purge, et le compteur SESSIONS de `cluster show` remonte : c'est
visible, et c'est voulu. Refuser ferait partir ces agents vers le core suivant
de leur fichier — mais couperait aussi tout le parc si les autres cores
tombaient pendant la maintenance, au moment précis où ce core est le dernier
recours. Un agent à jour, lui, reçoit la liste sans ce core et en repart
(`bascule.go`).

> Jusqu'au TO-DO 85, la suppression tombait à **cinq minutes**, pour tous. Un
> proxy redémarré lentement ou un hôte en veille revenait par un `INSERT` neuf,
> aux valeurs par défaut : les décisions d'exploitation étaient perdues, et le
> délai de purge des services n'était jamais atteint. Le core, lui, battait
> ensuite dans le vide sans se réenregistrer — il le fait désormais.

---

[← Sommaire du chapitre](./README.md) · [Découverte de service et proxies →](./02-decouverte-et-proxies.md)
