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
| `04_05` | core | proxy_metrics | métriques d'un proxy (table `proxy_metrics`) |
| `04_06` | nœud | proxy_metrics_ack | accusé |
| `04_07` | core | host_heartbeat | battement d'un nœud |
| `04_08` | nœud | host_heartbeat_ack | accusé |
| `04_09` | core | register_service | un **service** se déclare : version, point d'accès, capacités |
| `04_10` | service | register_service_ok | accusé |
| `04_11` | service | register_service_error | refus : code et message |
| `04_12` | core | service_heartbeat | battement d'un service |
| `04_13` | service | service_heartbeat_ack | accusé |
| `04_14` | core | service_deregister | sortie propre, sans réponse |

Plage réservée : `04_01` à `04_19` — libre à partir de `04_15`.

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

---

[← Sommaire du chapitre](./README.md) · [Découverte de service et proxies →](./02-decouverte-et-proxies.md)
