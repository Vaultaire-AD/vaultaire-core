[⌂ Documentation](../README.md) › [Proxy](./README.md) › HTTPS et LDAPS

# Relais HTTPS et LDAPS

[← Sécurité](./securite.md) · [Dépannage →](./depannage.md)

---

Depuis le **TO-DO 72**, le proxy ne relaie plus seulement Ducky :

- **HTTPS vers les services du cluster** — un site installe ses paquets depuis
  un **Nexus** (dépôts RPM, Debian, registre Docker) en ne joignant que son
  proxy ;
- **LDAPS vers les cores** — les applications d'un site (Keycloak, GitLab, une
  appliance) interrogent l'annuaire par le proxy local.

Le relais ne termine **toujours pas TLS** : le client négocie TLS avec le Nexus
ou le core, de bout en bout. Le proxy ne voit ni un mot de passe, ni un paquet.

```yaml
relais:
  - nom: ducky
    type: ducky
    ecoute: ":6666"
  - nom: nexus
    type: https
    ecoute: ":8843"
    cibles:
      source: "service:vaultaire_nexus"
  - nom: ldaps
    type: ldaps
    ecoute: ":1636"            # port haut : le conteneur tourne en UID 10001
    cibles:
      source: cores            # port 636 des cores, par défaut
```

## HTTPS vers un Nexus

### D'où viennent les cibles

`source: "service:vaultaire_nexus"` : le proxy demande au core les Nexus **en
ligne** par la trame **`04_15`**, au démarrage puis toutes les **5 minutes**. La
réponse **`04_16`** donne leurs adresses, déduites de l'URL publique que chaque
Nexus déclare (`public_url` : `https://nexus.acme.lan:8843` → `nexus.acme.lan:8843`,
443 si l'URL n'a pas de port).

- **Ordre fixe**, sans rotation : priorité explicite (`vlt cluster priority`),
  puis les Nexus sans priorité, puis le nom. Garder un site sur le même dépôt
  évite de promener un `docker pull` entre deux Nexus pas encore synchronisés.
  Si le premier ne répond pas, le suivant est tenté.
- **`vlt cluster rotation <nexus> out`** retire un Nexus de la liste, au plus
  cinq minutes plus tard.
- Une liste **vide** remplace la précédente : le relais refuse alors franchement,
  plutôt que de tenter des adresses que le core dit hors ligne.

La `04_15` est **réservée aux proxies** : la carte des services n'est pas
diffusée à tout le parc, comme elle le serait dans la `04_04` que reçoit chaque
agent.

Une source `liste` reste possible (Nexus hors cluster, tests). La source
`cores` est **refusée** pour un relais `https` : elle donne les adresses Ducky
des cores, pas un service HTTPS.

### Le certificat

Le client reçoit le certificat **du Nexus**. Il doit donc porter le nom par
lequel le client joint le proxy. Deux façons :

1. ajouter ce nom au SAN du Nexus (`tls.dns_names` de sa configuration) ;
2. ou faire résoudre le nom du Nexus **vers le proxy** par le DNS du site : le
   client vise `nexus.acme.lan`, le DNS du site répond l'adresse du proxy, et
   le certificat correspond sans rien changer.

La seconde est la plus simple quand le site a son propre DNS — voir
[`Utilisation/DNS.md`](../Utilisation/DNS.md).

### Ce que Nexus voit

L'adresse **du proxy** pour tous les clients du site : aucun en-tête ne la
corrige, le relais ne terminant pas TLS. Les journaux d'accès de Nexus et son
verrouillage après échecs nomment donc le proxy.

## LDAPS vers les cores

### L'adresse du client : PROXY protocol v2

Le core freine les échecs de bind **par adresse source**. Derrière un proxy,
tout le site partagerait un compteur : un poste qui se trompe de mot de passe
en boucle ferait freiner tout le site, et un balayage d'un mot de passe sur
mille comptes ne serait plus freiné par source du tout.

Le relais `ldaps` place donc devant chaque connexion un **en-tête PROXY v2**
(spécification HAProxy) qui porte l'adresse du client. Le core le lit **avant**
la poignée de main TLS et s'en sert partout où il lit l'adresse du client :
limitation des binds, journaux, session LDAP.

| Le pair qui envoie l'en-tête | Le core |
|---|---|
| un proxy **enregistré** et en ligne | croit l'en-tête : le client est compté sous son adresse |
| n'importe qui d'autre | **ferme** la connexion — `en-tête PROXY reçu d'un pair qui n'est pas un proxy enregistré` |
| un proxy, sans en-tête | connexion ordinaire, sous l'adresse du proxy |

Refuser plutôt qu'ignorer : quelqu'un qui envoie cet en-tête sans être un proxy
essaie précisément de choisir l'adresse sous laquelle il est compté.

L'en-tête n'est envoyé **qu'en LDAPS**, sans réglage : l'écoute Ducky et un
Nexus le prendraient pour le début de leur protocole.

### Le port

`source: cores` : les cores appris du cluster, **joints sur leur port LDAPS** —
636 par défaut, `cibles.port` sinon. La découverte n'annonce que leur port
Ducky, qu'il ne faut surtout pas reprendre ici.

```yaml
    cibles:
      source: cores
      port: 10636              # si les cores écoutent LDAPS ailleurs que sur 636
```

### Le certificat du core

Le client LDAPS vérifie le nom du serveur. Le certificat du core doit couvrir le
nom ou l'adresse **par lesquels les applications joignent le proxy** : ajoutez-les
à `ldaps_tls_dns_names` / `ldaps_tls_ip_addresses` de la configuration du core,
puis `vlt certificate regenerate ldaps`. Voir
[`exploitation/ldaps_keycloak.md`](../exploitation/ldaps_keycloak.md).

### Le plafond côté core

Les applications d'un site arrivent sur le core par l'adresse du proxy : pour un
proxy enregistré, le plafond de connexions LDAP par adresse passe de 20 à
**200**, comme pour Ducky. Le plafond global (500) reste commun.

## LDAP en clair : refusé

Le type `ldap` (389) reste **refusé** au démarrage :

```
relais de type "ldap" refusé : relayé, LDAP en clair ferait voyager les mots de
passe en clair du site jusqu'au core, et le core n'implémente pas StartTLS —
employez « ldaps »
```

Le core accepte le bind en clair tant que `RequireTLSForBind` n'est pas posé,
mais un relais le ferait passer sur le lien le plus long — du site au core —,
celui qu'on protège le moins bien.

## Le port 443 et les ports privilégiés

Le conteneur `vlt-proxy` tourne en UID 10001 : il ne peut pas écouter sous
1024. Écoutez sur un port haut (`:8843`, `:1636`) et publiez 443 ou 636 sur
l'hôte, ou donnez `CAP_NET_BIND_SERVICE` au conteneur.

---

[← Sécurité](./securite.md) · [Dépannage →](./depannage.md)
