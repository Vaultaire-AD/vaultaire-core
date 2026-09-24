[⌂ Documentation](../README.md) › [Proxy](./README.md) › Prévu : HTTPS et LDAP

# Relais prévus : HTTPS, LDAP, LDAPS

[← Sécurité](./securite.md) · [Dépannage →](./depannage.md)

---

Le proxy ne doit pas relayer que vers des cores. Deux besoins sont identifiés :

- **HTTPS vers des services du cluster** — un site qui installe ses paquets
  depuis un **Nexus** (dépôts RPM, Debian, registre Docker) ne devrait joindre
  que son proxy ;
- **LDAP et LDAPS vers les cores** — les applications d'un site (Keycloak,
  GitLab, une appliance) interrogent l'annuaire par le proxy local.

Ce document dit ce qui est **déjà prêt** dans le code, et ce qui **manque** avant
d'activer ces types. Le suivi est le **TO-DO 72**.

## Ce qui est prêt

Le relais a été écrit pour tous les types dès le lot 4 :

- `relais.Type` connaît `ducky`, `https`, `ldap`, `ldaps`, avec leurs ports par
  défaut (6666, 443, 389, 636) ;
- la section `relais:` du `config.yaml` accepte plusieurs relais, chacun avec
  son port et ses cibles ;
- les sources `cores`, `liste` et `service:<type>` sont reconnues ;
- le transport est le même pour tous : octets recopiés sans lecture, refus
  franc, plafonds, bilan dans le journal.

Deux verrous empêchent l'activation, volontairement :

| Verrou | Où | Message |
|---|---|---|
| type non actif | `relais/config.go`, table `actif` | `relais de type "https" prévu mais pas encore activé (TO-DO 72)` |
| source `service:` | `relais.Valider` | `la source "service:…" (services du cluster) est prévue avec le relais HTTPS` |

Activer un type revient à l'ajouter à `actif`, **une fois** les conditions
ci-dessous remplies — et à écrire les tests qui les vérifient.

Exemple de configuration visée :

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
    ecoute: ":636"
    cibles:
      source: cores
```

## Ce qui manque

### HTTPS vers un Nexus

1. **Découvrir les services.** La trame `04_04` n'annonce que les **cores** et
   les **proxies**. Pour `source: "service:vaultaire_nexus"`, le proxy doit
   apprendre les adresses des Nexus du cluster : soit une extension de `04_04`
   (un rôle `service` avec son type), soit une trame dédiée, réservée aux
   proxies. À trancher avec le TO-DO 67 (quels nœuds un client voit).
2. **Le certificat.** Le relais ne termine pas TLS : le navigateur, `dnf` ou
   `docker` reçoivent le certificat **du Nexus**. Il doit porter dans son SAN le
   nom par lequel les clients joignent le proxy — ou les clients doivent viser
   le nom du Nexus résolu vers le proxy par le DNS du site.
3. **Plusieurs Nexus.** L'ordre fixe (sans rotation) convient : un client HTTP
   n'a pas de clé en cache, mais garder l'ordre évite de promener un `docker
   pull` entre deux dépôts pas encore synchronisés.
4. **Port.** 443 est privilégié : le conteneur tourne en UID 10001. Écouter sur
   un port haut (8843) et publier 443 sur l'hôte, ou donner
   `CAP_NET_BIND_SERVICE`.

### LDAP et LDAPS vers les cores

1. **SAN du certificat du core** (lot 5 du point 38). En LDAPS, le client
   vérifie le nom du serveur : le certificat du core doit couvrir les noms ou
   adresses des proxies, sinon le client TLS refuse — voir
   [`exploitation/ldaps_keycloak.md`](../exploitation/ldaps_keycloak.md).
2. **Limitation par source.** Le core freine les échecs de bind **par adresse
   IP**. Derrière un proxy, tout le site partage l'adresse du proxy : un poste qui
   se trompe de mot de passe en boucle ferait freiner tout le site. Il faut, pour
   les adresses de proxies enregistrés, soit une exemption comme pour Ducky
   ([`securite.md`](./securite.md#le-plafond-par-adresse-côté-core)), soit un
   moyen de transmettre l'adresse d'origine (PROXY protocol v2, lu **seulement**
   depuis un proxy enregistré — sans quoi n'importe qui choisirait son adresse).
3. **LDAP en clair.** Le core refuse déjà le bind simple hors TLS. Un relais
   `ldap` (389) ne sert donc qu'avec StartTLS : à documenter, ou à ne pas
   activer du tout.
4. **Port.** 389 et 636 sont privilégiés : même remarque que pour 443.

## Ce qui ne changera pas

- Le relais **ne terminera pas TLS**, pour aucun type (arbitrage 2).
- Le **refus franc** reste la règle : un client HTTP ou LDAP qui reçoit une
  fermeture essaie son serveur suivant, s'il en a un.
- Un seul relais **Ducky** par proxy, sur le port annoncé au cluster.

---

[← Sécurité](./securite.md) · [Dépannage →](./depannage.md)
