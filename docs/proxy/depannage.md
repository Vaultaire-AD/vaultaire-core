[⌂ Documentation](../README.md) › [Proxy](./README.md) › Dépannage

# Dépanner un proxy

[← Prévu : HTTPS et LDAP](./prevu-https-ldap.md) · [Proxy ↑](./README.md)

---

## Les trois vérifications de départ

```bash
# Sur le core : le proxy est-il là, en ligne, et exposé à la bonne adresse ?
vlt cluster list

# Sur le proxy : le relais écoute-t-il, et que dit son dernier bilan ?
docker compose logs vlt-proxy | grep 'relais'

# Sur un agent : dans quel ordre voit-il ses nœuds, et lequel utilise-t-il ?
cat /var/log/vaultaire/vlt_client-Debug.log     # si le mode debug est actif
```

Le rapport de debug de l'agent (voir
[`Agent_configuration_et_debug.md`](../exploitation/Agent_configuration_et_debug.md))
montre le nœud utilisé et l'ordre des autres : c'est le moyen le plus direct de
savoir si un agent passe par le proxy.

## Symptômes

| Symptôme | Cause probable | Vérifier / corriger |
|---|---|---|
| Le proxy s'arrête au démarrage : `-listen-port est obligatoire` | option absente | conteneur : `VAULTAIRE_LISTEN_PORT` ; à la main : `-listen-port 6666` |
| `relais Ducky … sur le port X, alors que le port annoncé aux agents est Y` | la section `relais:` écoute ailleurs que `-listen-port` | aligner `ecoute` et `-listen-port` |
| `relais de type "https" prévu mais pas encore activé` | type prévu dans `relais:` | le retirer : seul `ducky` est actif ([détail](./prevu-https-ldap.md)) |
| `bind: address already in use` au démarrage | port déjà pris sur l'hôte | un autre proxy, ou un core sur la même machine sur 6666 |
| `aucune cible joignable pour … — connexion refusée` | aucun core joignable **depuis le proxy** | depuis le conteneur du proxy : `nc -vz <core> 6666` ; pare-feu sortant ; adresse effective du core (`cluster expose` sur le core) joignable du proxy ? |
| Les agents ignorent le proxy et vont au core | adresse annoncée injoignable pour eux | `vlt cluster list` : l'adresse exposée doit être celle de l'hôte et le port **publié** (6667 en préprod) — `vlt cluster expose <proxy> <IP> <port>` |
| Les agents ne voient pas du tout le proxy | proxy hors rotation, ou pas encore de `04_04` reçue | `vlt cluster rotation <proxy> in` ; redémarrer un agent |
| Au-delà d'une vingtaine d'agents par proxy, des connexions échouent | le core ne reconnaît pas l'adresse du proxy : plafond de 20 par IP | l'IP que le core voit (journal du core : `New connection established: <IP>`) doit être l'adresse déclarée du proxy ou son adresse exposée ; sinon (NAT), l'exposer à cette adresse |
| `connexion de … rejetée, plafond atteint` sur le proxy | une machine ouvre plus de 20 connexions | normal pour un poste en boucle ; sinon relever `max_par_source` |
| L'agent refuse le core à travers le proxy (empreinte) | la clé du core n'est pas dans son fichier de confiance | même diagnostic qu'en direct : le proxy n'y est pour rien, il ne présente jamais de clé |
| Connexions coupées après 15 min | inactivité : aucun octet dans aucun sens | un agent Ducky bat toutes les 2 min ; ne se produit que si `inactivite_secondes` a été baissé sous ce délai |

## Lire le bilan

Toutes les 5 minutes, et à l'arrêt :

```
relais ducky (ducky, [::]:6666) : 3 active(s), 120 au total, 4 refusée(s) faute de cible, 0 rejetée(s) au plafond, … cibles [10.0.0.10:6666=116]
```

| Compteur | Ce qu'il dit |
|---|---|
| `active(s)` | connexions en cours |
| `au total` | connexions acceptées depuis le démarrage |
| `refusée(s) faute de cible` | refus francs : aucun core ne répondait. Non nul et croissant → le proxy a perdu ses cores |
| `rejetée(s) au plafond` | connexions fermées par les plafonds du proxy |
| `cibles [...]` | combien de connexions chaque core a reçues. Une seule cible d'habitude : l'ordre est fixe, le second core ne sert qu'en repli |

## Tester le relais à la main

Depuis une machine du site :

```bash
nc -vz <adresse-exposée-du-proxy> <port>      # la connexion s'ouvre
```

Avec les cores arrêtés, la connexion s'ouvre puis se **ferme aussitôt** : c'est
le refus franc, voulu. Une connexion qui reste pendue est un problème (pare-feu
qui avale les paquets entre le proxy et le core : le délai par cible est de 3 s).

---

[← Prévu : HTTPS et LDAP](./prevu-https-ldap.md) · [Proxy ↑](./README.md)
