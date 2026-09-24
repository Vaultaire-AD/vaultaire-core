[⌂ Documentation](../README.md) › [Proxy](./README.md) › Relais

# Les relais

[← Déploiement](./deploiement.md) · [Sécurité →](./securite.md)

---

## Ce qu'est un relais

Un relais écoute un port, accepte une connexion, en ouvre une vers une **cible**
et recopie les octets dans les deux sens. Il ne lit rien, ne termine rien : ni
la session Ducky, ni TLS. Le même code sert donc pour tous les protocoles ; d'un
type à l'autre ne changent que **vers qui** on relaie et le port par défaut.

| Type | De → vers | Port par défaut | État |
|---|---|---|---|
| `ducky` | agents → cores | 6666 | **actif** (2.2) |
| `https` | navigateurs, `dnf`, `docker` → services HTTPS du cluster (Nexus…) | 443 | **actif** (TO-DO 72) |
| `ldaps` | applications → cores, avec l'adresse du client (PROXY v2) | 636 | **actif** (TO-DO 72) |
| `ldap` | applications → cores | 389 | **refusé** |

`ldap` est reconnu par la configuration et **refusé au démarrage** : relayé, il
ferait voyager les mots de passe en clair du site jusqu'au core. Le détail des
relais `https` et `ldaps` — cibles, certificats, en-tête PROXY — est dans
[`https-et-ldaps.md`](./https-et-ldaps.md).

## Le cas courant : aucune configuration

Sans section `relais:` dans `config.yaml`, le proxy ouvre **un** relais Ducky
vers les cores, sur le port de `-listen-port`. C'est ce que fait le conteneur
`vlt-proxy`, et c'est ce qu'il faut dans presque tous les cas.

## La section `relais:`

```yaml
relais:
  - nom: ducky
    type: ducky
    ecoute: ":6666"            # [adresse]:port — pour ducky, le port de -listen-port
    cibles:
      source: cores
    delai_connexion_secondes: 3   # pour joindre UNE cible
    inactivite_secondes: 900      # connexion muette fermée au-delà
    max_connexions: 4000          # total
    max_par_source: 20            # par adresse IP cliente
```

| Champ | Défaut | Remarque |
|---|---|---|
| `nom` | le type | unique ; apparaît dans chaque ligne du journal |
| `type` | `ducky` | `ducky`, `https`, `ldap`, `ldaps` |
| `ecoute` | `:<port par défaut>` | `ducky` : obligatoirement le port de `-listen-port` |
| `cibles.source` | `cores` | voir ci-dessous |
| `cibles.adresses` | — | pour `source: liste`, en `hôte:port` |
| `cibles.port` | 636 pour `ldaps`, le port annoncé sinon | pour `source: cores` seulement : le port à joindre sur chaque core |
| `delai_connexion_secondes` | 3 | court à dessein : on passe vite à la cible suivante |
| `inactivite_secondes` | 900 | doit dépasser le battement du protocole (Ducky : 2 min) |
| `max_connexions` | 4000 | |
| `max_par_source` | 20 | une machine ne prend pas toutes les places |

Règles vérifiées au chargement — une erreur arrête le proxy :

- un seul relais `ducky`, et sur le port annoncé : les agents se présentent là où
  le cluster leur dit d'aller ;
- deux relais n'ont ni le même nom ni la même adresse d'écoute ;
- une source `liste` a au moins une adresse, chacune en `hôte:port` ;
- un relais `https` nomme ses cibles (`service:<type>` ou `liste`) : `cores`
  donnerait les adresses Ducky des cores ;
- `service:<type>` ne sert qu'au relais `https`.

## Les sources de cibles

| Source | Cibles, dans l'ordre | État |
|---|---|---|
| `cores` | les cores appris du cluster (trame `04_04`, dans l'ordre servi), puis les serveurs du `config.yaml` du proxy | actif |
| `liste` | les `adresses`, dans l'ordre écrit | actif |
| `service:<type>` | les services d'un type en ligne, p. ex. `service:vaultaire_nexus` — trame `04_15`, relue toutes les 5 min | actif (`https`) |

Avec `cores`, les **proxies** de la liste apprise sont écartés : relayer vers un
autre proxy pourrait boucler, et n'apporterait rien. L'adresse utilisée est
l'adresse **effective** servie en `04_04` — celle de `cluster expose` si elle
est déclarée. Pour un relais `ldaps`, son port est remplacé par le port LDAPS
(`cibles.port`, 636 par défaut) : la `04_04` n'annonce que le port Ducky.

`liste` sert aux tests et aux sites qui doivent viser un core précis.

## Comment une connexion est traitée

1. **Plafonds.** Au-delà de `max_par_source` pour cette IP, ou de
   `max_connexions`, la connexion est fermée (compteur *rejetées*).
2. **Choix de la cible.** Les cibles sont essayées **dans l'ordre**, chacune
   avec `delai_connexion_secondes`. **Pas de rotation** : un agent garde en cache
   la clé d'UN core ; le promener d'un core à l'autre ferait échouer la poignée
   de main dès que les cores n'ont pas la même clé.
3. **Refus franc.** Aucune cible ne répond : la connexion de l'agent est
   **fermée aussitôt** (compteur *refusées*). L'agent essaie alors le nœud
   suivant de sa liste — un core, puisqu'ils y figurent toujours. Faire
   attendre l'agent ferait du proxy un trou noir.
4. **Transport.** Octets recopiés dans les deux sens. Fin propre d'un côté :
   demi-fermeture, l'autre sens finit de passer. Erreur ou inactivité : les deux
   côtés sont fermés.

Le relais **ne rejoue rien** : une connexion coupée en cours l'est pour l'agent,
qui se reconnecte comme il le ferait en direct.

## Ce que dit le journal

| Niveau | Message | Quand |
|---|---|---|
| INFO | `relais ducky (ducky) : écoute sur [::]:6666` | au démarrage |
| INFO | `relais ducky (ducky, [::]:6666) : 3 active(s), 120 au total, 0 refusée(s) faute de cible, 0 rejetée(s) au plafond, … cibles [10.0.0.10:6666=120]` | toutes les 5 minutes, et à l'arrêt |
| WARNING | `relais ducky : aucune cible joignable pour 10.1.2.3 — connexion refusée` | refus franc |
| WARNING | `relais ducky : connexion de 10.1.2.3 rejetée, plafond atteint` | plafond |
| DEBUG | `relais ducky : 10.1.2.3 → 10.0.0.10:6666` | chaque connexion (`-debug`) |
| DEBUG | `relais ducky : cible 10.0.0.10:6666 injoignable : …` | chaque cible essayée en vain |

Le bilan périodique est là pour un cas : un relais qui refuse tout ne se verrait
sinon qu'en lisant une ligne par connexion. Diagnostic : [`depannage.md`](./depannage.md).

## Ce que le relais ne fait pas

- **Répartir la charge.** L'ordre est fixe ; la répartition entre sites se fait
  par l'affinité et la priorité, côté core (`vlt cluster`).
- **Filtrer qui a le droit de passer.** Tout client qui joint le port est
  relayé ; c'est le core qui authentifie. Restreindre quels nœuds un client voit
  est le sujet du TO-DO 67.
- **Garder l'adresse du client.** Le core voit l'IP du **proxy** — d'où
  l'exemption décrite en [`securite.md`](./securite.md#le-plafond-par-adresse-côté-core).

---

[← Déploiement](./deploiement.md) · [Sécurité →](./securite.md)
