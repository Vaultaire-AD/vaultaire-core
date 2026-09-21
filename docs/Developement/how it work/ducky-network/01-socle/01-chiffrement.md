[⌂ Ducky Network](../README.md) › [Chapitre 1 — Le socle : canal, format, contrôles](./README.md) › 1.1

# 1.1 — Chiffrement du canal

[← Sommaire du chapitre](./README.md) · [Format des trames →](./02-format-des-trames.md)

---


Deux régimes se succèdent sur une même connexion, et la bascule se fait à
l'établissement de la clé de session (`duckysession.IsSafe`).

| Phase | Schéma | Clé |
|-------|--------|-----|
| Avant `IsSafe` | **RSA-4096 OAEP, SHA-256, label nil** | clé publique du destinataire |
| Après `IsSafe` | AES-GCM | clé de session |

### RSA-OAEP et non PKCS#1 v1.5

Le bourrage PKCS#1 v1.5 était utilisé jusqu'à la version 2.1. Il est vulnérable à
l'attaque de Bleichenbacher — un oracle de bourrage à texte chiffré choisi — et
les trois conditions étaient réunies pour l'exploiter **sans posséder le moindre
identifiant** :

- la clé publique du serveur s'obtient par un `askkey` non authentifié ;
- tant que `IsSafe` est faux, le serveur déchiffre avec sa clé privée **toute**
  trame reçue (`trames_manager/ReadMessageContent.go`) ;
- l'échec de déchiffrement était observable — journal `CRITICAL`, et comportement
  différent en aval.

Un attaquant ayant enregistré un échange de clé de session pouvait donc la
déchiffrer hors ligne. OAEP ferme ce chemin : bourrage probabiliste, et
vérification qui ne laisse pas fuir d'information exploitable.

**Les clés n'ont pas changé.** OAEP est un schéma de bourrage posé au-dessus de
RSA, pas un format de clé : mêmes paires, mêmes fichiers PEM, mêmes lignes en
base. Seul le texte chiffré diffère, ce qui rend la version 2.1 incompatible avec
les agents antérieurs — bascule simultanée du serveur et du parc.

### Conséquence sur la taille

OAEP consomme `2×hLen + 2` octets de bourrage contre 11 pour PKCS#1 v1.5. Sur les
clés RSA-4096 du canal :

```
501 octets utiles (PKCS#1 v1.5)  →  446 octets utiles (OAEP-SHA256)
```

Le chiffrement asymétrique porte sur la **trame entière**, en-tête compris. La
plus grosse trame antérieure à `IsSafe` est le `02_01` :

```
02_01\nserveur_central\n<uuid 36>\n<username>\n<clientID 12>\n<password>
≈ 112 octets + le mot de passe
```

Il reste donc plus de 330 caractères de marge. **Aucune fragmentation n'est
nécessaire** — contrairement au transport GPO, qui lui bute sur la limite
`uint16` du fil (voir plus bas).

### Où sont les paramètres

Les deux modules Go étant séparés, les paramètres sont nécessairement dupliqués.
C'est la seule duplication assumée du projet, et elle impose une règle : **les
deux fichiers se modifient ensemble ou pas du tout.**

| Côté | Fichier |
|------|---------|
| serveur | `ducky-network/key_decode_encode/oaep_params.go` |
| agent | `duckynetworkClient/key_encode_decode/oaep_params.go` |

Une divergence de hachage ou de label produit un échec de déchiffrement
**indistinguable d'une mauvaise clé**, ce qui envoie chercher au mauvais endroit.

---

[← Sommaire du chapitre](./README.md) · [Format des trames →](./02-format-des-trames.md)
