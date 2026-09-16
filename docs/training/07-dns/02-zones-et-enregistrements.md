[⌂ Formation](../README.md) › [Chapitre 7 — DNS](./README.md) › Jalon 7.2

# Jalon 7.2 — Zones et enregistrements

[← Activer et exposer le DNS](./01-activer-et-exposer.md) · [Distribuer le résolveur au parc →](./03-distribuer-le-resolveur.md)

---

## Objectif

Créer la zone `acme.lan` et ses enregistrements.

## Syntaxe

```text
dns zone create|list|show|delete <zone>
dns record add <fqdn> <type> <données> [ttl] [priorité]
dns record delete <fqdn> <type>
dns ptr list | dns ptr delete <ip>
```

Types : `A`, `CNAME`, `MX`, `NS`, `TXT`. L'apex s'écrit `@.<zone>`. Le TTL vaut
300 s par défaut.

## Étapes

1. Créez la zone et les enregistrements :

   ```bash
   vlt dns zone create acme.lan
   vlt dns record add vaultaire.acme.lan A <IP-serveur>
   vlt dns record add web01.acme.lan     A <IP-web01>
   vlt dns record add www.acme.lan       CNAME web01.acme.lan
   vlt dns record add @.acme.lan         MX vaultaire.acme.lan 300 10
   vlt dns record add @.acme.lan         TXT "v=spf1 -all"
   ```

2. Relisez :

   ```bash
   vlt dns zone show acme.lan
   vlt dns ptr list
   ```

   Les PTR des enregistrements `A` sont créés automatiquement.

3. Interrogez :

   ```bash
   dig @<IP-serveur> web01.acme.lan +short
   dig @<IP-serveur> www.acme.lan +short
   dig @<IP-serveur> -x <IP-web01> +short
   ```

## ✅ Vous avez réussi si

Les trois `dig` rendent respectivement l'IP de `web01`, `web01.acme.lan.` puis
son IP, et `web01.acme.lan.`.

## 🧪 Exercice

Créez la sous-zone `dev.acme.lan` et l'enregistrement `api.dev.acme.lan`.
Dans quelle zone est-il rangé ?

<details><summary>Solution</summary>

```bash
vlt dns zone create dev.acme.lan
vlt dns record add api.dev.acme.lan A 10.0.0.42
vlt dns zone show dev.acme.lan
```

Dans `dev.acme.lan` : un enregistrement va dans la **zone la plus spécifique**
qui contient son nom.
</details>

> ⚠️ `dns zone delete` supprime la zone **et tout son contenu**, sans retour
> possible.

---

[← Activer et exposer le DNS](./01-activer-et-exposer.md) · [Distribuer le résolveur au parc →](./03-distribuer-le-resolveur.md)
