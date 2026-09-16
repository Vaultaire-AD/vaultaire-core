[⌂ Formation](../README.md) › [Chapitre 10 — Cluster et proxy](./README.md) › Jalon 10.3

# Jalon 10.3 — Topologie : exposition, affinité, rotation

[← Déployer un proxy](./02-deployer-un-proxy.md) · [Fin de la formation ⌂](../README.md)

---

## Objectif

Décider par où les agents joignent chaque nœud, et quel nœud sert quel site.

## Syntaxe

```text
cluster expose <nœud> <adresse> [port] | --clear
cluster affinity <nœud> <groupe…> | --none
cluster priority <nœud> <valeur>
cluster rotation <nœud> <in|out>
```

## Étapes

1. Le proxy annonce une adresse interne au réseau Docker. Déclarez celle par
   laquelle le parc le joint :

   ```bash
   vlt cluster expose <nœud-proxy> <IP-hôte> 16666
   vlt cluster list        # ACCÈS AGENTS vs VU PAR LE NŒUD
   ```

2. Faites-le servir le groupe `Infra` en priorité :

   ```bash
   vlt cluster affinity <nœud-proxy> Infra
   vlt get -c <computeur_id-web01> --targets
   ```

   Le proxy passe en tête pour `web01`, les cores restent derrière.

3. Sortez-le pour maintenance, puis remettez-le :

   ```bash
   vlt cluster rotation <nœud-proxy> out
   vlt get -c <computeur_id-web01> --targets
   vlt cluster rotation <nœud-proxy> in
   ```

## ✅ Vous avez réussi si

`--targets` reflète chaque changement, avec la raison de chaque rang.

## 🧪 Exercice

Comment faire qu'un proxy enrôlé pour le site de Lyon serve Lyon **sans** geste
manuel après son déploiement ?

<details><summary>Solution</summary>

Émettre sa clé avec des groupes de naissance :

```bash
vlt enroll create --type vaultaire_proxy --groups lyon --uses 1 --expires 1h
```

Le proxy entre dans `lyon` à l'enrôlement, et son affinité est semée à
l'enregistrement.
</details>

> `rotation out` n'est pas un contrôle d'accès : le nœud reste joignable par qui
> connaît son adresse. C'est le pare-feu qui protège un nœud.

## 📚 Référence

[`MAN.md` §19 et §21](../../Utilisation/MAN.md) ·
[`vlt-proxy/README.md`](../../../deployments/pre-prod/vlt-proxy/README.md) ·
[`Protocole_Ducky.md`](../../Developement/how%20it%20work/Protocole_Ducky.md)

---

[← Déployer un proxy](./02-deployer-un-proxy.md) · [Fin de la formation ⌂](../README.md)
