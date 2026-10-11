[⌂ Formation](../README.md) › [Chapitre 10 — Cluster et proxy](./README.md) › Jalon 10.3

# Jalon 10.3 — Topologie : exposition, affinité, rotation

[← Déployer un proxy](./02-deployer-un-proxy.md) · [Décider ce qu'un proxy expose →](./04-piloter-les-relais.md)

---

## Objectif

Décider par où les agents joignent chaque nœud, et quel nœud sert quel site.

## Syntaxe

```text
cluster expose <nœud> <adresse> [port] | --clear
cluster affinity <nœud> <groupe…> | --none
cluster priority <nœud> <valeur>
cluster rotation <nœud> <in|out>
cluster show <nœud>
cluster maintenance <nœud> <on|off> [--confirm]
cluster purge <nœud> [--etalement <s>]
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

4. Regardez ce que porte chaque core :

   ```bash
   vlt cluster list               # colonne SESSIONS : « m » machines, « c » comptes, « p » poignées
   vlt cluster show <nœud-core>   # le détail, et l'âge de la mesure
   ```

   Chaque core publie ses sessions avec son battement : lui seul les voit.
   `web01` y compte pour **une** machine, même s'il tient plusieurs tunnels.
   Sortir un nœud de la rotation ne ferme **aucune** session : son compteur ne
   descend qu'au fil des reconnexions des agents.

5. Mettez le proxy en **maintenance**, puis essayez avec le core :

   ```bash
   vlt cluster maintenance <nœud-proxy> on
   vlt get -c <computeur_id-web01> --targets   # le proxy a disparu de la liste
   vlt cluster list                            # ÉTAT « online · maint. »
   vlt cluster maintenance <nœud-core> on      # refusé : c'est le dernier core
   vlt cluster maintenance <nœud-proxy> off
   ```

   La maintenance, c'est la rotation `out` **partout** — liste des agents, des
   proxies, des services — sans toucher au réglage de rotation. Sur le core, la
   commande s'arrête : en maintenance, votre unique core ne serait plus servi à
   personne. **Ne confirmez pas.** Sur un cluster à deux cores, `vlt cluster
   purge <nœud-core>` viderait ensuite le core en maintenance de ses sessions :
   chaque poste redemande sa liste et part de lui-même, le reste est fermé, étalé
   sur une minute.

## ✅ Vous avez réussi si

- `--targets` reflète chaque changement, avec la raison de chaque rang ;
- `cluster show <nœud-core>` compte `web01` parmi ses machines, avec une mesure
  de moins d'une minute ;
- en maintenance, le proxy disparaît de `--targets` et y revient au `off` ; la
  maintenance du core est **refusée** sans `--confirm`.

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
[protocole, chapitre 4](../../Developement/how%20it%20work/ducky-network/04-cluster/README.md)

---

[← Déployer un proxy](./02-deployer-un-proxy.md) · [Décider ce qu'un proxy expose →](./04-piloter-les-relais.md)
