[⌂ Formation](../README.md) › [Chapitre 11 — Nexus](./README.md) › Jalon 11.4

# Jalon 11.4 — Exposer Nexus par un proxy

[← Changer la version d'un agent par Nexus](./03-mettre-a-jour-un-agent.md) · [Fin de la formation ⌂](../README.md)

---

## Objectif

Ouvrir sur le proxy du chapitre 10 un relais **HTTPS** vers les Nexus du
cluster, le traverser comme le ferait un poste d'un site distant, puis savoir
faire passer **les agents** de ce site par lui.

## Ce qu'il faut savoir

- Un site distant ne joint que **son proxy**. Le relais `https` transporte les
  connexions vers Nexus **sans terminer TLS** : le client négocie avec Nexus de
  bout en bout. Le proxy ne voit ni un jeton, ni un paquet.
- **`--source service:vaultaire_nexus`** : le proxy demande au core les Nexus
  **en ligne et dans la rotation** (trame `04_15`), au démarrage puis toutes
  les **5 minutes**. Les cibles sont tirées de leur `public_url`. Ordre fixe :
  priorité (`vlt cluster priority`), puis les autres, puis le nom.
- **Le certificat reçu est celui de Nexus.** Il doit porter le nom (ou
  l'adresse) que le client vise. Deux façons : ajouter ce nom au certificat
  (`tls.dns_names` / `tls.ip_addresses`), ou, mieux, viser partout **un nom**
  (`nexus.acme.lan`) que le DNS de chaque site fait pointer vers ce qu'il peut
  joindre : Nexus au siège, le proxy ailleurs.
- **Nexus voit l'adresse du proxy** pour tout le site, dans son suivi comme
  dans son verrouillage après échecs.

## Étapes

1. **Publiez le port** du relais dans le compose du proxy
   (`deployments/pre-prod/vlt-proxy/docker-compose.yml`). Le core ne voit pas
   ce que la machine publie : c'est la seule partie qui se fait chez le proxy.

   ```yaml
       ports:
         - "6667:6666"
         - "8853:8843"     # au labo, 8843 est déjà pris par Nexus sur le même hôte
   ```

   ```bash
   docker compose -f deployments/pre-prod/vlt-proxy/docker-compose.yml up -d
   ```

   > Sur un vrai site distant, publiez **le même port** que celui de
   > `public_url` (`8843:8843`) : un client garde le port de l'URL.

2. **Ouvrez le relais depuis le core** :

   ```bash
   vlt cluster relais <nœud-proxy> set nexus --type https --ecoute :8843 --source service:vaultaire_nexus
   vlt cluster relais <nœud-proxy>
   ```

   La ligne `nexus` passe à **appliqué**. Dans le journal du proxy :

   ```
   relais nexus (https) : écoute sur [::]:8843
   services du cluster : 1 vaultaire_nexus joignable(s) [<IP-serveur>:8843]
   ```

3. **Traversez-le** depuis `web01`, comme un poste du site distant dont le DNS
   enverrait vers le proxy. `--connect-to` dit à `curl` : « vise
   `<IP-serveur>:8843`, mais connecte-toi au proxy » :

   ```bash
   N=https://<IP-serveur>:8843
   curl -sS --connect-to <IP-serveur>:8843:<IP-proxy>:8853 $N/healthz
   curl -sS --connect-to <IP-serveur>:8843:<IP-proxy>:8853 $N/repo/vaultaire/releases/api/releases/latest | head
   ```

   Le certificat est accepté : c'est celui de Nexus, pour le nom visé (approuvé
   par le système au jalon 11.2 ; sinon, ajoutez `--cacert
   /etc/vaultaire_client/nexus-ca.pem`). Puis :

   ```bash
   vlt cluster relais <nœud-proxy>        # ACT./TOTAL du relais nexus a bougé
   ```

   Et dans Nexus, **Suivi** : ces accès viennent de l'adresse **du proxy**.

4. **Visez le proxy par son propre nom** :

   ```bash
   curl -sS https://<IP-proxy>:8853/healthz
   ```

   Si `<IP-proxy>` n'est pas dans le certificat de Nexus : `certificate is not
   valid for …`. Le proxy n'y est pour rien : c'est le certificat de Nexus qui
   ne connaît pas ce nom. Au labo, si le proxy tourne sur l'hôte de Nexus, son
   adresse **est** `<IP-serveur>` et la commande passe ; visez-le alors par un
   nom absent du certificat :

   ```bash
   curl -sS --resolve proxy-lab.acme.lan:8853:<IP-proxy> https://proxy-lab.acme.lan:8853/healthz
   ```

5. **Retirez Nexus de la rotation**, puis remettez-le :

   ```bash
   vlt cluster rotation <nœud-nexus> out
   ```

   Au plus cinq minutes plus tard, le proxy journalise `0 vaultaire_nexus
   joignable(s)` et refuse franchement les connexions du relais, au lieu
   d'essayer une adresse que le core dit indisponible. Les **agents** ne se
   voient plus annoncer ce Nexus non plus.

   ```bash
   vlt cluster rotation <nœud-nexus> in
   ```

## Les agents d'un site distant

Un agent ne choisit pas son dépôt au hasard. Il prend les Nexus que le core lui
annonce, par leur **`public_url`**. `update_repository` ne sert **que** si le
cluster n'en annonce aucun. Pour qu'un site passe par son proxy :

1. donnez à Nexus une `public_url` **par nom** : `https://nexus.acme.lan:8843`
   (`NEXUS_PUBLIC_URL`), ce nom étant dans `tls.dns_names` ;
2. faites résoudre `nexus.acme.lan` vers **Nexus** au siège et vers **le proxy**
   sur le site distant (DNS du site, chapitre 7) ;
3. publiez sur le proxy le **même port** (`8843:8843`) ;
4. sur une machine du site, au démarrage de l'agent :
   `mise à jour : dépôt(s) https://nexus.acme.lan:8843 (cluster)`. Rejouez le
   jalon 11.3 : la bascule passe par le proxy, et le **Suivi** de Nexus montre
   son adresse.

Les mêmes remarques valent pour `dnf`, `apt`, `docker` et `docker-update.sh` :
l'API des releases donne des liens de téléchargement **en `public_url`**. Un
client qui ne peut joindre que le proxy n'ira donc au bout que si ce nom le
mène au proxy.

## ✅ Vous avez réussi si

- `vlt cluster relais <nœud-proxy>` montre `nexus` **appliqué**, avec Nexus en
  cible ;
- `curl --connect-to … /healthz` répond à travers le proxy, et le **Suivi** de
  Nexus porte l'adresse du proxy ;
- après `rotation out`, le proxy annonce 0 Nexus joignable, et après
  `rotation in`, de nouveau 1.

## 🧪 Exercice

Le relais `nexus` est **appliqué**, mais sa colonne CIBLES reste `—` et le
journal du proxy dit `services du cluster : 0 vaultaire_nexus joignable(s)`.
Nexus répond pourtant très bien en direct. Trois causes possibles ?

<details><summary>Solution</summary>

1. Nexus n'est **pas en ligne** pour le cluster : arrêté, ou son identité
   (`<data_dir>/ducky`) a été perdue. `vlt cluster list` le montre `offline`.
2. Nexus est **hors rotation** (`ROT. out`) : `vlt cluster rotation <nœud-nexus> in`.
3. La demande du proxy (`04_15`) est refusée par le core : son journal porte
   une ligne `04_15 : …`.

Et si tout vient d'être corrigé, comptez jusqu'à **5 minutes** : c'est la
cadence à laquelle le proxy redemande la liste.
</details>

## 🧪 Exercice — fin de chapitre

Remettez le labo au propre : le relais fermé, le port dépublié, et plus aucune
dérogation de version dans le parc.

<details><summary>Solution</summary>

```bash
vlt cluster relais <nœud-proxy> remove nexus
# compose du proxy : retirer « 8853:8843 », puis docker compose up -d
vlt agent | grep dérogation           # rien
```

Le Nexus, lui, peut rester : c'est maintenant le dépôt du parc.
</details>

## 📚 Référence

[`proxy/https-et-ldaps.md`](../../proxy/https-et-ldaps.md) ·
[`proxy/pilotage.md`](../../proxy/pilotage.md) ·
[`proxy/depannage.md`](../../proxy/depannage.md) ·
[`Agent_configuration_et_debug.md`](../../exploitation/Agent_configuration_et_debug.md) § 4.1

---

[← Changer la version d'un agent par Nexus](./03-mettre-a-jour-un-agent.md) · [Fin de la formation ⌂](../README.md)
