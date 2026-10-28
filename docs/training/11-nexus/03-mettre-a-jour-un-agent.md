[⌂ Formation](../README.md) › [Chapitre 11 — Nexus](./README.md) › Jalon 11.3

# Jalon 11.3 — Changer la version d'un agent par Nexus

[← Les dépôts : créer, publier, consommer](./02-depots.md) · [Exposer Nexus par un proxy →](./04-exposer-par-un-proxy.md)

---

## Objectif

Verser deux versions du paquet d'agent dans le dépôt du parc, ramener `web01`
à la plus **ancienne**, puis la remettre à la **courante**, en lisant chaque
étape dans le journal de l'agent et dans `vlt agent`.

## Ce qu'il faut savoir

Le chemin d'une mise à jour :

```
core : vlt agent pin / target  ──ordre (09_02 / 09_06)──►  agent de web01
                                                             │ étalement (≤ 2 min)
Nexus : /repo/vaultaire/releases/download/v<W>/  ◄──https───┤ archive + manifeste + signature
                                                             │ vérifie : signature du CLUSTER, empreintes, modules, --check
                                                             ▼
                                         vaultaire-update : bascule, porte de santé (≈ 30 s)
                                                             │ réussite → compte rendu « installe »
                                                             │ échec    → retour à l'ancienne version, « echec »
core : vlt agent  ◄──compte rendu (09_04)────────────────────┘
```

- **Qui signe ?** Votre core, avec sa clé des paquets. La release GitHub ne
  porte qu'un manifeste **non signé** : un paquet que votre cluster n'a pas
  signé est refusé.
- **Où l'agent lit-il ?** Dans les Nexus **en ligne et exposés** du cluster
  (`public_url`), que le core lui annonce à chaque connexion, ou dans
  `update_repository` s'il est réglé dans son `client_conf.json`.
- **TLS est toujours vérifié**, et `http://` est refusé. Les autorités de
  confiance sont celles du système, plus le fichier `update_tls_ca`.
- **Jamais de rétrogradation d'office.** Une machine plus récente que sa cible
  est « en avance » et n'est pas touchée. Il faut `--downgrade`.
- Un dépôt **injoignable** est un échec **passager** : pas de compte rendu, le
  core redonne l'ordre à la reconnexion suivante. L'erreur ne se lit donc **que
  sur la machine**.

Notez dans la suite `<V>` la version de vos agents (celle de la pile), `<W>` une
version plus ancienne publiée sur GitHub (par exemple la précédente du même
patch), et `<id-web01>` le computeur ID de `web01`.

## Étapes

1. **L'état de départ** :

   ```bash
   vlt agent
   ```

   `web01` déclare `<V>`. Lisez aussi les lignes **Dépôt** (`releases` par
   défaut, `vlt agent depot` le change) et **Clés des paquets**.

2. **La clé qui signe** : la même des deux côtés.

   ```bash
   docker exec vaultaire-ad /opt/vaultaire/bin/vaultaire_serveur --pkg-key show
   sudo cat /etc/vaultaire_client/.ssh/pkg_signing_key.pem      # sur web01
   ```

3. **Les archives** : récupérez les deux versions sur l'hôte Docker, puis
   copiez-les dans le core.

   ```bash
   for v in <W> <V>; do
     curl -fsSLO https://github.com/Vaultaire-AD/vaultaire-core/releases/download/v$v/vaultaire_client-v$v-linux-amd64.tar.gz
     docker cp vaultaire_client-v$v-linux-amd64.tar.gz vaultaire-ad:/tmp/
   done
   ```

   > Parc sans Internet ? Importez la release dans Nexus (bouton **Importer
   > depuis GitHub** du dépôt `releases`, tag **avec** son `v`), puis prenez
   > l'archive depuis Nexus.

4. **Le certificat de Nexus**, pour que le core le vérifie en versant :

   ```bash
   cd src/vaultaire_nexus/deploy
   docker compose exec nexus cat /var/lib/vaultaire_nexus/tls/nexus.crt > /tmp/nexus-ca.pem
   docker cp /tmp/nexus-ca.pem vaultaire-ad:/tmp/nexus-ca.pem
   ```

5. **Signer et verser**, en un geste, avec le jeton `publisher` du jalon 11.2 :

   ```bash
   read -rs VAULTAIRE_NEXUS_TOKEN && export VAULTAIRE_NEXUS_TOKEN
   for v in <W> <V>; do
     docker exec -e VAULTAIRE_NEXUS_TOKEN vaultaire-ad /opt/vaultaire/bin/vaultaire_serveur \
         --publish-package /tmp/vaultaire_client-v$v-linux-amd64.tar.gz --ca /tmp/nexus-ca.pem
   done
   unset VAULTAIRE_NEXUS_TOKEN
   ```

   Pour chaque version, cinq fichiers versés (l'archive, un manifeste et sa
   signature par famille, Rocky et Debian), relus **sans jeton** comme le fera
   l'agent, puis `Bilan : 1/1 Nexus à jour.` Relancez : tout est « déjà en
   place ».

6. **La confiance TLS sur `web01`.** Si vous avez fait approuver le certificat de
   Nexus par le système au jalon 11.2 (`update-ca-trust`), c'est fait. Sinon,
   donnez-le à l'agent seul :

   ```bash
   sudo curl -fsSko /etc/vaultaire_client/nexus-ca.pem https://<IP-serveur>:8843/repo/keys/nexus.crt
   # dans /etc/vaultaire_client/client_conf.json :
   #   "update_tls_ca": "/etc/vaultaire_client/nexus-ca.pem"
   sudo restorecon -v /etc/vaultaire_client/nexus-ca.pem     # SELinux
   sudo systemctl restart vaultaire_client
   ```

7. **Ouvrez le suivi** sur `web01`, dans un second terminal :

   ```bash
   sudo tail -f /var/log/vaultaire/vaultaire_client.log | grep --line-buffered -E 'mise à jour|configuration système'
   ```

   Au démarrage de l'agent : `mise à jour : dépôt(s) https://<IP-serveur>:8843 (cluster)`.

8. **Ramenez `web01` à `<W>`**, d'abord sans `--downgrade` :

   ```bash
   vlt agent pin <id-web01> <W>
   vlt agent
   ```

   Dérogation posée, état **en avance**… et rien ne part : une machine plus
   récente n'est jamais rétrogradée sans le demander. Demandez-le :

   ```bash
   vlt agent pin <id-web01> <W> --downgrade
   ```

   Dans le suivi, en deux minutes au plus :

   ```
   mise à jour : ordre reçu — <W> depuis le dépôt releases (rétrogradation demandée)
   [SECURITY] mise à jour : rétrogradation demandée par le core, de <V> vers <W>
   mise à jour : <W> dans 40s (étalement)
   mise à jour : <W> vérifiée (signature, empreintes, modules, --check) — bascule
   mise à jour : <W> en place — porte de santé franchie en 30s
   mise à jour : compte rendu envoyé au core
   ```

   La bascule elle-même se suit aussi dans `journalctl -u vaultaire-update`.

9. **Lisez le résultat côté core** :

   ```bash
   vlt agent
   ```

   `web01` : déclarée `<W>`, attendue `<W> (dérogation)`, **à jour**, dernier
   compte rendu « `<W>` installe : porte de santé franchie en 30s ». Même chose
   sur le portail, **Admin → Clients**, colonne **Version**.

10. **Remettez-la à `<V>`**, puis rendez-la au parc :

    ```bash
    vlt agent pin <id-web01> <V>          # une montée : pas besoin de --downgrade
    vlt agent                             # attendre « <V> installe »
    vlt agent pin <id-web01> none
    ```

    Sans dérogation, `web01` suit la cible de ses groupes ou du parc. S'il n'y
    en a pas, elle est « sans cible » et ne bouge plus.

## ✅ Vous avez réussi si

- `vlt agent` a montré « `<W>` installe », puis « `<V>` installe » ;
- le journal de `web01` porte les deux lignes « porte de santé franchie » ;
- `web01` n'a plus de dérogation, et une connexion SSH d'`alice.martin` passe
  toujours.

## 🧪 Exercice

Sur une machine fraîchement intégrée, la rétrogradation ne se fait pas.
`vlt agent` ne montre **aucun** compte rendu, et le journal de la machine dit :

```
mise à jour : transitoire : téléchargement impossible — https://<IP-serveur>:8843 : Get "…": tls: failed to verify certificate: x509: certificate signed by unknown authority — l'ordre sera redonné
```

Pourquoi rien côté core, et que faire ?

<details><summary>Solution</summary>

Un dépôt injoignable est **passager** : l'agent n'envoie pas de compte rendu, le
core redonnera l'ordre. L'erreur ne se voit donc que sur la machine.

La cause : le certificat auto-signé de Nexus n'est connu ni du système de la
machine, ni de son `update_tls_ca`. Le core n'écrit **jamais** ce réglage, et
l'intégration (`-join`) ne le pose pas non plus. Refaites l'étape 6 sur cette
machine, puis `systemctl restart vaultaire_client` : au démarrage, l'agent
redemande l'ordre et le joue dans la minute.

Avec un certificat signé par l'AC du site, déjà approuvée par les machines,
rien de tout cela n'est nécessaire.
</details>

## 🧪 Exercice

Pendant une montée, la nouvelle version ne tient pas : le service s'arrête au
bout de dix secondes. Que se passe-t-il sur la machine, et comment relancer
une fois le défaut corrigé ?

<details><summary>Solution</summary>

La **porte de santé** exige que le service tienne 30 s et que le socket PAM
réponde, tunnel établi. Faute de quoi `vaultaire-update` remet **seul**
l'ancienne version, et le compte rendu est `echec`, avec le motif.

Une machine en échec n'est pas relancée à chaque connexion : elle retenterait
sans fin un basculement qui casse. Une fois le paquet corrigé et reversé :

```bash
vlt agent update <id>
```

C'est le même geste que le bouton **Relancer** d'**Admin → Clients**.
</details>

## 📚 Référence

[`Releases.md`](../../exploitation/Releases.md) « Signer le paquet d'agent »
et « Le dépôt du parc » ·
[`Agent_configuration_et_debug.md`](../../exploitation/Agent_configuration_et_debug.md) § 4 ·
[`Mise_a_jour_du_parc.md`](../../Developement/Mise_a_jour_du_parc.md) ·
[`MAN.md`](../../Utilisation/MAN.md), commande `agent`

---

[← Les dépôts : créer, publier, consommer](./02-depots.md) · [Exposer Nexus par un proxy →](./04-exposer-par-un-proxy.md)
