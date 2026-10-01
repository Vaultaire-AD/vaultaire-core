[⌂ Formation](../README.md) › [Chapitre 5 — Ajouter un client](./README.md) › Jalon 5.1

# Jalon 5.1 — Préparer la machine

[← Sommaire du chapitre](./README.md) · [Intégrer la machine →](./02-integrer-la-machine.md)

---

## Objectif

Rendre la machine cible installable à distance par le core.

## Ce qu'il faut savoir

L'intégration est **poussée par le core** : il se connecte en SSH à la machine
en `root`, avec **sa propre clé de déploiement**, y copie l'agent et les modules
PAM, puis exécute le script d'installation
`automatisation/auto_deployements/rocky.sh`.

Aujourd'hui, seul **Rocky Linux** dispose d'un script d'installation.

## Étapes

1. Sur `web01`, vérifiez que `sshd` tourne et que le serveur Vaultaire est
   joignable :

   ```bash
   systemctl is-active sshd
   curl -k -s -o /dev/null -w '%{http_code}\n' https://<IP-serveur>:4443/login
   timeout 3 bash -c '</dev/tcp/<IP-serveur>/6666' && echo "6666 joignable"
   ```

2. Récupérez la **clé de déploiement** du core : elle est affichée sur le
   tableau de bord du portail (`https://<IP-serveur>:4443/admin`), avec un
   script prêt à copier.

3. Sur `web01`, en root, autorisez cette clé :

   ```bash
   mkdir -p /root/.ssh
   echo 'ssh-rsa AAAA… (clé du tableau de bord)' >> /root/.ssh/authorized_keys
   chmod 700 /root/.ssh
   chmod 600 /root/.ssh/authorized_keys
   ```

4. Depuis le serveur, vérifiez que le core voit la machine :

   ```bash
   docker exec vaultaire-ad ssh-keyscan -p 22 <IP-web01>
   ```

## ✅ Vous avez réussi si

`ssh-keyscan` depuis le conteneur rend au moins une clé d'hôte.

## 🧪 Exercice

Le `sshd` de `web01` écoute sur le port **2222**. Comment l'indiquerez-vous au
jalon suivant ?

<details><summary>Solution</summary>

Dans la cible de `-join` : `<IP-web01>:2222`. Une adresse IPv6 avec port
s'écrit entre crochets : `[2001:db8::10]:2222`.
</details>

---

[← Sommaire du chapitre](./README.md) · [Intégrer la machine →](./02-integrer-la-machine.md)
