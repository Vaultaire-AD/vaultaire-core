[⌂ Ducky Network](../README.md) › [Chapitre 5 — Transport des GPO (05)](./README.md) › 5.3

# 5.3 — Charge utile, état local, application en scope user

[← Les trames 05_01 à 05_18](./02-trames.md) · [Chapitre 6 — Révocation — kill switch (06) →](../06-revocation/README.md)

---


Les fragments réassemblés forment un document JSON canonique, celui déjà produit
par `gpo.CanonicalJSON` :

```json
{
  "name": "effective_machine",
  "scope": "machine",
  "version": 7,
  "fingerprint": "752bf78712f8…",
  "modules": [
    { "type": "sysctl", "scope": "machine", "apply_order": 11,
      "params": { "key": "net.ipv4.ip_forward", "value": "0" },
      "state_key": "sysctl:net.ipv4.ip_forward",
      "fingerprint": "f3dad3533bb3…" },

    { "type": "sudoers_rule", "scope": "machine", "apply_order": 12,
      "params": { "group": "ops", "command_set": "nginx_restart", "nopasswd": "false" },
      "state_key": "sudoers_rule:ops",
      "fingerprint": "a91c0e4471bd…",
      "drift_mode": "audit",
      "definitions": {
        "command_set": {
          "name": "nginx_restart",
          "kind": "command_list",
          "payload": "/usr/bin/systemctl restart nginx\n/usr/bin/systemctl status nginx"
        }
      } }
  ]
}
```

Quatre champs méritent d'être détaillés, parce qu'ils portent des garanties :

- **`state_key`** et **`fingerprint`** par module sont calculés par le serveur et
  transmis, jamais recalculés par l'agent. Le client est un module Go séparé :
  deux implémentations du même hachage finiraient par diverger, et une machine se
  croirait à jour sans l'être.

- **`definitions`** porte le CONTENU des valeurs nommées référencées par les
  paramètres. Un module `sudoers_rule` ne transmet pas seulement le nom du jeu de
  commandes mais sa liste réelle : sans cela, créer un jeu custom depuis
  l'interface n'aurait aucun effet sur le parc, puisque l'agent ne saurait pas ce
  que ce nom recouvre.

  Conséquence sur les empreintes : le contenu des définitions **entre dans le
  calcul** de l'empreinte du module et de celle de la politique. Modifier la liste
  de commandes d'un jeu ne change aucun paramètre de module, mais change bel et
  bien ce qui sera appliqué — sans cela le serveur répondrait « rien à faire » et
  le parc conserverait indéfiniment l'ancienne règle.

- **`drift_mode`** dit ce que l'agent doit faire d'un écart constaté sur CE
  module : `enforce` le fait réappliquer au cycle suivant, `audit` se contente de
  le signaler. Il est hérité de la GPO qui porte le module, côté serveur.

  Le champ est **absent quand il vaut `enforce`**, et l'agent applique alors ce
  défaut de lui-même. Ce n'est pas de l'économie de place : le mode entre dans
  l'empreinte de POLITIQUE — sans quoi un passage en audit n'atteindrait jamais
  un parc dont la politique ne change pas par ailleurs, le serveur répondant
  `05_03`. L'écrire systématiquement changerait donc l'empreinte de toutes les
  GPO existantes, et le parc entier retéléchargerait sa politique le jour de la
  mise à jour.

  Il n'entre en revanche **pas** dans l'empreinte du MODULE : changer le mode ne
  change pas ce qu'il faut poser sur la machine. L'agent retélécharge le document
  et trouve tous ses modules `unchanged` — aucun service relancé, aucun paquet
  réinstallé. Détail dans [GPO.md](../../GPO.md), section « Le mode de dérive ».

Les modules sont triés par ordre d'application et les clés de paramètres sont
ordonnées : le document est reproductible, et son empreinte stable d'un envoi à
l'autre. C'est ce qui rend la comparaison d'empreintes fiable.

**Signature.** Le document n'est pas encore signé. Le tunnel Ducky est déjà
authentifié et chiffré, ce qui couvre l'écoute et la modification en transit, mais
pas un serveur central compromis. La signature fera l'objet d'une entrée de TO-DO
séparée ; le champ est prévu dans le format pour ne pas avoir à changer les trames.

## État local du client

Fichier `/var/lib/vaultaire/applied_policies.json`, en `0600 root:root` — chemin
déjà refusé à toutes les GPO par les règles de restriction, précisément pour qu'une
GPO ne puisse pas réécrire l'état qui décide de son application.

```json
{
  "machine": {
    "fingerprint": "a1b2…",
    "version": 7,
    "applied_at": "2026-07-30T14:22:03Z",
    "modules": { "sysctl:net.ipv4.ip_forward": "e3f4…" },
    "modes":   { "sudoers_rule:ops": "audit" }
  },
  "users": {
    "alice": { "fingerprint": "c5d6…", "version": 3, "applied_at": "…", "modules": {} }
  }
}
```

L'empreinte **par module** est ce qui permet de ne réappliquer que ce qui a changé :
à empreinte globale différente, le client compare module par module et laisse
tranquille ceux dont les paramètres sont identiques. Réappliquer l'ensemble à chaque
changement serait plus simple, mais relancerait des services et réinstallerait des
paquets sans raison.

`modes` ne porte que les modules qui s'écartent du mode par défaut. Une clé
absente — comme la totalité d'un état écrit par un agent antérieur — vaut
`enforce`. Le scan de conformité tourne avant le cycle et sans avoir parlé au
serveur : sans cette mémoire, une machine coupée du core se rabattrait sur
enforce et corrigerait des écarts délibérément tolérés sur un poste en audit.

## Moment d'application en scope user

L'ordre demandé est : utilisateur local créé et validé → **GPO user appliquées** →
droit de connexion accordé. Le point d'insertion est donc le traitement de `03_02`
côté client, après `ProvisionVaultaireUser` et avant la remise du résultat au
module PAM.

Ce choix rend la connexion dépendante de l'application des GPO. C'est acceptable
ici parce qu'aucun module de scope user n'est lent : environnement, timers
utilisateur et fichiers sous le home. Les modules lents (installation de paquets,
redémarrage de services) sont tous machine-only, donc appliqués au démarrage.

**À l'expiration du délai ou en cas d'échec d'un module, la connexion est
accordée** et l'incident part en `WARNING` + `SECURITY`, avec un rapport `05_12` de
statut `partial` ou `failed`. Aucun module de scope user ne touche aux privilèges :
une variable d'environnement non posée ne crée pas de faille, alors qu'un annuaire
qui bloque les connexions sur incident GPO est un incident d'exploitation majeur.

---

[← Les trames 05_01 à 05_18](./02-trames.md) · [Chapitre 6 — Révocation — kill switch (06) →](../06-revocation/README.md)
