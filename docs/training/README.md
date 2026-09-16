[⌂ Accueil du dépôt](../../README.md) · [Index de la documentation](../README.md)

# Formation Vaultaire

Apprendre Vaultaire **en le pratiquant**, chapitre par chapitre : installer un
serveur, construire l'annuaire d'une entreprise fictive, intégrer une machine,
lui appliquer des politiques, puis brancher DNS et LDAP.

10 chapitres, 30 jalons. Chaque jalon tient en 15 à 30 minutes.

---

## Comment l'utiliser

- Suivez les chapitres **dans l'ordre** : chacun s'appuie sur ce que les
  précédents ont créé.
- Chaque chapitre a son dossier et son sommaire ; chaque jalon a en tête un fil
  d'Ariane (**⌂ Formation › Chapitre › Jalon**) et des liens
  **précédent / suivant**.
- Un jalon se termine par **✅ Vous avez réussi si** : ne passez pas au suivant
  tant que ce n'est pas le cas.
- Les **🧪 exercices** ont leur solution repliée : cherchez d'abord avec
  `-h`.

## Le laboratoire

| Élément | Rôle | Chapitres |
|---|---|---|
| Hôte Docker (`<IP-serveur>`) | la pile Vaultaire : core, MariaDB, Keycloak | tous |
| VM Rocky Linux 9 `web01` (`<IP-web01>`) | la machine intégrée au domaine | 5, 6, 7 |
| Votre poste | navigateur, `vlt` à distance, `dig`, `ldapsearch` | 3, 7, 8 |

## Le fil rouge : Acme

Une entreprise fictive dont le domaine racine est `acme.lan`.

```
acme.lan
├── infra.acme.lan        Infra     alice.martin   administratrice système
├── dev.acme.lan          Dev       bob.durand     développeur
│   └── web.dev.acme.lan  Dev-Web
├── rh.acme.lan           RH        chloe.petit    ressources humaines
└── svc.acme.lan          Services  svc_keycloak   compte de service (chapitre 8)
```

## Conventions

- `vlt …` désigne la CLI d'administration. Sur l'hôte :

  ```bash
  alias vlt='docker exec -it vaultaire-ad /opt/vaultaire/bin/vaultaire_cli'
  ```

  À distance, c'est le binaire `vaultaire_ctl` installé sous le nom `vlt`
  (chapitre 3). Les commandes sont les mêmes.
- `<IP-serveur>`, `<IP-web01>`, `<computeur_id>` : à remplacer par vos valeurs.
- Les mots de passe des exemples sont des mots de passe **de labo**.

---

## Sommaire

| # | Chapitre | Jalons |
|---|---|---|
| 1 | [Installer le serveur](./01-installation-serveur/README.md) | 1.1 [Préparer l'hôte](./01-installation-serveur/01-preparer-l-hote.md)<br>1.2 [Démarrer la pile](./01-installation-serveur/02-demarrer-la-pile.md)<br>1.3 [Premier accès et sécurisation](./01-installation-serveur/03-premier-acces.md) |
| 2 | [Premiers groupes et utilisateurs](./02-groupes-et-utilisateurs/README.md) | 2.1 [Penser l'arborescence de domaines](./02-groupes-et-utilisateurs/01-arborescence-de-domaines.md)<br>2.2 [Créer groupes et comptes](./02-groupes-et-utilisateurs/02-creer-groupes-et-comptes.md)<br>2.3 [Rattacher, consulter, retirer](./02-groupes-et-utilisateurs/03-rattacher-et-consulter.md) |
| 3 | [Administrer Vaultaire via vlt](./03-administrer-avec-vlt/README.md) | 3.1 [La CLI locale](./03-administrer-avec-vlt/01-cli-locale.md)<br>3.2 [vlt à distance par l'API](./03-administrer-avec-vlt/02-vlt-a-distance.md)<br>3.3 [Le portail web](./03-administrer-avec-vlt/03-portail-web.md) |
| 4 | [Permissions et délégation](./04-permissions-et-delegation/README.md) | 4.1 [Une permission utilisateur](./04-permissions-et-delegation/01-permission-utilisateur.md)<br>4.2 [Déléguer un domaine](./04-permissions-et-delegation/02-deleguer-un-domaine.md)<br>4.3 [Droits sur les machines](./04-permissions-et-delegation/03-droits-sur-les-machines.md) |
| 5 | [Ajouter un client](./05-ajouter-un-client/README.md) | 5.1 [Préparer la machine](./05-ajouter-un-client/01-preparer-la-machine.md)<br>5.2 [Intégrer la machine](./05-ajouter-un-client/02-integrer-la-machine.md)<br>5.3 [Première connexion d'un utilisateur](./05-ajouter-un-client/03-premiere-connexion.md) |
| 6 | [Première GPO](./06-premiere-gpo/README.md) | 6.1 [Créer une GPO machine](./06-premiere-gpo/01-creer-une-gpo-machine.md)<br>6.2 [Lier et appliquer](./06-premiere-gpo/02-lier-et-appliquer.md)<br>6.3 [Dérive, audit, et GPO utilisateur](./06-premiere-gpo/03-derive-et-gpo-utilisateur.md) |
| 7 | [DNS](./07-dns/README.md) | 7.1 [Activer et exposer le DNS](./07-dns/01-activer-et-exposer.md)<br>7.2 [Zones et enregistrements](./07-dns/02-zones-et-enregistrements.md)<br>7.3 [Distribuer le résolveur au parc](./07-dns/03-distribuer-le-resolveur.md) |
| 8 | [LDAP et liaison d'applications](./08-ldap-et-liaison/README.md) | 8.1 [Un compte de service LDAP](./08-ldap-et-liaison/01-compte-de-service.md)<br>8.2 [Interroger l'annuaire](./08-ldap-et-liaison/02-interroger-l-annuaire.md)<br>8.3 [LDAPS et Keycloak](./08-ldap-et-liaison/03-ldaps-et-keycloak.md) |
| 9 | [Sécurité et exploitation](./09-securite-et-exploitation/README.md) | 9.1 [Second facteur et mots de passe](./09-securite-et-exploitation/01-mfa-et-mots-de-passe.md)<br>9.2 [Incident et journaux](./09-securite-et-exploitation/02-incident-et-journaux.md)<br>9.3 [Réglages et mises à jour](./09-securite-et-exploitation/03-reglages-et-mises-a-jour.md) |
| 10 | [Cluster et proxy](./10-cluster-et-proxy/README.md) | 10.1 [Clés d'enrôlement](./10-cluster-et-proxy/01-cles-d-enrolement.md)<br>10.2 [Déployer un proxy](./10-cluster-et-proxy/02-deployer-un-proxy.md)<br>10.3 [Topologie : exposition, affinité, rotation](./10-cluster-et-proxy/03-topologie.md) |

---

## Aller plus loin

| Sujet | Document |
|---|---|
| Toutes les commandes | [`MAN.md`](../Utilisation/MAN.md) |
| Quel droit pour quelle opération | [`Actions_et_Permissions.md`](../Utilisation/Actions_et_Permissions.md) |
| Vocabulaire | [`Lexique.md`](../Utilisation/Lexique.md) |
| Fonctionnement interne | [`how it work/`](../Developement/how%20it%20work/README.md) |
| Installation sans Docker | [`Setup.md`](../Installation/Setup.md) |

> Une commande ne se comporte pas comme décrit ici ? `vlt <commande> -h` fait
> foi. Signalez l'écart pour que la formation soit corrigée.

---

[⌂ Accueil du dépôt](../../README.md) · [Commencer : Chapitre 1 →](./01-installation-serveur/README.md)
