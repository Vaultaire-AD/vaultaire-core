# 📚 Documentation Vaultaire

Index de la documentation technique du projet **Vaultaire**.
Pour la structure du dépôt et la compilation, voir le [README racine](../README.md).

---

## 🎓 Formation

| Fichier | Contenu |
| --- | --- |
| [`training/README.md`](./training/README.md) | **Apprendre Vaultaire pas à pas** : 10 chapitres, 30 jalons avec exercices — installation, annuaire, `vlt`, permissions, clients, GPO, DNS, LDAP, sécurité, cluster |

---

## 🛠 Installation

| Fichier | Contenu |
| --- | --- |
| [`Installation/Requirements.md`](./Installation/Requirements.md) | Prérequis système, versions, dépendances |
| [`Installation/Setup.md`](./Installation/Setup.md) | Installation complète : base de données, service systemd, configuration YAML, poste client |
| [`Installation/Docker_Kubernetes.md`](./Installation/Docker_Kubernetes.md) | Déploiement conteneurisé |
| [`Installation/Client_Windows.md`](./Installation/Client_Windows.md) | **Poste Windows (V1)** : identité de la machine, service, tuile de l'écran de connexion, compte local |

---

## 📚 Utilisation

Documentation destinée à qui **exploite** Vaultaire : administrateurs, délégués,
intégrateurs. Elle répond à « que taper » et « quel droit accorder », jamais à
« comment c'est écrit ».

| Fichier | Contenu |
| --- | --- |
| [`Utilisation/Lexique.md`](./Utilisation/Lexique.md) | **Le vocabulaire** : client, agent, service, core, proxy, domaine, portée, trame, GPO… |
| [`Utilisation/MAN.md`](./Utilisation/MAN.md) | Manuel des commandes `vlt` : create, get, add, remove, delete, update, status, clear, eyes, DNS, certificate, kill, mfa, enroll, gpo, cluster |
| [`Utilisation/Group-Permission.md`](./Utilisation/Group-Permission.md) | Groupes et permissions au quotidien : ce que donne un droit sur un domaine |
| [`Utilisation/Actions_et_Permissions.md`](./Utilisation/Actions_et_Permissions.md) | **Quel droit pour quelle opération** — la référence à consulter avant de déléguer |
| [`Utilisation/vaultairectl.md`](./Utilisation/vaultairectl.md) | `vaultaire_ctl` — administration distante via l'API REST signée |
| [`Utilisation/vaultaireLDAP.md`](./Utilisation/vaultaireLDAP.md) | Module LDAP : arborescence, filtres, intégrations |
| [`Utilisation/DNS.md`](./Utilisation/DNS.md) | Commandes DNS : zones, enregistrements, PTR |

---

## 🔀 Proxy

| Fichier | Contenu |
| --- | --- |
| [`proxy/README.md`](./proxy/README.md) | **Le proxy** : déploiement, relais (Ducky, HTTPS vers les Nexus, LDAPS ; LDAP en clair refusé), sécurité, dépannage |

---

## 🔒 Sécurité

| Fichier | Contenu |
| --- | --- |
| [`Securite/SECURITY.md`](./Securite/SECURITY.md) | Politique de sécurité et signalement des vulnérabilités |

---

## 🧪 Développement

### `Developement/how it work/` — comment les modules fonctionnent

Documentation **interne**, destinée à qui modifie le code. Chaque fichier répond
à « comment ce module marche, et comment y toucher sans rien casser ».

| Fichier | Contenu |
| --- | --- |
| [`README.md`](./Developement/how%20it%20work/README.md) | **Point d'entrée pour un agent IA ou un nouveau développeur** : quel module, quel chemin, quelle page — et les pièges avant d'écrire |
| [`Actions.md`](./Developement/how%20it%20work/Actions.md) | Le registre `core/action` : chemin d'une requête, portées, filtrage, **comment ajouter une action** |
| [`Permissions_RBAC.md`](./Developement/how%20it%20work/Permissions_RBAC.md) | Modèle RBAC : clés, domaines, les trois portées, matrice d'administration |
| [`Reglages_de_duree.md`](./Developement/how%20it%20work/Reglages_de_duree.md) | Comment une période de boucle est déclarée, lue et changée |
| [`ducky-network/`](./Developement/how%20it%20work/ducky-network/README.md) | **Référence du protocole Ducky Network**, un chapitre par catégorie de trames (01 à 08) |
| [`Nouveau_service.md`](./Developement/how%20it%20work/Nouveau_service.md) | **Créer un nouveau service** : module, catalogue, raccordement, authentification, droits, build, déploiement |
| [`Versions.md`](./Developement/how%20it%20work/Versions.md) | Comment chaque composant déclare sa version, et ce que le core en fait |
| [`GPO.md`](./Developement/how%20it%20work/GPO.md) | Modèle déclaratif des GPO, catalogue des modules, restrictions, **ajouter un module** |
| [`Base_de_donnees.md`](./Developement/how%20it%20work/Base_de_donnees.md) | Schéma de la base de données |
| [`MFA_et_Expiration.md`](./Developement/how%20it%20work/MFA_et_Expiration.md) | Second facteur et expiration des mots de passe |
| [`Journalisation.md`](./Developement/how%20it%20work/Journalisation.md) | Ce que le serveur journalise, à quel niveau, et pourquoi |
| [`Tests.md`](./Developement/how%20it%20work/Tests.md) | **Les tests** : comment les lancer, les deux familles, les tests-sentinelles, la suite `--test` |
| [`Dependances.md`](./Developement/how%20it%20work/Dependances.md) | **De quoi Vaultaire dépend** : l'inventaire, à quoi chaque dépendance sert, et les divergences de version |
| [`Pense-bete_developpement.md`](./Developement/how%20it%20work/Pense-bete_developpement.md) | **Les étapes à suivre** quand on ajoute une fonctionnalité — de l'entrée TO-DO au commit |

> **Ce qui n'a pas sa place ici** : « comment déléguer un droit », « quelle
> commande taper ». Cela relève de [`Utilisation/`](./Utilisation/). La règle est
> le LECTEUR, pas le sujet : le même sujet peut avoir une page dans chaque
> dossier, l'une expliquant le mécanisme, l'autre l'usage.

| | |
| --- | --- |
| [`../CONTRIBUTING.MD`](../CONTRIBUTING.MD) | Comment contribuer (à la racine du dépôt) |

### Suivi des travaux

| Fichier | Contenu |
| --- | --- |
| [`Developement/TO-DO.md`](./Developement/TO-DO.md) | Tâches ouvertes |
| [`Developement/DO/`](./Developement/DO/) | Tâches terminées, classées par version (`2.0/`, `2.1/`) |

> Une tâche validée est déplacée **à la main** de `TO-DO.md` vers
> `DO/<version>/`, puis reportée dans [`Version_History.md`](./Version_History.md).

---

## 🚨 Exploitation

| Fichier | Contenu |
| --- | --- |
| [`../src/vaultaire_nexus/README.md`](../src/vaultaire_nexus/README.md) | Nexus, le dépôt de paquets du parc : installation, dépôts RPM/Debian/Docker, releases, droits |
| [`exploitation/Releases.md`](./exploitation/Releases.md) | Releases automatiques, numérotation, rétention, mise à jour de la préprod, purge de l'historique |
| [`exploitation/Agent_configuration_et_debug.md`](./exploitation/Agent_configuration_et_debug.md) | Agent : liste des cores (installation, apprise, persistée) et rapport de debug `vlt_client-Debug.log` |
| [`exploitation/Changement_de_version.md`](./exploitation/Changement_de_version.md) | Passer à la série suivante (2.1 → 2.2) : fichiers à modifier, documentation à clore et à ouvrir |
| [`exploitation/selinux.md`](./exploitation/selinux.md) | Politique SELinux pour les clients — diagnostic des refus sous `sshd_t` |
| [`exploitation/ldaps_keycloak.md`](./exploitation/ldaps_keycloak.md) | LDAPS et intégration Keycloak : SAN, magasin de confiance, messages d'erreur |

---

## 🔀 Migrations

| Fichier | Contenu |
| --- | --- |
| [`migrations/clienttype_catalogue.md`](./migrations/clienttype_catalogue.md) | Bascule vers le catalogue des types de client |

---

## 🕰️ Versions

[`Version_History.md`](./Version_History.md) est l'**index**. Le détail vit dans
[`Version/`](./Version/), un dossier par version majeure et un fichier par
version mineure, **du plus récent au plus ancien**.

| Fichier | Contenu |
| --- | --- |
| [`Version/2.0/2.2.md`](./Version/2.0/2.2.md) | Cycle 2.2 — en cours, travaux non publiés |
| [`Version/2.0/2.1.md`](./Version/2.0/2.1.md) | Alpha 2.1.0 — refactorisation, releases automatiques |
| [`Version/2.0/2.0.md`](./Version/2.0/2.0.md) | Alpha 2.0.0 « PIG » — les deux audits de sécurité |
| [`Version/1.0/1.1.md`](./Version/1.0/1.1.md) | Cycle 1.1 — GPO, LDAP puis LDAPS, portail web, API |
| [`Version/1.0/1.0.md`](./Version/1.0/1.0.md) | Cycle 1.0 « ROCKET » — premières versions |

---

## 🗄️ Archives

[`legacy/`](./legacy/) — documentation antérieure, conservée pour référence
(`Documentation_Technique_vaultaire.odt`, schéma d'infrastructure).

---

## 📬 Contact

**contact@vaultaire.fr**
