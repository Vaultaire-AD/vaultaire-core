# 📚 Documentation Vaultaire

Index de la documentation technique du projet **Vaultaire**.
Pour la structure du dépôt et la compilation, voir le [README racine](../README.md).

---

## 🛠 Installation

| Fichier | Contenu |
| --- | --- |
| [`Installation/Requirements.md`](./Installation/Requirements.md) | Prérequis système, versions, dépendances |
| [`Installation/Setup.md`](./Installation/Setup.md) | Installation complète : base de données, service systemd, configuration YAML, poste client |
| [`Installation/Docker_Kubernetes.md`](./Installation/Docker_Kubernetes.md) | Déploiement conteneurisé |

---

## 📚 Utilisation

Documentation destinée à qui **exploite** Vaultaire : administrateurs, délégués,
intégrateurs. Elle répond à « que taper » et « quel droit accorder », jamais à
« comment c'est écrit ».

| Fichier | Contenu |
| --- | --- |
| [`Utilisation/MAN.md`](./Utilisation/MAN.md) | Manuel des commandes `vlt` : create, get, add, remove, delete, update, status, clear, eyes, DNS, certificate, kill, mfa, enroll, gpo, cluster |
| [`Utilisation/Group-Permission.md`](./Utilisation/Group-Permission.md) | Groupes et permissions au quotidien : ce que donne un droit sur un domaine |
| [`Utilisation/Actions_et_Permissions.md`](./Utilisation/Actions_et_Permissions.md) | **Quel droit pour quelle opération** — la référence à consulter avant de déléguer |
| [`Utilisation/vaultairectl.md`](./Utilisation/vaultairectl.md) | `vaultaire_ctl` — administration distante via l'API REST signée |
| [`Utilisation/vaultaireLDAP.md`](./Utilisation/vaultaireLDAP.md) | Module LDAP : arborescence, filtres, intégrations |

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
| [`Actions.md`](./Developement/how%20it%20work/Actions.md) | Le registre `core/action` : chemin d'une requête, portées, filtrage, **comment ajouter une action** |
| [`Permissions_RBAC.md`](./Developement/how%20it%20work/Permissions_RBAC.md) | Modèle RBAC : clés, domaines, les trois portées, matrice d'administration |
| [`Protocole_Ducky.md`](./Developement/how%20it%20work/Protocole_Ducky.md) | Référence du protocole Ducky Network : toutes les trames `MM_SS` |
| [`GPO.md`](./Developement/how%20it%20work/GPO.md) | Modèle déclaratif des GPO, catalogue des modules, restrictions, **ajouter un module** |
| [`Base_de_donnees.md`](./Developement/how%20it%20work/Base_de_donnees.md) | Schéma de la base de données |
| [`MFA_et_Expiration.md`](./Developement/how%20it%20work/MFA_et_Expiration.md) | Second facteur et expiration des mots de passe |
| [`Journalisation.md`](./Developement/how%20it%20work/Journalisation.md) | Ce que le serveur journalise, à quel niveau, et pourquoi |

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
| [`Version/2.0/2.1.md`](./Version/2.0/2.1.md) | Cycle 2.1 — refactorisation, et travaux non publiés |
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
