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

| Fichier | Contenu |
| --- | --- |
| [`Utilisation/MAN.md`](./Utilisation/MAN.md) | Manuel des commandes `vlt` : create, get, add, remove, delete, update, status, clear, eyes, DNS |
| [`Utilisation/vaultairectl.md`](./Utilisation/vaultairectl.md) | `vaultaire_ctl` — administration distante via l'API REST signée |
| [`Utilisation/Group-Permission.md`](./Utilisation/Group-Permission.md) | Gestion des groupes et des permissions au quotidien |
| [`Utilisation/vaultaireLDAP.md`](./Utilisation/vaultaireLDAP.md) | Module LDAP : arborescence, filtres, intégrations |

---

## 🔒 Sécurité

| Fichier | Contenu |
| --- | --- |
| [`Securite/SECURITY.md`](./Securite/SECURITY.md) | Politique de sécurité et signalement des vulnérabilités |
| [`Developement/Audit_Permissions.md`](./Developement/Audit_Permissions.md) | Audit du système de permissions sur les quatre points d'entrée (Ducky, LDAP, CLI, web) |

---

## 🧪 Développement

| Fichier | Contenu |
| --- | --- |
| [`Developement/Tableau_Protocole_Réseau.md`](./Developement/Tableau_Protocole_Réseau.md) | Référence du protocole Ducky Network : toutes les trames `MM_SS` |
| [`Developement/Permissions.md`](./Developement/Permissions.md) | Modèle de permissions : domaines, portées, héritage |
| [`Developement/Actions_et_Permissions.md`](./Developement/Actions_et_Permissions.md) | Catalogue des actions et des droits requis |
| [`Developement/GPO.md`](./Developement/GPO.md) | Modèle déclaratif des GPO, catalogue des modules, restrictions |
| [`Developement/DataBase_Struct.md`](./Developement/DataBase_Struct.md) | Schéma de la base de données |
| [`Developement/MFA_et_Expiration.md`](./Developement/MFA_et_Expiration.md) | Authentification multifacteur et expiration des mots de passe |
| [`Developement/WebUI_Picker.md`](./Developement/WebUI_Picker.md) | Sélecteur d'entités du portail web : recherche, filtres, sélection multiple |
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

## 🕰️ Historique

[`Version_History.md`](./Version_History.md) — versions, correctifs et changements
de protocole, de l'Alpha 1.0 à l'Alpha 2.0.0 « PIG ».

---

## 🗄️ Archives

[`legacy/`](./legacy/) — documentation antérieure, conservée pour référence
(`Documentation_Technique_vaultaire.odt`, schéma d'infrastructure).

---

## 📬 Contact

**contact@vaultaire.fr**
