# 📚 Documentation Vaultaire

Bienvenue dans la documentation officielle du projet **Vaultaire**.  
Ce dossier contient toutes les informations nécessaires pour comprendre, installer, configurer, utiliser et contribuer au projet.

---

## 📂 Arborescence de la documentation

```perl
docs/
│
├── 📖 Introduction/
│   ├── Overview.md              # Présentation générale du projet
│   ├── Features.md               # Liste des fonctionnalités actuelles et prévues
│   └── Roadmap.md                # Déplacé depuis roadmap.md
│
├── 🛠 Installation/
│   ├── Requirements.md           # Prérequis système, versions, dépendances
│   ├── Setup.md                  # Installation de base (déplacé depuis Setup.md)
│   ├── Docker_Kubernetes.md      # Installation avec Docker/K8s
│   └── Upgrade_Guide.md          # Mise à jour vers une nouvelle version
│
├── 📚 Utilisation/
│   ├── MAN.md                    # Guide d’utilisation (manuel)
│   ├── vaultaireLDAP.md          # Documentation LDAP
│   ├── Group-Permission.md       # Gestion des groupes et permissions
│   └── Troubleshooting.md        # Résolution des problèmes courants
│
├── 🔒 Sécurité/
│   ├── SECURITY.md               # Déplacé
│   └── Security_Best_Practices.md # Bonnes pratiques pour le déploiement
│
├── 🧪 Développement/
│   ├── CONTRIBUTING.md           # Comment contribuer
|   ├── Tableau_Protocole_Reseau.md
│   ├── Code_Style_Guidelines.md  # Règles de code Go/C/PAM
│   ├── write-test.md             # Déplacé ici
│   └── bug.md                    # Déplacé ici, renommé en Bug_Reports.md
│
└── README.md                     # Présentation synthétique

```

---

## 📖 Contenu

### 1. Introduction
Présentation du projet Vaultaire, ses objectifs, ses technologies et son état actuel.

### 2. Installation
Voir [Setup.md](./Setup.md) pour les instructions détaillées d’installation et de configuration.

### 3. Utilisation
- Gestion des utilisateurs et groupes : [Group-Permission.md](./Group-Permission.md)  
- Manuel utilisateur : [MAN.md](./MAN.md)  
- Module LDAP : [vaultaireLDAP.md](./vaultaireLDAP.md)

### 4. Sécurité
Guide des bonnes pratiques et politique de sécurité : [SECURITY.md](./SECURITY.md)

### 5. Développement
- Écriture de tests : [write-test.md](./write-test.md)  
- Signalement de bugs : [bug.md](./bug.md)  
- Roadmap : [roadmap.md](./roadmap.md)

### 6. Historique
- Historique des versions : [Version_History.md](./Version_History.md)  
- Protocoles réseau : [Tableau_Protocole_Réseau.md](./Tableau_Protocole_Réseau.md)

---

## 📬 Contact

Pour toute question ou contribution : **contact@vaultaire.fr**

---

## 💡 Astuce

Si vous cherchez la documentation technique détaillée des API, reportez-vous au dossier `/api-docs` (si disponible) ou aux commentaires dans le code source.
