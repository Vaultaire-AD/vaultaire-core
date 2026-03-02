# Vaultaire Core – Dépôt Développement / Préprod / Prod

Ce dépôt contient **le code source, les configurations et les outils de déploiement** de Vaultaire pour les environnements de développement, préproduction et production.  
Il est destiné **aux développeurs, testeurs et partenaires techniques** connaissant déjà la solution.

---

## 📂 Structure du dépôt

```plaintext
vaultaire-core/
│
├── cmd/                      # Binaries compilés du serveur et du client
│   ├── vaultaire_server/      # Serveur principal Vaultaire
│   └── vaultaire_client/      # CLI / client Vaultaire
│
├── src/                  # Code source Go principal
│   ├── vaultaire_cli/        # Application CLI
│   ├── vaultaire_client/     # Client réseau
│   └── vaultaire_serveur/    # Serveur principal
│
├── web/                      # Interface web
│   ├── templates/             # Templates HTML
│   └── static/                # Fichiers statiques (CSS, JS, images)
│
├── deployments/              # Fichiers de déploiement
│   ├── docker-compose.yml
│   ├── dockerfile
│   ├── dockerfile_debian
│   └── config/                # Configs YAML, JSON...
│
├── docs/                     # Documentation technique interne
│   ├── Group-Permission.md
│   ├── SECURITY.md
│   ├── Setup.md
│   ├── Tableau_Protocole_Réseau.md
│   ├── Version_History.md
│   ├── bug.md
│   ├── vaultaireLDAP.md
│   └── legacy/                # Ancienne documentation (archivée)
│
├── images/                   # Logos et illustrations
│
├── LICENSE
├── README.md
└── go.mod / go.sum
```

## 🔗 Points d’entrée importants

- **Configuration & Installation** : `docs/Setup.md`
- **Commandes Serveur** : `docs/MAN.md`
- **Historique des versions** : `docs/Version_History.md`
- **Sécurité** : `docs/SECURITY.md`
- **Protocoles Réseau** : `docs/Tableau_Protocole_Réseau.md`

---

## 🛠 Branches & Workflow Git

Le développement suit un modèle inspiré de **Gitflow** :

- `main` → **Production** (code stable uniquement)
- `preprod` → **Préproduction** (tests finaux avant mise en prod)
- `dev` → **Développement** (intégration continue des nouvelles fonctionnalités)
- Branches de fonctionnalités : `feature/<nom>`
- Branches de correctifs : `hotfix/<nom>`

---

## ⚙️ Prérequis pour le développement

- Go >= 1.20
- Docker / Docker Compose
- Accès à la base de données de test (MariaDB)
- Clés API ou certificats internes si requis

---

## 🚀 Lancer le projet en local

```bash
# Cloner le dépôt
git clone git@github.com:Vaultaire-AD/vaultaire-core.git
cd vaultaire-core

# Lancer en mode développement
.\deployments\pre-prod\docker-build-and-up.ps1
## ou pour linux
./deployments/pre-prod/docker-build-and-up.sh 
```

---

## 📝 Notes

- ❌ Pas de binaires dans Git : compiler via go build ou CI/CD.
- 📂 Respecter la structure : toute nouvelle fonctionnalité doit être intégrée dans src/ avec tests.
- 🗒️ Documenter vos changements : mise à jour de docs/Version_History.md obligatoire.
