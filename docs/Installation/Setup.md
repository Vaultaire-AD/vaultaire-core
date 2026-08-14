
# 🚀 Installation du Service Vaultaire

## 📜 Table des Matières

- [💻 Pré-requis](#-pré-requis)
- [📊 Database-Setup](#-database-setup)
  - [1. Download](#1-download)
  - [2. Setup DataBase](#2-setup-database)
  - [3. Setup Service](#3-setup-service)
- [🔧 Étapes d'Installation](#-étapes-dinstallation)
  - [1. Configuration SELinux](#1-configuration-selinux)
  - [2. Création de l'utilisateur Vaultaire](#2-création-de-lutilisateur-vaultaire)
  - [3. Installation du Binaire Vaultaire](#3-installation-du-binaire-vaultairecli)
  - [4. Création des Dossiers et Attribution des Permissions](#4-création-des-dossiers-et-attribution-des-permissions)
  - [5. Configuration du Service Vaultaire](#5-configuration-du-service-vaultaire)
  - [6. Activation du Service Vaultaire](#6-fichier-de-configuration)
  - [7. Activation du Service Vaultaire](#7-activation-du-service-vaultaire)
  - [8. Setup des fichier client pour l'auto join](#8-setup-des-fichier-client-pour-lauto-join)
- [⚙️ Vérification du Service](#️-vérification-du-service)
- [♻️ Installation d'un client](#️-installation-client)
  - [1. Téléchargé les fichier requis](#1-téléchargé-les-fichier-requis)
  - [2. configuré la connection ssh ](#2-importé-le-fichier-du-nouveau-client)
  - [3. Setup Via le serveur central](#3-setup-via-le-serveur-central)
  - [4. Fichier de Configuration](#4-fichier-de-conf)
  - [5. Test](#5-test)
  - [6. Config SSH Robuste](#6-config-ssh-robuste)
- [📊 Mise à jour](#-mise-à-jour)
  - [1. Mise a jour serveur](#1-serveur)
  - [2. Mise a jour client](#2-client)

---

## 💻 Pré-requis

- Serveur Linux avec accès root.
- Une base de donnée MariaDB (peut etre sur le meme serveur que l'ad )
- Accès à un dossier contenant les binaires Vaultaire.

---
## 📊 DataBase Setup

[Desactiver se linux](#1-configuration-selinux)

### 1. Download

On va installer MariaDB server sur le serveur
```bash
sudo dnf install -y mariadb-server mariadb
sudo systemctl enable --now mariadb
```

### 2. Setup DataBase

On lance cette jolie commande
```bash
sudo mysql_secure_installation
```
cela va vous afficher plusieur ligne :
  - Defined root password ton passwd root de la DB
  - Switch to Unix Socket Yes
  - Change root password n
  - Remove anonymous users Y
  - Disallow root login remotely Y
  - Remove test database and access to it Y
  - Reload privilege tables now Y

On setup le user vaultaire
```sql
mysql -u root -p

CREATE DATABASE vaultaire;
CREATE USER 'vaultaire'@'%' IDENTIFIED BY 'fksjesjKFLJEMjdiqz57dqzD4fzq';
GRANT ALL PRIVILEGES ON vaultaire.* TO 'vaultaire'@'%';
GRANT ALL PRIVILEGES ON vaultaire_dns.* TO 'vaultaire'@'%';
FLUSH PRIVILEGES;
```

### 3. Setup Service

la conf de mariaDB service
```bash
sudo nano /etc/my.cnf.d/mariadb-server.cnf
# Ajoute/modifie ces lignes sous [mysqld] :
skip-networking=0
bind-address = 0.0.0.0
port = 3306
```

on desactive le connection via root via autre que localhost
```bash
sudo systemctl stop mariadb
sudo mysqld_safe --skip-grant-tables &
mysql -u root
UPDATE mysql.user SET host='localhost' WHERE user='root' AND host='%';
FLUSH PRIVILEGES;
# exit terminal SQL
rm -rf /var/lib/mysql/mysql.sock 
firewall-cmd --add-port=3306/tcp --permanent
firewall-cmd --reload
reboot
```

## 🔧 Étapes d'Installation

### 1. Configuration SELinux

D'abord, assurez-vous que SELinux est désactivé :

```bash
sudo vi /etc/selinux/config
```

Modifiez la ligne suivante pour `SELINUX=disabled` :

```ini
SELINUX=disabled
```

---

### 2. Création de l'utilisateur Vaultaire

Créez un nouvel utilisateur `vaultaire` :

```bash
sudo useradd -m -s /bin/bash vaultaire
```

---

### 3. Installation du Binaire VaultaireCLI

Placez le binaire Vaultaire CLI dans le dossier `/usr/local/bin/` :

```bash
mv /mnt/vaultaire_cli/vaultaire_cli /usr/local/bin/vaultaire
chown root:root /usr/local/bin/vaultaire
chmod 750 /usr/local/bin/vaultaire
```

---

### 4. Création des Dossiers et Attribution des Permissions

Créez les dossiers nécessaires pour le binaire et les logs :

```bash
# Création du dossier pour Vaultaire
mkdir /opt/vaultaire
mv /mnt/serveur/vaultaire_serveur /opt/vaultaire/vaultaire_serveur
mv /mnt/serveur/web_packet /opt/vaultaire/web_packet
chown -R vaultaire:vaultaire /opt/vaultaire
chmod -R 700 /opt/vaultaire

# Création du dossier de CONFIGURATION
#
# /etc et non /opt : c'est là qu'un administrateur cherche la configuration
# d'un service, et c'est ce qu'une sauvegarde de /etc emporte.
mkdir -p /etc/vaultaire
chown -R vaultaire:vaultaire /etc/vaultaire
chmod 750 /etc/vaultaire

# Création du dossier pour les logs
mkdir /var/log/vaultaire
chown -R vaultaire:vaultaire /var/log/vaultaire
chmod -R 700 /var/log/vaultaire

# Création du dossier SSH pour Vaultaire (pour les fichiers temporaires générés depuis la BDD)
# Note: Les clés et certificats sont maintenant stockés en base de données, ce dossier sert uniquement
# pour les fichiers temporaires nécessaires aux outils SSH (ssh -i, scp -i)
mkdir /opt/vaultaire/.ssh
chown -R vaultaire:vaultaire /opt/vaultaire/.ssh
chmod -R 700 /opt/vaultaire/.ssh

```

---

### 5. Configuration du Service Vaultaire

Créez un fichier de service systemd pour Vaultaire :

```bash
echo "[Unit]
Description=Vaultaire Service
After=network.target

[Service]
User=vaultaire
Group=vaultaire
ExecStart=/opt/vaultaire/vaultaire_serveur
WorkingDirectory=/opt/vaultaire
Environment=HOME=/home/vaultaire
Environment=USER=vaultaire
# Facultatif : le core trouve /etc/vaultaire/serveur_conf.yaml tout seul.
# Le nommer ici rend la configuration lue VISIBLE dans l'unité, plutôt que
# déduite d'un ordre de recherche qu'il faut connaître.
Environment=VAULTAIRE_CONFIG=/etc/vaultaire/serveur_conf.yaml
LimitNOFILE=4096
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=false
ProtectSystem=full
ProtectHome=yes
ReadOnlyPaths=/etc /usr /lib /bin
ReadWritePaths=/home/vaultaire /var/log/vaultaire /tmp
#RestrictAddressFamilies=AF_INET AF_INET6
LimitMEMLOCK=2048mo

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/vaultaire.service > /dev/null
```

---

### 6. Fichier de configuration

Le core cherche sa configuration dans cet ordre :

| | |
|---|---|
| 1 | `$VAULTAIRE_CONFIG` — s'il est posé, il **l'emporte** |
| 2 | `/etc/vaultaire/serveur_conf.yaml` — **emplacement recommandé** |
| 3 | `/opt/vaultaire/serveur_conf.yaml` — installations existantes |

`/etc` est là où un administrateur cherche la configuration d'un service, et
c'est ce qu'une sauvegarde de `/etc` emporte. `/opt` reste accepté pour ne pas
casser les déploiements en place.

La variable l'emporte **même si le fichier qu'elle désigne n'existe pas** : la
poser est une décision, et se rabattre en silence sur un autre fichier ferait
démarrer le core sur une configuration que personne n'a demandée.

```bash
sudo mkdir -p /etc/vaultaire
sudo cp deployments/configs/serveur_conf.yaml /etc/vaultaire/serveur_conf.yaml
```

Le modèle de référence est
[`deployments/configs/serveur_conf.yaml`](../../deployments/configs/serveur_conf.yaml).
Contenu minimal :

```yaml
serveurlistenport: "6666"
file-path:
  socketpath: "/opt/vaultaire/vaultaire.sock"
  privatekeypath: "/opt/vaultaire/.ssh/private_key.pem"
  publickeypath: "/opt/vaultaire/.ssh/public_key.pub"
  privatekeyforlogintoclient: "/opt/vaultaire/.ssh/private_key_for_login_client_rsa"
  publickeyforlogintoclient: "/opt/vaultaire/.ssh/public_key_for_login_client_rsa.pub"
  clientconfpath: "/opt/vaultaire/client_conf.yaml"
  logpath: "/var/log/vaultaire/vaultaire.log"
  servercheckonlinetimer: 5
ldap:
  ldap_enable: false
  ldaps_enable: true
  Ldap_Port: 389
  Ldaps_Port: 636
  # Logs DEBUG (LDAP, etc.) : utiliser la section debug: debug: true
website:
  website_enable: true
  Website_Port: 443
database:
  username: "root"
  password: "root"
  ip_database: "127.0.0.1"
  port_database: "3306"
  databaseName: "vaultaire_db"
autoAddClientCommandes:
  - mv -f /opt/vaultaire/vaultaire_client/pam*.so /usr/lib64/security/
  - mkdir -p /opt/vaultaire_client/.ssh
  - mv /opt/vaultaire/vaultaire_client/vaultaire_client /opt/vaultaire_client/
  - mv /opt/vaultaire/client_software.yaml /opt/vaultaire_client/.ssh/client_software.yaml
  - mv /opt/vaultaire/*.pem /opt/vaultaire_client/.ssh/
  - chmod 700 -R /opt/vaultaire_client/
  - chmod 400 -R /opt/vaultaire_client/.ssh/*
  - |
    cat > /etc/systemd/system/vaultaire_client.service <<'EOF'
    [Unit]
    Description=Vaultaire_Client Service
    After=network.target

    [Service]
    User=root
    Group=root
    ExecStart=/opt/vaultaire_client/vaultaire_client
    WorkingDirectory=/opt/vaultaire_client
    Environment=USER=root
    LimitNOFILE=4096
    PrivateTmp=false
    ProtectSystem=full
    ReadOnlyPaths=/etc /usr /lib /bin
    ReadWritePaths=/tmp

    [Install]
    WantedBy=multi-user.target
    EOF
  - chmod 644 /usr/lib64/security/pam_login_custom_module.so
  - chmod 644 /usr/lib64/security/pam_logout_custom_module.so
  - chown root:root /usr/lib64/security/pam_login_custom_module.so
  - chown root:root /usr/lib64/security/pam_logout_custom_module.so
  - |
    cat > /opt/vaultaire_client/client_conf.yaml <<'EOF'
    serveurlistenport: 666
    serveur_ip: 192.168.10.76
    EOF
  - systemctl daemon-reload
  - systemctl enable vaultaire_client.service
  - systemctl start vaultaire_client.service
  - rm -rf /opt/vaultaire
  - |
    cat /etc/pam.d/system-auth <<''EOF
    #%PAM-1.0
    # This file is auto-generated.
    # User changes will be destroyed the next time authselect is run.
    #auth        required      pam_env.so
    #auth        sufficient    pam_unix.so try_first_pass nullok
    #auth        required      pam_deny.so
    auth        required      pam_login_custom_module.so
    account     required      pam_unix.so
    
    password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
    password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
    password    required      pam_deny.so
    
    session     optional      pam_keyinit.so revoke
    session     required      pam_limits.so
    -session     optional      pam_systemd.so
    session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
    session     required      pam_unix.so
    EOF
  - |
    cat /etc/pam.d/login <<''EOF'
    #%PAM-1.0
    #auth       substack     system-auth
    #auth       include      postlogin
    auth       required     pam_login_custom_module.so
    account    required     pam_nologin.so
    account    include      system-auth
    password   include      system-auth
    # pam_selinux.so close should be the first session rule
    session    required     pam_selinux.so close
    session    required     pam_loginuid.so
    # pam_selinux.so open should only be followed by sessions to be executed in the user context
    session    required     pam_selinux.so open
    session    required     pam_logout_custom_module.so
    session    required     pam_namespace.so
    session    optional     pam_keyinit.so force revoke
    session    include      system-auth
    session    include      postlogin
    -session   optional     pam_ck_connector.so
    EOF
  - |
    cat /etc/pam.d/sudo <<''EOF'
    #%PAM-1.0
    #auth       include      system-auth
    #account    include      system-auth
    #password   include      system-auth
    #session    include      system-auth
    auth       required      pam_env.so
    auth       sufficient    pam_unix.so try_first_pass nullok
    auth       required      pam_deny.so

    account    required      pam_unix.so

    password   sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
    password   required      pam_deny.so

    session    optional      pam_keyinit.so revoke
    session    required      pam_limits.so
    -session   optional      pam_systemd.so
    EOF
  - chmod 644 /etc/pam.d/*

```


chaque variable a une valeur par default qui est celle ci dessus 

---

### 7. Activation du Service Vaultaire

Enfin, activez et démarrez le service :

```bash
# Rechargez les fichiers de service systemd
sudo systemctl daemon-reload

# Activez le service au démarrage
sudo systemctl enable vaultaire.service

# Donnez à l'exécutable les permissions nécessaires pour lier le port
setcap cap_net_bind_service=ep /opt/vaultaire/vaultaire_serveur

# Démarrez le service
sudo systemctl start vaultaire.service

# Assurez-vous que le fichier de service est bien protégé
sudo chmod 640 /etc/systemd/system/vaultaire.service
sudo chown root:root /etc/systemd/system/vaultaire.service
alias vlt=vaultaire
```

### Rotation des journaux

```bash
sudo cp deployments/logrotate/vaultaire-core /etc/logrotate.d/
sudo logrotate --debug /etc/logrotate.d/vaultaire-core   # simulation
```

Le journal **principal** du core n'est pas concerné : il part sur la sortie
standard, et c'est systemd ou le moteur de conteneurs qui le collecte, avec sa
propre rétention. Le faire tourner ici en tiendrait deux, et « où sont les
journaux » aurait deux réponses.

Deux familles passent par un fichier, parce qu'on veut pouvoir les lire à part :

| Fichier | Contenu |
|---|---|
| `/var/log/vaultaire/date.log` | dates de naissance refusées à la création d'un compte |
| `/var/log/vaultaire/SQL_Injection.log` | identifiants écartés par l'assainissement des requêtes |

Politique : **un fichier par jour, 30 archives, compressées sauf la plus
récente**, et une taille maximale de 50 Mo pour qu'un incident bavard ne
remplisse pas la partition avant minuit.

> ⚠️ La borne de taille ne joue que si logrotate est invoqué **plus souvent
> qu'une fois par jour**. Le minuteur systemd standard est quotidien — dans ce
> cas la seule borne réelle est la cadence. Voir
> `deployments/logrotate/README.md` pour le passer à l'heure.

Ces deux fichiers sont créés en `0600 root:root`, dans un répertoire en `0700` :
ils nomment des comptes et des tentatives d'injection.

---

## ⚙️ Vérification du Service

Pour vérifier que votre service fonctionne correctement, vous pouvez consulter son état avec :

```bash
sudo systemctl status vaultaire.service
```

### Ce que le premier démarrage fait tout seul

Aucune clé n'est à générer à la main. Au premier démarrage, le core :

1. crée les tables si elles n'existent pas ;
2. **génère sa paire de clés** (`server_main`) et la clé SSH de déploiement des
   agents, puis les range **en base** — pas sur disque ;
3. journalise son **empreinte**, et s'enregistre dans le cluster.

La ligne à retrouver dans le journal :

```
keymanagement: empreinte du core SHA256:…
```

C'est cette empreinte qu'un agent compare à la clé qu'on lui sert. La même
valeur est disponible à tout moment par `certificate fingerprint`.

> Les clés sont amorcées **avant** tout service qui les lit. Une version
> antérieure les générait depuis le démarrage du service réseau, en parallèle :
> sur une base neuve, le gestionnaire de cluster lisait une clé qui n'existait
> pas encore et le serveur s'arrêtait — au premier démarrage, celui où l'on
> comprend le moins ce qui se passe.

### Si le démarrage échoue

| Message | Ce qu'il faut faire |
|---|---|
| `configuration du core introuvable ou illisible` | le message liste les emplacements consultés et la commande pour y déposer le modèle |
| `Impossible d'amorcer les clés du core` | la base est inaccessible, ou la table `certificates` manque — vérifiez la section `database` de la configuration |
| `cluster: empreinte du core indisponible` | **non fatal** : le core tourne, mais ne s'annoncera pas aux agents |

---

# 8. Setup des fichier client pour l'auto join

sur le git recupère le contenu du dossier vaultaireAD-client ou sur les release la version client que vous souhaiter
placer dans le repertoire suivant
`/opt/vaultaire/vaultaire_client/`
c'est depuis ce fichier que le serveur recupèrera les fichier a installé sur les clients
Attention la clé public devra etre ajouter au client au préalable 

```sh
ssh-copy-id -i ~/.ssh/id_rsa.pub user@host
``` 

attention pour utiliser la commande autojoin vous devez crée une variable d'environement
```bash
sudo nano /etc/profile.d/setenv.sh
# add this line
# Note: VAULTAIRE_pubKeyLogin n'est plus nécessaire - la clé publique est maintenant gérée automatiquement depuis la base de données
# Si vous avez besoin d'accéder à la clé publique, utilisez l'interface web admin ou l'API
#reload
sudo chmod +x /etc/profile.d/setenv.sh
source /etc/profile.d/setenv.sh
echo $VAULTAIRE_pubKeyLogin

```
🎉 **Installation terminée !** Vous avez maintenant le serveur Vaultaire installé et en cours d'exécution sur votre machine. Vous pouvez gérer votre service et vos fichiers de configuration à partir du répertoire `/opt/vaultaire`.


## ♻️ Installation client

### 1. Téléchargé les fichier requis

via un acces interne ou via le repo officiel de prod ou de preprod
téléchargé le binaire vaultaire_client ainsi que les different module pam
puis déplacé tous les fichier dans le dossier /opt/vaultaire_client-install

### 2. importé le fichier du nouveau client

ensuite via le serveur central recupéré le donnée dans le fichier de conf qui contient toutes les info de creation des users et de client dans le dossier clientsoftware envoyé le info dans le dossier vers le bon server dans /opt/

**le plus simple est de se co en ssh au serveur a intégré**  

✨*example*
---
```bash
scp -r /opt/vaultaire/conf/clientsoftware/oRcwnlgXCIi3/* root@192.168.10.221:/opt/
```

### 3. Setup en local


A faire en **root**
```bash
mv /opt/pam*.so /usr/lib64/security/
mkdir -p /opt/vaultaire
mkdir -p /opt/vaultaire/.ssh
mv /opt/vaultaire_client /opt/vaultaire/
mv /opt/*.pem /opt/vaultaire/.ssh/
mv /opt/client_software.yaml /opt/vaultaire/.ssh/
chmod 700 -R /opt/vaultaire
```

ensuite il faudrai modifier 3 fichier dans /etc/pam.d
il faut que les fichier est les memes lignes commenter et l'ajout des lignes avec des custom module
```bash
[root@client pam.d]# cat system-auth 
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authselect is run.
auth        required      pam_login_custom_module.so
#auth        required      pam_env.so
#auth        sufficient    pam_unix.so try_first_pass nullok
#auth        required      pam_deny.so

account     required      pam_unix.so

----------------------------------------------

[root@client pam.d]# cat login 
#%PAM-1.0
#auth       substack     system-auth
#auth       include      postlogin
auth       required     pam_login_custom_module.so
account    required     pam_nologin.so
account    include      system-auth
password   include      system-auth
# pam_selinux.so close should be the first session rule
#session           required     pam_logout.so
session    required     pam_selinux.so close
session    required     pam_logout_custom_module.so
session    required     pam_loginuid.so
```
si vous voulez que la commande sudo soit gère par l'auth local commenter le contenu de votre ancien fichier et rejouter celui ci en dessous
```sh
[root@NTFS nfs]# cat /etc/pam.d/sudo
#%PAM-1.0
auth       required      pam_env.so
auth       sufficient    pam_unix.so try_first_pass nullok
auth       required      pam_deny.so

account    required      pam_unix.so

password   sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
password   required      pam_deny.so

session    optional      pam_keyinit.so revoke
session    required      pam_limits.so
-session   optional      pam_systemd.so
```

il vous reste plus qu'a ecrire un fichier de service et ca sera bon voila un example
vi /etc/systemd/system/vaultaire_client.service
```bash
[Unit]
Description=Vaultaire_Client Service
After=network.target

[Service]
User=root
Group=root
ExecStart=/opt/vaultaire/vaultaire_client
WorkingDirectory=/opt/vaultaire
Environment=USER=root
LimitNOFILE=4096
PrivateTmp=false
ProtectSystem=full
ReadOnlyPaths=/etc /usr /lib /bin
ReadWritePaths=/tmp


[Install]
WantedBy=multi-user.target


```
sudo systemctl daemon-reload
sudo systemctl enable vaultaire_client.service
sudo systemctl start vaultaire_client.service
sudo systemctl status vaultaire_client.service
sudo chmod 644 /usr/lib64/security/pam_login_custom_module.so
sudo chmod 644 /usr/lib64/security/pam_logout_custom_module.so
sudo chown root:root /usr/lib64/security/pam_login_custom_module.so
sudo chown root:root /usr/lib64/security/pam_logout_custom_module.so

### 4. Fichier de Conf

crée le fichier de configuration suivant
/opt/vaultaire/client_conf.yaml 
```yaml
serveurlistenport: 666
serveur_ip: 192.168.10.76
```

### 5. Test

tester la connection d'un user du domaine

### 6. Config SSH Robuste

remmetez la configuration ssh que vous voulez


## ⏫ Mise à jour

Pour mettre a jour les client et les serveurs vous devrez telechargé les nouveau binaires
si dans le patch notes il est mentionner les modules pam vous devrez resuivre la doc d'installation pour les modules pam sur tous vos clients

### 1. Serveur

Si update sur le binaire vaultaire_cli resuivre la doc d'installation pour la partie cli  
```bash
systemctl stop vaultaire
#remplacer le binaire vaultaire_serveur en dessous exemple
mv /mnt/serveur/vaultaire_serveurAlpha-1.0.3 /opt/vaultaire/vaultaire_serveur
chown -R vaultaire:vaultaire /opt/vaultaire/vaultaire_serveur
chmod -R 700 /opt/vaultaire/vaultaire_serveur
systemctl restart vaultaire
```

### 2. Client

si aucune update sur les modules pam voir le patch note de votre version sinon resuivre la doc d'installation   

```bash
systemctl stop vaultaire
#remplacer le binaire vaultaire_serveur en dessous exemple
mv /mnt/serveur/vaultaire_clientAlpha-1.0.3 /opt/vaultaire/vaultaire_client
chown -R vaultaire:vaultaire /opt/vaultaire/vaultaire_client
chmod -R 700 /opt/vaultaire/vaultaire_client
systemctl restart vaultaire_client
```
