# 🏢 Manuel des Commandes Vaultaire AD

## 📜 Table des Matières

- [📌 Commandes Disponibles](#-commandes-disponibles)
- [🚀 `create` (Création)](#-create)
- [📊 `status` - Voir l'état](#-status)
- [🧹 `clear` (Nettoyage des sessions)](#-clear)
- [🔍 `get` (Récupérer des informations)](#-get)
- [➕ `add` (Ajouter des groupes ou permissions)](#-add)
- [➖ `remove` (Retirer des permissions ou groupes)](#-remove)
- [🗑️ `delete` (Suppression)](#-delete)
- [⚙️ `update` (Mise à jour des utilisateurs)](#-update)

---

## 📌 Commandes Disponibles

- `create`  
- `status`  
- `clear`  
- `get`  
- `add`  
- `remove`  
- `delete`  
- `update`  

---

# 🚀 `create`

On peut créer différentes entités :
- 🧑‍💻 **Utilisateurs**
- 📁 **Groupes**
- 🔐 **Permissions**
- 🖥️ **Clients**
- 🔒 **GPO**

   ## `create -p -u` (Créer une permission user)

   ```bash
   create -p -u "nom_de_la_permission" <description_sans_espace>
   ```
   ✨*example*
   ---
   ```bash
   ```
   🔹 yes/not : Indique si la permission concerne l'administration globale.  

   ## `create -p -c` (Créer une permission client)

   ```bash
   create -p -c "nom_de_la_permission" <yes/not>
   ```
   ✨*example*
   ---
   ```bash
   ```
   🔹 yes/not : Indique si la permission concerne l'administration globale.  

## `create -g` (Créer un groupe)

```bash
create -g "nom_du_groupe" "domain_name"
```
✨*example*
---
```bash
create -g test
📂 Group Information: test
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   ❌ No permissions assigned to this group.
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   ❌ No clients associated with this group.
--------------------------------------------------
🔐 Client Permissions:
   ❌ No permissions assigned to clients in this group.
--------------------------------------------------0
```

⚠️ Un groupe doit être associé à une permission.

## `create -u` (Créer un utilisateur)  

📌 Commande pour créer un utilisateur :

if you create user with firstname.lastname it will auto complete in database
```bash
create -u username domain password birthdate(06/02/1992) email
#optional path for auto create first and last name 
create -u user.name domain password birthdate(06/02/1992) email
#optional priorité sur le parsing avec le point pour definir le first et last name
create -u user.name domain password birthdate(06/02/1992) email firstname lastname
```
✨*example*
---
```bash
>> vaultaire create -u alice secret123 06/02/1992
vaultaire create -u bob.lenon company.com strongpass 09/12/1988 
vaultaire create -u fiona company.com mypass321 08/07/1985 fiona targerien
vaultaire create -u julie company.com loginme 10/09/1994
vaultaire create -u charlie company.com admin987 03/09/1995
vaultaire create -u diana company.com pass456 01/07/1990
vaultaire create -u eric company.com devpass99 30/01/1993 
vaultaire create -u george company.com testme! 12/11/1997 
vaultaire create -u hannah company.com welcome1 04/02/1991
vaultaire create -u isaac company.com vault123 05/03/1989 
```
 

## `create` -c (Créer un client)

```bash
create -c <type_client> <yes/not> 
#optional argument 
#for auto integration of the client
create -c <type_client> <yes/not> -join <IP> <Username>
```
✨*example*
---
```bash
>> create -c serveurKubernetes yes
Client software configuration et clés générées avec succès dans : /opt/vaultaire/conf/clientsoftware/wUTEcxeT5RGY
new user create with succes with this conf : serveurKubernetesserveur = yes
```

🔹 yes/not : Indique s'il s'agit d'un serveur ou non.

## `create` -gpo (Créer une gpo)

```bash
create -gpo <nom_de_la_gpo> [--cmd <commande>] ou [--ubuntu <commande> --debian ... --rocky]"
```
✨*example*
---
```bash
>> create -gpo alias --cmd alias vlt=vautlaire
🔒 GPO Information
--------------------------------------------------
ID                  : 22                            
Nom de la GPO       : alias                         
Ubuntu Commande     : alias vlt=vautlaire           
Debian Commande     : alias vlt=vautlaire           
Rocky Commande      : alias vlt=vautlaire           
--------------------------------------------------
>>create -gpo test3 --ubuntu alias vlt_ubuntu=vaultaire --debian vlt_debian=vaultaire --rocky vlt_rocky=vaultaire
🔒 GPO Information
--------------------------------------------------
ID                  : 23                            
Nom de la GPO       : test3                         
Ubuntu Commande     : alias vlt_ubuntu=vaultaire    
Debian Commande     : vlt_debian=vaultaire          
Rocky Commande      : vlt_rocky=vaultaire           
--------------------------------------------------
```

🔹 yes/not : Indique s'il s'agit d'un serveur ou non.
---

# 📊 `status`

📌 Permet d'afficher l'activité de l'Active Directory :
- **Les utilisateurs connectés et sur quel client 🧑‍💻**
- **La liste des utilisateurs par client 🖥️**
- **La liste des clients serveurs 🌐**

## `status -u` (Lister les utilisateurs connectés)  

```bash
status -u
```
✨*example*
---
```bash
>> status -u
📋 Connected Users
--------------------------------------------------------------------------
ID Username             Created At            Token Expiry       Status
1    visiteur        2025-02-15 15:29:46  2025-03-01 22:10:51  ✅ Active
2    admin           2025-03-01 21:09:00  2025-03-01 22:11:19  ✅ Active
--------------------------------------------------------------------------
```

## **🎯 Arguments** :
- Par nom **d'utilisateur** :
```bash
status -u "username"
```
✨*example*
---
```bash
>> status -u admin
📋 Connected Users
--------------------------------------------------
ID Username Created At Token Expiry Status
2    admin           2025-03-01 21:09:00  2025-03-01 22:11:19  ✅ Active
--------------------------------------------------
```
- Par **groupe** :
```bash
status -u -g "group_name"
```
✨*example*
---
```bash
>> status -u -g Administrateur_Global
📋 Connected Users
--------------------------------------------------
ID Username Created At Token Expiry Status
2    admin           2025-03-01 21:09:00  2025-03-01 22:11:19  ✅ Active
--------------------------------------------------
```

## `status -c` (Lister les clients connectés)

```bash
status -c
```
✨*example*
---
```bash
>> status -c
💻 Connected Clients
----------------------------------------------------------------------------------------------------------------------------------------
Username        Type            Computeur ID       Hostname                 Serveur  CPU         RAM                  OS
test10          test            Vhg4WLMbHbwO         client               🟢 Serveur 6          4.2Gi      Rocky Linux 9.4 (Blue Onyx)
admin           test            Vhg4WLMbHbwO         client               🟢 Serveur 6          4.2Gi      Rocky Linux 9.4 (Blue Onyx)
----------------------------------------------------------------------------------------------------------------------------------------
```

## **🎯 Arguments** :
- Par type de **client** :
```bash
status -c <type_client>
```
✨*example*
---
```bash
>> status -c test
💻 Connected Clients
----------------------------------------------------------------------------------------------------------------------------------------
Username        Type            Computeur ID       Hostname                 Serveur  CPU         RAM                  OS
Test            test            Vhg4WLMbHbwO         client               🟢 Serveur 6          4.2Gi      Rocky Linux 9.4 (Blue Onyx)
admin           test            Vhg4WLMbHbwO         client               🟢 Serveur 6          4.2Gi      Rocky Linux 9.4 (Blue Onyx)
----------------------------------------------------------------------------------------------------------------------------------------
```

- Par **groupe** :
```bash
status -c -g "group_name"
```
✨*example*
---
```bash
>> status -c -g visiteur
💻 Connected Clients
--------------------------------------------------
Username Type Computeur ID Hostname Serveur CPU RAM OS
admin   test            Vhg4WLMbHbwO         client               🟢 Serveur 6          4.2Gi      Rocky Linux 9.4 (Blue Onyx)
```

---

# 🧹 `clear` 

## **Nettoyer les sessions**

```bash
clear
```
✨*example*
---
```bash
>> clear
```

📌 Exécute immédiatement la suppression des sessions inactives (sinon exécuté toutes les 30 minutes).

# 🔍 `get`

## `get -u` (Informations sur un utilisateur)

- Tous les **utilisateurs** :
```bash
get -u
```
✨*example*
---
```bash
>> get -u
👥 Liste de tous les Utilisateurs
--------------------------------------------------
ID Utilisateur Username    Date de Naissance Créé à
1               test                      2004-01-06      2025-02-15 15:29:46 
2               admin                     2004-01-06      2025-03-01 21:09:00 
--------------------------------------------------
```
- Un utilisateur **spécifique** :
```bash
get -u "username"
```
✨*example*
---
```bash
>> get -u admin
👤 User Information
--------------------------------------------------
Username: admin      
Date of Birth: 2004-01-06 
Status: ✅ Online   

Groups: [Administrateur_Global]
Permissions: [visiteur]
--------------------------------------------------
```

- Par **groupe** :
```bash
get -u -g "group_name"
```
✨*example*
---
```bash
>> get -u -g visiteur
>> -aucun utilisateur trouvé pour le groupe 'visiteur'
>> get -u -g Administrateur_Global
👥 Users in Group: Administrateur_Global
--------------------------------------------------
Username Date of Birth Status
admin                2004-01-06      ✅ Online
--------------------------------------------------
```

## `get -p` (Lister les permissions et leurs groupes associés)

```bash
get -p -u
get -p -u permission name
```

```bash
get -p -c
get -p -c permission name
```

## `get -g` (Lister les groupes et leurs permissions associées)

- Tous les **groupes** avec leur contenu :
```bash
get -g
```
✨*example*
---
```bash
>> get -g
📊 Group Details
--------------------------------------------------
Group_Name Permissions Users  Clients
Administrateur_Global 0                    2                    1                   
visiteur             1                    0                    1                   
--------------------------------------------------
```
- Détails **d'un** groupe :
```bash
get -g "groupe_name"
```
✨*example*
---
```bash
>> get -g visiteur
📂 Group Information: visiteur
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   - test
   - visiteur
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   - client
--------------------------------------------------
🔐 Client Permissions:
   - test
--------------------------------------------------
```
- **Clients** d'un groupe :
```bash
get -g -c "group_name"
```
✨*example*
---
```bash
>> get -g -c visiteur
💻 Clients in Group: visiteur
--------------------------------------------------
Client ID Type Computeur ID Hostname Serveur Processeur RAM
1          test            Vhg4WLMbHbwO         client          Yes        6               4.2Gi     
--------------------------------------------------
```
- **Utilisateurs** d'un groupe :
```bash
get -g -u "group_name"
```
✨*example*
---
```bash
>> get -g -u Administrateur_Global
👥 Users in Group: Administrateur_Global
--------------------------------------------------
Username Date of Birth Status
admin                2004-01-06      ✅ Online
--------------------------------------------------
```

## `get -c` (Lister les Clients)

- **Tous** les clients :
```bash
get -c
```
✨*example*
---
```bash
>> get -c
💻 Liste de tous les Clients (Logiciels)
--------------------------------------------------
ID Logiciel Logiciel Type Computeur ID Hostname Serveur Processeur RAM OS
1               test                      Vhg4WLMbHbwO    client          Oui        6          4.2Gi           Rocky Linux 9.4 (Blue Onyx)
--------------------------------------------------
```
- Par **Computeur ID** :
```bash
get -c "computeur_id"
```
✨*example*
---
```bash
>> get -c Vhg4WLMbHbwO
💻 Client Information
--------------------------------------------------
ID    : 1                             
Type  : test                          
Computeur ID: Vhg4WLMbHbwO                  
Hostname: client                        
Serveur: ✅ Yes                
Processeur: 6                             
RAM   : 4.2Gi                         
OS    : Rocky Linux 9.4 (Blue Onyx)   
Groupes: Administrateur_Global, visiteur
Permissions: visiteur                      
--------------------------------------------------
```

## `get -gpo` (Lister les gpo)

- Tous les **groupes** avec leur contenu :
```bash
get -gpo
```
✨*example*
---
```bash
>> get -gpo
🔒 Liste des GPO
--------------------------------------------------
ID                  : 22                            
Nom de la GPO       : alias                         
Ubuntu Commande     : alias vlt=vautlaire           
Debian Commande     : alias vlt=vautlaire           
Rocky Commande      : alias vlt=vautlaire           
--------------------------------------------------
>> get gpo alias
🔒 GPO Information
--------------------------------------------------
ID                  : 22                            
Nom de la GPO       : alias                         
Ubuntu Commande     : alias vlt=vautlaire           
Debian Commande     : alias vlt=vautlaire           
Rocky Commande      : alias vlt=vautlaire           
--------------------------------------------------
```

# ➕ `add`

## `add -u` (Ajouter un groupe à un utilisateur)

```bash
add -u "username" -g "group_name"
```
✨*example*
---
```bash
>> add -u admin -g visiteur
👤 User Information
--------------------------------------------------
Username: admin
Date of Birth: 2004-12-06 
Status: ✅ Online   

Groups: [Administrateur_Global visiteur]
--------------------------------------------------
```

## `add -c` (Ajouter un client à un groupe)

```bash
add -c "computeur_id" -g "group_name"
```
✨*example*
---
```bash
>> add -c Vhg4WLMbHbwO -g Administration_Global
💻 Client Information
--------------------------------------------------
ID    : 1                             
Type  : test                          
Computeur ID: Vhg4WLMbHbwO                  
Hostname: client                        
Serveur: ✅ Yes                
Processeur: 6                             
RAM   : 4.2Gi                         
OS    : Rocky Linux 9.4 (Blue Onyx)   
Groupes: Administrateur_Global, visiteur
--------------------------------------------------
```

## `add -g` (Ajouter une permission à un groupe)

- Groupe **d'utilisateurs** :
```bash
add -gu "group_name" -p "permission_name"
```
✨*example*
---
```bash
>> add -gu test10 -p test
✅ La permission 'test' a été ajoutée au groupe 'test10' avec succès !
📂 Group Information: test10
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   - test
   - visiteur
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   ❌ No clients associated with this group.
--------------------------------------------------
🔐 Client Permissions:
   ❌ No permissions assigned to clients in this group.
--------------------------------------------------
```
- Groupe de **clients** :
```bash
add -gc "group_name" -p "permission_name"
```
✨*example*
---
```bash
>> add -gc test10 -p visiteur
✅ La permission 'visiteur' dans le groupe 'test10' avec succès !
📂 Group Information: test10
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   - test
   - visiteur
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   ❌ No clients associated with this group.
--------------------------------------------------
🔐 Client Permissions:
   - visiteur
--------------------------------------------------
```

## `add -gpo` (Ajouter une permission à un groupe)
```bash
add -gpo "gpo_name" -p "group_name"
```
✨*example*
---
```bash
>> add -gpo session-timeout -g test
📂 Group Information: test
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   ❌ No permissions assigned to this group.
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   ❌ No clients associated with this group.
--------------------------------------------------
🔐 Client Permissions:
   ❌ No permissions assigned to clients in this group.
--------------------------------------------------
🔒 Group GPOs:
   - session-timeout
--------------------------------------------------
```

# ➖ `remove`

## `remove -u` (Retirer une permission a un groupe )

```bash
remove -u "username" -g "group_name"
```
✨*example*
---
```bash
>> remove -u admin -g visiteur
👤 User Information
--------------------------------------------------
Username: admin      
Date of Birth: 2004-01-06 
Status: ❌ Offline  

Groups: [Administrateur_Global]
--------------------------------------------------
```

## `remove -c` (Retirer un client d'un groupe)

```bash
remove -c "computeur_id" -g "group_name"
```
✨*example*
---
```bash
>> remove -c Vhg4WLMbHbwO -g visiteur
💻 Client Information
--------------------------------------------------
ID    : 1                             
Type  : test                          
Computeur ID: Vhg4WLMbHbwO                  
Hostname: client                        
Serveur: ✅ Yes                
Processeur: 6                             
RAM   : 4.2Gi                         
OS    : Rocky Linux 9.4 (Blue Onyx)   
Groupes: Administrateur_Global         
--------------------------------------------------
```

## `remove -g` (Retirer une permission d'un groupe)
 remove une permission users d'un groupe
```bash
remove -g "group_name" -pu "permission_name"
```
✨*example*
---
```bash
>> remove -g test10 -pu test
📂 Group Information: test10
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   - visiteur
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   ❌ No clients associated with this group.
--------------------------------------------------
🔐 Client Permissions:
   - visiteur
--------------------------------------------------
```

remove une permission Client d'un groupe
```bash
remove -g "group_name" -pc "permission_name"
```
✨*example*
---
```bash
>> remove -g test10 -pc visiteur
📂 Group Information: test10
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   ❌ No permissions assigned to this group.
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   ❌ No clients associated with this group.
--------------------------------------------------
🔐 Client Permissions:
   - visiteur
--------------------------------------------------
```

## `remove -gpo` (Retirer une gpo d'un groupe)
 remove une permission users d'un groupe
```bash
remove -gpo "gpo_name" -pu "group_name"
```
✨*example*
---
```sh
>> vlt remove -gpo session-timeout -g test
 Group Information: test
--------------------------------------------------
👥 Users in Group:
   ❌ No users in this group.
--------------------------------------------------
🔑 Group Permissions:
   ❌ No permissions assigned to this group.
--------------------------------------------------
🖥️ Clients (Softwares) in Group:
   ❌ No clients associated with this group.
--------------------------------------------------
🔐 Client Permissions:
   ❌ No permissions assigned to clients in this group.
--------------------------------------------------
🔒 Group GPOs:
   ❌ No GPOs assigned to this group.
--------------------------------------------------
```

# 🗑️ `delete`

la fonction delete detruit aussi toutes les relation entres les differentes entités
```bash
delete -u "username"
delete -g "group_name"
delete -p -u/-c "permission_name"
delete -c "computeur_id"
delete -gpo "gpo_name"
```
✨*example*
---
```bash
>> delete -p visiteur
The Client :visiteur Has been DELETED With Succes
```

# ⚙️ `update`

```bash
update -u "username" -uu "new_username"
```
✨*example*
---
```bash

```

## Update User permission

```bash
update -pu LDAP_WriteAccess can_read yes
```

✨*example*
---
```bash
vaultaire update -pu LDAP_WriteAccess can_read yes
👤 Permission Utilisateur : LDAP_WriteAccess
-------------------------------------------------------------
ID: 3
Description: Ecriture_dans_LDAP
None: false
Auth: true
Compare: false
Search: false
Read: true
Write: false
-------------------------------------------------------------
```

# 👁️ `eyes`

eyes est un module pour obtenir des inormation particuliere sur l'etat de votre controlleur de domaine

## eyes -g

cette commande permet d'obtenir un arbre de groupe au format foret de ldap

```bash
eyes -g
```

✨*example*
---
```bash
vaultaire eyes -g
├── data
│   └── solution
│       └── test
│           └── * Group: externe (test.solution.data)
└── fr
    └── vaultaire
        ├── * Group: direction (vaultaire.fr)
        ├── admin
        │   ├── * Group: admin (admin.vaultaire.fr)
        │   └── virtu
        │       └── * Group: admin-virtu (virtu.admin.vaultaire.fr)
        ├── audit
        │   └── * Group: audit (audit.vaultaire.fr)
```

📌 **Paramètres facultatifs** après -u.
