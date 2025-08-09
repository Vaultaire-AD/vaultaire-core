# Explication du focntionnement des **Groupes** et des **Permission**

Dans cette Section Vous allez apprendre le fonctionnement des Groupes et des 2 type de Permissions qui existe dans l'environement Vaultaire

## 1.🚀 `Liste des entités`

- 🧑‍💻 **Utilisateurs**
- 📁 **Groupes**
- 🔐 **Permissions**
- 🖥️ **Clients**

## 2.📁 Les groupes

Les groupes sont des dossier qui servent a regroupé differentes entités ensemble

### 2.1.❓ ca sert a quoi un groupe
---
Lse groupes servent a gère plus facilement l'acces et les permission des different utilisateur au ressource mise a disposition par le domaine

### 2.2.l'interet de mettre un user dans un groupe
---

### 2.3.l'interet de mettre un client dans un groupe
---

### 2.4.relation direct client user
---
si un client et un user sont dans un groupe commun alors le user aura acces au client (par default pas d'acces administrateur)


## 3.🔐 Les Permissions

il existe 2 type de permission les permission dite **client** et les permission dite **user**
**ATTENTION** une permission peut etre a la fois une permission client et user pas recommande

### 3.1.Permission Client
---
Les permissions Client gère les droit que possède les users quand il accède au machine via leur groupe
c'est via c'est permission que l'on peut donner les droit d'administration sur une machine/chargé dse permission custom pour le user est gère les partition qui seront monté sur la machine

-   ## En **resumé**
    -   Gère les permision des users sur la machines
    -   Gère les partition monté sur la machine

### 3.2.Permission User
---
Les permissions User gère l'acces au ressource hors client accés au different service web notament via le SSO

## 📖 **CONVENTION**

Pour la nomentlature du domaine il est recomandé de :  
- crée les Permission User = U_nomdelaperm  
- crée les Permission Client = C_nomdelaperm