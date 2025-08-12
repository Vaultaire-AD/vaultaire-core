# 📌 Roadmap Vaultaire — Jusqu’à fin septembre 2025

## 1. Structurer le projet et l’infra de base (debût août – mi-août)

- Réorganiser les repos GitHub (dev / prod / doc séparés)  
- Standardiser le workflow Git (branches, PR, issues, tags)  
- Mettre en place une CI simple (tests unitaires, lint Go)  
- Documenter la stack technique (README + résumé architecture)  
- Écrire une roadmap publique (même sommaire) pour attirer la com  

## 2. Consolider la base technique (mi-août – fin août)

- Stabiliser et finaliser les features alpha critiques (bugfix LDAP, GPO basique)  
- Ajouter un système minimal d’authentification pour la gestion à distance (clé/token)  
- Développer un client CLI vaultctl basique (socket local + option tunnel SSH)  
- Tester la CLI en usage réel (ajout utilisateur, groupe, lecture infos)  

## 3. Préparer la montée en charge collaborative (septembre)

- Mettre en place un canal de communication d’équipe (Slack/Discord/Matrix)  
- Définir un backlog clair et priorisé (issues GitHub)  
- Préparer un guide de contribution simple (style de code, process PR)  
- Rédiger un document d’architecture fonctionnelle pour guider les dev web  

## 4. Communication et early adopters (septembre)

- Créer une landing page simple (GitHub Pages)  
- Publier un premier article/annonce (Reddit, LinkedIn, HN) pour recruter des early testers  
- Recueillir les premiers retours utilisateurs et corriger les bugs bloquants  
- Construire la documentation utilisateur / admin  

## 5. Préparation du dev du site web (fin septembre)

- Lister clairement les besoins API + fonctionnalités web  
- Valider les choix technos (Go + gRPC ou REST, React, etc.)  
- Définir les specs API basiques (auth, gestion users, groupes, DNS, GPO)  
- Créer un repo dédié API + site si séparés  

---

# 🔹 Architecture gRPC proposée

## Pourquoi découper en services avec gRPC

- **Modularité** : services indépendants (LDAP, DNS, GPO, Auth, etc.)  
- **Scalabilité** : déploiement indépendant, réplication possible  
- **Interopérabilité** : support de plusieurs langages  
- **Performance** : protocole binaire rapide, streaming bidirectionnel  
- **Sécurité** : TLS mutuel, auth centralisée  

## Exemple d’architecture

- **gateway-service** : point d’entrée, authentifie et route les requêtes  
- **auth-service** : gère permissions, tokens, certificats  
- **ldap-service** : logique annuaire LDAP  
- **dns-service** : gestion des entrées DNS  
- **gpo-service** : gestion GPO / scripts  

## Stratégie de migration vers gRPC

- Alpha actuelle : garder le socket local pour ne pas tout casser  
- Dès maintenant : isoler la logique par paquets Go (LDAP, DNS, Auth…)  
- Quand API prête : ajouter couche gRPC devant chaque service  
- Clients (CLI & Web) : communiquent uniquement via gRPC  
