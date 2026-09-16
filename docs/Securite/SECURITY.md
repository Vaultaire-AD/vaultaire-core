# Politique de Sécurité – Vaultaire Core

## 🟢 Versions supportées

| Version | Statut |
| ------- | ------ |
| Alpha 2.0.0+ | ✅ Maintenue |
| Alpha 1.1.x | ⚠️ Non maintenue — deux élévations de privilèges corrigées en 2.0.0, mise à jour requise |
| Alpha < 1.1 | ❌ Abandonnée |

Le détail des correctifs de sécurité est dans [`../Version/2.0/2.0.md`](../Version/2.0/2.0.md).

---

## 🛡️ Objectifs de sécurité

- Protection des identités et permissions  
- Intégrité des communications (TLS/LDAPS)  
- Prévention des accès non autorisés  
- Auditabilité et traçabilité des actions  
- Limitation des risques liés aux bugs connus

---

## ⚠️ Limitations actuelles

- **Linux uniquement.** Windows et macOS ne sont ni supportés ni prévus : l'agent
  repose sur des modules PAM et NSS
- **Pas d'atomicité sur les actions groupées** du portail : un lot partiellement
  appliqué est signalé dans le message, pas annulé
- Une injection shell reste possible dans la gestion du groupe sudo — des constats
  de l'audit `Audit_Client_SDK_PAM` restent ouverts
- **Les clés SSH ne sont rafraîchies qu'à la connexion.** `authorized_keys` est
  réécrit à chaque ouverture de session à partir de ce que rend l'annuaire, y
  compris quand il ne reste aucune clé. Rien ne le réécrit entre deux connexions :
  une clé révoquée reste donc en place jusqu'à la suivante, et une session déjà
  ouverte n'est pas interrompue. Le kill switch est le seul moyen de fermer un
  compte immédiatement
- **Le certificat du portail web n'a ni CommonName ni SAN** :
  `security.GenerateSelfSignedCertPEM` n'en pose pas. Le navigateur affiche un
  avertissement contournable là où la JVM refuse net — corrigé pour LDAPS, pas
  pour le web
- **Aucune limitation de débit sur l'API.** Le portail web, le bind LDAP, la trame
  Ducky `02_03` et l'authentification PAM/SSH partagent désormais des compteurs
  communs ; l'API n'y est pas raccordée
- **Les comptes dormants restent en SHA-256.** Les mots de passe sont hachés en
  argon2id, et une empreinte héritée est réencodée à la première connexion
  réussie — la seule migration possible, puisqu'on ne peut pas recalculer une
  empreinte forte à partir d'une faible. Un compte qui ne se connecte jamais
  garde donc son ancienne empreinte, et la lecture de ce format ne peut pas être
  retirée à une date fixée d'avance sans l'enfermer dehors
- **Le mot de passe arrive en clair au serveur** sur les quatre chemins
  d'authentification — à l'intérieur de TLS, de LDAPS ou de la session Ducky
  chiffrée, mais visible d'un serveur compromis. Seul un PAKE augmenté (OPAQUE,
  SRP) supprimerait cela
- La configuration de référence livre des identifiants de démonstration
  (`root`/`root`, `admin`/`admin123`) : à changer avant toute exposition

---

## 📝 Signaler une vulnérabilité

1. Ouvrir une **issue privée** avec `[SECURITY]`  
2. Décrire la vulnérabilité : version, reproduction, logs  
3. Gravité estimée (Low / Medium / High / Critical)  
4. Optionnel : proposer patch/test

**Engagement Vaultaire** :

- Accusé de réception sous 72h  
- Évaluation et priorisation  
- Correction via preprod ou patch dédié  
- Publication sécurisée après validation

---

## 🔒 Scope pour les tests

**Autorisé** :

- LDAP / LDAPS (auth, permissions)  
- CLI (vaultaire_client / vaultaire_ctl)  
- Webadmin (interface ALPHA)  
- Communications serveur → client  
- Déploiements Docker / configs

**Interdit** :

- Accès aux infrastructures Vaultaire externes  
- Exploitation de vulnérabilités non reproductibles localement  
- Actions provoquant perte de données ou indisponibilité pour d’autres utilisateurs

---

## 🔑 Bonnes pratiques

- Tester dans un environnement isolé  
- Ne pas utiliser d’identifiants réels d’entreprise  
- Respecter confidentialité des logs et données  
- Documenter les tests  
- Prioriser les versions maintenues

---

## 📅 Historique des patchs

Voir [docs/Version_History.md] pour les correctifs récents :
- Permissions client  
- Timeout & crash serveur  
- Authentification LDAPS  
- Patch DuckyNetwork

---

## ⚡ Note finale

Vaultaire est **en phase ALPHA**.  
Cette politique sera renforcée avec :  
- Pentests externes contrôlés  
- Tests unitaires & CI sécurité  
- Intégration des retours contributeurs
