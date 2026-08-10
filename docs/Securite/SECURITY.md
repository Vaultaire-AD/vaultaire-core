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
- **L'écriture d'`authorized_keys` par l'agent ne se protège pas des liens
  symboliques**, et une injection shell reste possible dans la gestion du groupe
  sudo — 17 constats de l'audit `Audit_Client_SDK_PAM` restent ouverts
- **Le certificat du portail web n'a ni CommonName ni SAN** :
  `security.GenerateSelfSignedCertPEM` n'en pose pas. Le navigateur affiche un
  avertissement contournable là où la JVM refuse net — corrigé pour LDAPS, pas
  pour le web
- **Aucune limitation de débit** sur l'authentification web, LDAP ou API
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
