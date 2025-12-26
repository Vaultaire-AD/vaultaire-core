
---

## `SECURITY.md` – Version ALPHA publique

```markdown
# Politique de Sécurité – Vaultaire Core

## 🟢 Versions supportées

| Version | Status |
| ------- | ------ |
| Alpha 1.1.3+ | ✅ Maintenue / support limitée |
| Alpha <1.1.3 | ⚠️ Ancienne version – patch recommandé |

---

## 🛡️ Objectifs de sécurité

- Protection des identités et permissions  
- Intégrité des communications (TLS/LDAPS)  
- Prévention des accès non autorisés  
- Auditabilité et traçabilité des actions  
- Limitation des risques liés aux bugs connus

---

## ⚠️ Limitations actuelles

- Linux uniquement (Rocky Linux)  
- SSH premier-login pour utilisateur privilégié : en cours de patch  
- username@domain : erreurs possibles sur certaines requêtes LDAP  
- WebAdmin fonctionnelle mais interface non sécurisée  
- Windows / macOS : non supporté

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
