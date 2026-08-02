# Audit global du serveur — base de données et interface web

Audit statique de `src/vaultaire_serveur`, ciblé sur les deux paquets demandés :
`core/database` (et ses cinq sous-paquets) et `core/web_serveur`.

Côté client, rien à signaler qui n'ait déjà été traité.

Aucune compilation ni exécution n'a été possible : tout ce qui suit est un
constat de lecture, avec chemin et ligne.

---

## Récapitulatif

| # | Gravité | Où | Constat | État |
|---|---------|-----|---------|------|
| 11 | **Critique** | Ducky | Le chemin `04_01` contourne l'authentification et désarme le contrôle d'ordre des trames | **Ouvert — reporté** |
| 7 | **Faible** | database | Même requête recopiée dans 10 fonctions, alors que le helper existe | Ouvert |
| 8 | **Faible** | database | Doublons fonctionnels et nommage incohérent | Ouvert |
| 10 | **Note** | web | `web_admin_pages.go` fait 1314 lignes et mélange sept domaines | Ouvert |

> La numérotation vient des audits successifs ; les points corrigés ont été
> retirés. Le **11** est repris de l'audit des quatre points d'entrée
> (`Audit_Permissions.md`) : il y était reporté au motif que la catégorie 04 est
> expérimentale, et il le reste. Sa portée a en revanche changé depuis, et
> l'analyse ci-dessous est à jour.
>
> Les points **7, 8 et 10** sont de la dette technique sans conséquence de
> sécurité immédiate, laissés de côté à la demande.

---

## 11. Critique — `04_01` contourne l'authentification (reporté)

> **Décision : la catégorie 04 est expérimentale, à traiter avec le sujet
> cluster.** Conservé ici pour que le travail ne reparte pas de zéro, et parce
> que le report est une décision, pas un oubli.

**Chemins :** `ducky-network/networkSecurity/CheckIntegrity.go:19-21`,
`ducky-network/sessionmgr/trames.go:82`,
`ducky-network/host_handler/handler.go:66`

### Le mécanisme

Trois éléments se combinent, et aucun n'est fautif isolément.

**1. Rien n'est authentifié avant `02_01`.** C'est là, et seulement là, que
`duckysession.IsSafe` passe à `true` (`ClientAuthManager.go:16`). Avant ce
point, `MessageReader` déchiffre les trames entrantes avec la **clé privée du
serveur** :

```go
if duckysession.IsSafe {
    messageDecrypt, err = DecryptAESGCMString(duckysession.SessionKey, messageBuf)
} else {
    messageDecrypt, err = DecryptMessageWithPrivate(privateKeyStr, messageBuf)  // ← ici
}
```

Or la clé publique du serveur s'obtient sans aucune authentification, en
envoyant `askkey` sur le socket. **N'importe qui peut donc fabriquer une trame
que le serveur déchiffrera**, tant que `IsSafe` est faux.

**2. `04_01` est atteignable juste après `01_01`.**

```go
// CheckIntegrity.go
if lastTrame == "01_01" && newTrame == "04_01" { return true }
```

Et `01_01` n'authentifie personne : `Prove_Identity` se contente de renvoyer le
contenu reçu.

**3. `04_01` désarme le contrôle d'ordre pour le reste de la session.**

```go
// trames.go
if newTrame == "04_01" { s.TrameIsSafe = true }
```

Or `UpdateConnectionTrame` commence par `if s.TrameIsSafe { return nil }` :
au-delà, plus aucune trame n'est vérifiée dans son ordre.

### Ce que ça permet encore aujourd'hui

**Écriture non authentifiée dans l'annuaire.** `handleRegisterHost` crée un
groupe et un domaine à partir de chaînes fournies dans la trame :

```go
_, err := database.GetGroupIDByName(db, groupName)
if err != nil {
    _, errCreate := database.CreateGroup(db, groupName, domain)
}
```

Séquence complète, sans le moindre identifiant :

```
1. connexion TCP au port Ducky
2. « askkey »                    → clé publique du serveur
3. 01_01, chiffrée avec cette clé → session amorcée
4. 04_01, chiffrée avec cette clé → groupe et domaine créés
```

S'y ajoutent l'enregistrement de nœuds cluster (`04_01`), les métriques proxy
(`04_05`) et les battements de cœur (`04_07`), tous inscriptibles de la même
façon.

**Conséquence indirecte sur le RBAC, la moins visible et la plus gênante.** Le
projet a corrigé en Alpha 2.0.0 le fait qu'un droit accordé sur un domaine
inexistant ou mal orthographié passait quand même ; la vérification de
l'existence réelle du domaine a été ajoutée. Mais si un attaquant peut **créer**
un domaine, il peut rendre valide un droit qui ne l'était pas : une permission
portant `write:delete:user` sur `vault.fr` — faute de frappe pour
`vaultaire.fr` — devient effective le jour où quelqu'un crée `vault.fr`.

### Ce qui a été refermé entre-temps

L'audit initial décrivait une chaîne bien plus large : lecture des GPO de
n'importe quelle machine, du sel de n'importe quel utilisateur, de ses clés
publiques. **Ce volet est fermé**, par un correctif qui ne visait pas
directement celui-ci : le `ClientSoftwareID` est désormais figé à `01_01` et
vérifié à chaque trame.

Le raisonnement tient à la façon dont les réponses sont chiffrées. Tant que
`IsSafe` est faux, `SendMessage` chiffre avec la **clé publique du client
annoncé** :

| L'attaquant annonce… | Ce qui se passe |
|----------------------|-----------------|
| l'ID d'une machine qu'il ne possède pas | il ne peut pas déchiffrer les réponses — pas de fuite |
| un ID inexistant | le chiffrement échoue, aucune réponse n'est émise |
| son propre ID légitime | il lit les réponses, mais la liaison le cantonne à **ses** données |

Autrement dit, il reste **une écriture non authentifiée, sans lecture**. La
gravité passe de « divulgation de la configuration du parc » à « pollution de
l'annuaire », ce qui reste critique mais change la nature du risque.

### Correction proposée

Ne poser `TrameIsSafe` qu'après une authentification réellement établie. Le
chemin host a besoin de la sienne — un secret de nœud, ou le même challenge que
les clients — et le raccourci `01_01 → 04_01` devrait disparaître.

En attendant, une atténuation qui coûte peu : refuser `CreateGroup` depuis
`handleRegisterHost` et exiger que le groupe existe déjà. Un hôte s'enregistre
alors dans une structure qu'un administrateur a préparée, au lieu de la
fabriquer lui-même.

---

## 7. Faible — la même requête recopiée dans dix fonctions

Analyse des requêtes identiques sur les 84 fichiers du paquet :

| Occurrences | Requête | Helper existant |
|-------------|---------|-----------------|
| **10** | `SELECT id_group FROM groups WHERE group_name = ?` | `GetGroupIDByName` (`Command_CREATE_Groups.go`) |
| **7** | `SELECT id_user FROM users WHERE username = ?` | `Get_User_ID_By_Username` (`GetUserIDByUsername.go`) |
| **4** | `SELECT id_logiciel FROM id_logiciels WHERE computeur_id = ?` | `Get_ClientID_By_ComputerID` |
| 3 | `SELECT id_permission FROM client_permission WHERE name_permission = ?` | — |
| 2 | `SELECT count(*) FROM logiciel_group WHERE ...` | — |
| 2 | `SELECT count(*) FROM users_group WHERE ...` | — |

Les trois premières ont **déjà un helper dédié**, simplement pas utilisé. Le
paquet `db_gpo` a même reconstruit le sien (`groupIDByName`, `group_link.go:…`)
plutôt que d'appeler l'existant.

Ce n'est pas qu'une question d'esthétique : ces copies ne se comportent pas
toutes pareil. Certaines appellent `SanitizeIdentifier`, d'autres non ; certaines
distinguent `sql.ErrNoRows` d'une vraie erreur, d'autres retournent la même chose
dans les deux cas. Un durcissement posé sur le helper — comme celui que je viens
d'ajouter — ne protège donc que le tiers des appels.

---

## 8. Faible — doublons fonctionnels et nommage

**Doublons à départager :**

| Fonctions | Fichier |
|-----------|---------|
| `Command_STATUS_GetConnectedUser` / `…Users` | `Command_STATUS_GetAllUserLogin.go` — même requête, l'une filtrée par username |
| `Command_GET_UsersByGroup` / `Command_STATUS_GetUsersByGroup` | deux fichiers, types de retour différents pour la même question |
| `GetUsersByGroup` / `GetUsersByGroups` | `LDAP_GET_GetUsersData.go` |
| `GetGroupWithUsersByName` / `GetGroupsWithUsersByNames` | `LDAP_GET_GetGroupWithUser.go` |
| `GetGroupIDByName` / `groupIDByName` | paquet racine / `db_gpo` |

**Nommage :** sept conventions coexistent sur 191 fonctions — `Command_GET_`,
`Command_STATUS_`, `Command_ADD_`, `Command_Remove_` (casse mixte),
`Get_User_ID_By_Username` (souligné), `GetUserByUsername` (camel), et 114
fonctions sans préfixe. Deux fichiers portent `Comment_` au lieu de `Command_`
(`Comment_SET_UserPermissionActionContent.go`).

Aucune conséquence fonctionnelle, mais c'est ce qui explique le point 7 : on ne
trouve pas le helper existant, donc on le réécrit.

---

## 10. Note — `web_admin_pages.go` fait 1314 lignes

Le fichier contient les handlers des utilisateurs, groupes, clients,
permissions, certificats, logs et cluster. Le seul `AdminUsersHandler` fait plus
de 250 lignes et mélange vue liste, vue détail et sept actions POST.

Ce n'est pas un défaut de sécurité, mais c'est ce qui a rendu invisibles les
points 1 et 2 : dans un fichier de cette taille, l'absence d'un filtre par
domaine ne saute pas aux yeux.

Découpage suggéré, un fichier par section — le paquet suit déjà ce modèle pour
`web_admin_gpo.go`, `web_admin_dns.go` et `web_admin_tree.go`.

---
