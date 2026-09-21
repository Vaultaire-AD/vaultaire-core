[⌂ Ducky Network](../README.md) › [Chapitre 8 — Authentification par un service (08)](./README.md) › 8.4

# 8.4 — Brancher un nouveau service

[← Ordre des contrôles et sécurité](./03-controles-et-securite.md) · [Retour à l'index →](../README.md)

---

Pour qu'un nouveau service vérifie ses utilisateurs par le core. Le guide
complet de création d'un service est [`Nouveau_service.md`](../../Nouveau_service.md).

## 1. Côté core — le catalogue

Dans `core/clienttype/clienttype.go`, l'entrée du type :

```go
Frames: []string{
    "01_01", "01_05", "01_07",
    "02_01", "02_03", "02_05", "02_12",
    "04_09", "04_12", "04_14",
    "08_01", "08_04",               // vérifier et relire des comptes
},
UserRights: []string{"read:monservice", "write:monservice"},
AssertsUser: false,
```

Les clés de `UserRights` doivent être des **actions spéciales globales**
déclarées dans `core/permission/isValidAction.go` — un test
(`TestUserRightsDuCatalogueSontDesClesConnues`) le vérifie. Liste vide : le
service vérifie des comptes sans rien apprendre de leurs droits.

## 2. Côté service — le SDK

```go
// avant toute émission
tramesmanager.RegisterHandler("08", func(t storage.Trames_struct_client, _ *storage.DuckySession) string {
    code := t.Message_Order[0] + "_" + t.Message_Order[1]   // "08_02", "08_03"…
    livrer(champs(t.Content)["ref"], code, t.Content)          // à la demande en attente
    return ""
})

// une demande
lignes := []string{"08_01", "serveur_central", cleDeSession, "vaultaire", storage.Computeur_ID,
    identifiant, motDePasse, "otp:" + code, "from:" + ip, "ref:" + ref}
sendmessage.SendMessage(strings.Join(lignes, "\n"), session.DuckySession)
```

Implémentation complète et testée : `src/vaultaire_nexus/internal/clusterlink/serviceauth.go`
(file d'attente par `ref`, délai, traduction des codes en erreurs).

## 3. Les règles à respecter

| Règle | Pourquoi |
|---|---|
| Refuser un mot de passe contenant un saut de ligne **avant** l'envoi | il décalerait les champs |
| Toujours envoyer `ref:` et vérifier `user:` dans la réponse | pas d'identifiant de requête dans le protocole |
| `mfa_required` n'est **pas** un échec | c'est l'étape normale : afficher le champ du code |
| Ne pas renvoyer le mot de passe au navigateur entre les deux étapes | le garder en mémoire côté service, peu de temps (Nexus : 2 min, 3 essais) |
| Relire les comptes actifs (`08_04`) au plus tous les `ttl:` | un retrait de droit ou une révocation doit se voir sans reconnexion |
| Traiter `unavailable` comme passager | garder l'identité précédente, ne pas déconnecter tout le monde |
| Les clients sans saisie (docker, dnf, apt) utilisent des **jetons** du service | ils ne peuvent pas saisir de code TOTP |

## 4. Accorder les droits

Dans l'interface d'administration : **Permissions → *permission* → Actions hors
matrice**, clé `read:monservice` → « Tous domaines ». En ligne de commande :

```bash
vlt update -pu depot-lecture read:nexus all
vlt add -gu Dev -p depot-lecture
```

Ces clés sont globales : `all` ou `nil`, jamais une liste de domaines.

---

[← Ordre des contrôles et sécurité](./03-controles-et-securite.md) · [Retour à l'index →](../README.md)
