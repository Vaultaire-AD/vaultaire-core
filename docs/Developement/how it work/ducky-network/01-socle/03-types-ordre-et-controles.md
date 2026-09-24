[⌂ Ducky Network](../README.md) › [Chapitre 1 — Le socle : canal, format, contrôles](./README.md) › 1.3

# 1.3 — Types de client, ordre et contrôles

[← Format des trames](./02-format-des-trames.md) · [Chapitre 2 — Authentification et enrôlement (01, 02) →](../02-authentification-et-enrolement/README.md)

---

Une trame reçue par le core franchit trois contrôles **avant** d'atteindre son
gestionnaire. Ils vivent dans `ducky-network/trames_manager/Spliter.go` et
`ducky-network/sessionmgr/`.

## 1. La machine annoncée est celle de la session

Chaque trame client porte un `client_software_id` en en-tête. Il doit être égal à
celui figé sur la connexion lors de `01_01` (`BoundClientSoftwareID`). Sinon la
trame est refusée : un client authentifié ne peut pas parler au nom d'une autre
machine.

## 2. Le type du client autorise la trame

Le type du client (`vaultaire_client`, `vaultaire_proxy`, `vaultaire_web`,
`vaultaire_nexus`…) est lu en base au moment de `01_01` et figé sur la session
(`BoundClientType`). `clienttype.MayEmit(type, "CC_SS")` décide ensuite, trame par
trame.

- **Fail-closed** : un type inconnu n'émet rien ; une sous-trame non déclarée
  n'est émise par personne.
- **Granularité à la sous-trame** : on déclare `02_12`, pas « la catégorie 02 ».
- Un refus **ferme la connexion** et laisse une ligne `SECURITY` qui nomme le type
  et la trame.

Le catalogue est du **code** (`core/clienttype/clienttype.go`), pas de la
donnée : c'est une frontière de privilège.

| Type | Famille | Trames émises |
|---|---|---|
| `vaultaire_client` | agent | `01_01` · `02_01 02_03 02_05 02_12` · `03_01 03_04 03_06 03_08` · `04_03` · `05_01 05_05 05_09 05_12 05_15` · `06_02 06_03 06_04` |
| `vaultaire_proxy` | service | `01_01 01_05 01_07` · `02_01 02_03 02_05 02_12` · `04_01 04_03 04_05 04_07 04_15` |
| `vaultaire_web` | service | `01_01 01_05 01_07` · `02_01 02_03 02_05 02_12` · `04_09 04_12 04_14` · `07_01 07_04` — **porte `AssertsUser`** |
| `vaultaire_nexus` | service | `01_01 01_05 01_07` · `02_01 02_03 02_05 02_12` · `04_09 04_12 04_14` · `08_01 08_04` — apprend `read:nexus write:nexus write:nexus_admin` |

`vlt enroll types` affiche ce tableau depuis le code.

### Les trames d'avant l'identité

`01_01`, `01_05` et `01_07` échappent au contrôle par type (`preAuthTrame`) :
`01_01` **établit** le type, `01_05` et `01_07` précèdent l'existence même du
client. C'est la clé d'enrôlement qui autorise ces deux dernières.

## 3. L'ordre des trames

Tant qu'une session n'est pas « sûre », seule la séquence attendue passe
(`networkSecurity/CheckIntegrity.go`) :

```
01_01  →  02_01  →  02_03        la session devient sûre (TrameIsSafe)
01_01  →  04_01                  chemin d'un hôte qui s'enregistre
```

Une fois la session sûre, l'ordre n'est plus contrôlé : les catégories 03 à 08
arrivent dans l'ordre que le client choisit.

## 4. La répartition

| Catégorie | Gestionnaire (core) |
|---|---|
| `01` | `authentification/serveur` — `Serveur_Auth_Manager` |
| `02` | `authentification/client` — `Client_Auth_Manager` |
| `03` | `authentification/ssh` — `SSH_Client_Manager` |
| `04` | `host_handler` — `HandleHostTrame` |
| `05` | `gpo_manager` — `GPO_Trame_Manager` |
| `06` | `revocation_manager` — `Revocation_Trame_Manager` |
| `07` | *aucun* — voir le chapitre 7 |
| `08` | `serviceauth` — `Trame_Manager` |

Côté clients services, le SDK (`src/ducky-network-sdk-service`) répartit les
réponses par catégorie : `tramesmanager.RegisterHandler("08", …)`. Un service
branche ses gestionnaires **avant** d'émettre, sinon une réponse rapide arrive
sans destinataire.

## Ajouter une trame : la liste

1. Choisir le numéro : la demande et ses réponses sont **contiguës**, et la plage
   de la catégorie est notée dans son chapitre.
2. Écrire le gestionnaire (core) et le brancher dans `Spliter.go` si la catégorie
   est nouvelle.
3. Déclarer la sous-trame dans le catalogue, pour **chaque** type qui l'émet.
4. Écrire les réponses avec `trame.ReponseClient` (en-tête serveur → client à
   3 lignes).
5. Tester le refus par type (`clienttype_test.go`) et le gestionnaire.
6. Documenter la trame dans ce dossier.

---

[← Format des trames](./02-format-des-trames.md) · [Chapitre 2 — Authentification et enrôlement (01, 02) →](../02-authentification-et-enrolement/README.md)
