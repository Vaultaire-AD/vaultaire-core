# Migration — catalogue des types de clients

**À exécuter AVANT de déployer un core qui applique le catalogue.**
Sans elle, des machines qui fonctionnaient cessent de se connecter.

## Le problème

pour resume :
```sh
docker exec -i -e APPLY=1 vaultaire-db sh < deployments/pre-prod/scripts/migrate-clienttype.sh
```

`id_logiciels.logiciel_type` a longtemps été un `VARCHAR(255)` libre. Rien ne le
validait, rien n'en dépendait : le formulaire web proposait « client » en simple
exemple, et le fichier de configuration du dépôt porte `logiciel_type:
administration`.

Le catalogue (`core/clienttype`) le transforme en frontière de privilège, et il
est **fail-closed** : un type absent du catalogue n'émet **rien**.

C'est le bon défaut — une sous-trame ajoutée au protocole reste interdite tant
que personne ne l'a déclarée. Mais appliqué à une base existante, il coupe les
clients dont le type a été saisi à la main.

## Le symptôme, si la migration est oubliée

Côté core :

```
[WARNING] trame 02_01 refusée : la machine "XXXX-06-08-2026" est de type
          "administration", qui n'a pas le droit de l'émettre
[INFO   ] Connection closed
```

Côté client, rien d'explicite : la connexion s'ouvre, le serveur s'authentifie,
puis le flux s'arrête sur un `EOF`. **L'agent ne dit pas que son type est en
cause** — il ne le sait pas.

## 1. Diagnostic

```sql
SELECT logiciel_type, COUNT(*) AS clients
FROM id_logiciels
GROUP BY logiciel_type
ORDER BY clients DESC;
```

Les seules valeurs acceptées sont :

| Valeur | Famille | Créé par |
|--------|---------|----------|
| `vaultaire_client` | agent | `vlt create -c` sur le core |
| `vaultaire_proxy` | service | enrôlement (01_05 → 01_08) |
| `vaultaire_web` | service | enrôlement (01_05 → 01_08) |

Toute autre valeur — `administration`, `client`, une chaîne vide, une faute de
frappe — désigne un **agent** : avant le catalogue, seuls les agents existaient.
Les services ne peuvent être créés que par l'enrôlement, qui écrit lui-même une
valeur du catalogue.

## 2. Vérification avant écriture

Regardez ce qui va changer, et confirmez qu'il ne s'agit que d'agents :

```sql
SELECT computeur_id, logiciel_type, hostname, serveur
FROM id_logiciels
WHERE logiciel_type NOT IN ('vaultaire_client', 'vaultaire_proxy', 'vaultaire_web');
```

Si une ligne vous semble être un service, **ne la migrez pas en agent** :
corrigez-la à la main vers son vrai type. Un service basculé en
`vaultaire_client` obtiendrait les catégories 03, 05 et 06 — GPO, SSH,
révocations — qui n'ont aucun sens pour lui.

## 3. Migration

```sql
UPDATE id_logiciels
   SET logiciel_type = 'vaultaire_client'
 WHERE logiciel_type NOT IN ('vaultaire_client', 'vaultaire_proxy', 'vaultaire_web');
```

## 4. Contrôle

```sql
SELECT logiciel_type, COUNT(*) FROM id_logiciels GROUP BY logiciel_type;
```

Il ne doit plus rester que les trois valeurs du catalogue.

## 5. Côté machines

Le fichier `client_software.yaml` de chaque agent porte lui aussi un
`logiciel_type`. **Il n'entre dans aucune décision** : le core lit le type en
base, jamais celui que le client annonce — sinon il suffirait de modifier un
fichier local pour changer ses privilèges.

Le corriger sur les machines n'est donc pas nécessaire, seulement plus propre.
Les nouvelles installations reçoivent la bonne valeur automatiquement.

## Pourquoi ne pas avoir mis d'alias

Accepter `administration` comme synonyme de `vaultaire_client` aurait évité cette
migration. Mais un alias ne se retire jamais : il faudrait le maintenir
indéfiniment, et chaque valeur libre trouvée en base ajouterait la sienne. Le
catalogue redeviendrait ce qu'il remplace — une liste ouverte de chaînes dont
personne ne sait plus laquelle est la bonne.

Une migration se fait une fois. Un alias se paie à chaque lecture du code.
