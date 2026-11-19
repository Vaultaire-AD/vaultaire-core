[⌂ Accueil du dépôt](../../README.md) · [Index de la documentation](../README.md) · [Actions et permissions](./Actions_et_Permissions.md) · [vaultairectl](./vaultairectl.md)

# API REST *(2.3.2)*

L'API REST est une **interface** sur le registre d'actions de Vaultaire, pas une
gestion de plus. Chaque route appelle **l'action que la commande `vlt` appelle
pour le même geste** : mêmes droits, même portée par domaine, mêmes listes
filtrées, même journal d'audit. Ce qui change, c'est la forme : des routes HTTP,
des paramètres en JSON, et des réponses en **JSON structuré** au lieu du texte
mis en forme pour un terminal.

| | |
|---|---|
| Adresse | `https://<core>:6643/api/v1/…` — le port de l'API (`api.api_port`), le même que `/api/command` |
| Authentification | la **clé SSH du compte**, comme `vlt` à distance — aucun jeton à gérer |
| Description | `GET /api/v1/openapi.json` (OpenAPI 3.0, générée, sans authentification) |
| Client | `vlt api <MÉTHODE> <chemin> [corps]` — signe et envoie |

---

## 1. Premier appel

Avec un `vlt` déjà configuré (formation, [jalon 3.2](../training/03-administrer-avec-vlt/02-vlt-a-distance.md)) :

```bash
vlt api GET /api/v1/users
```

```json
{
  "ok": true,
  "action": "user.list",
  "message": "3 utilisateur(s).",
  "data": [
    { "id_user": 1, "username": "admin", "email": "admin@vaultaire.fr", "date_naissance": "…", "created_at": "…" },
    …
  ]
}
```

Créer un compte, dans un groupe (création déléguée, voir
[Actions et permissions](./Actions_et_Permissions.md)) :

```bash
vlt api POST /api/v1/users '{
  "username": "carla.martin", "domain": "users.admin.local",
  "password": "Sable-Lynx-Fjord-38", "birthdate": "03/04/1991",
  "group": "admin-users"
}'
```

Choisir l'adresse e-mail *(2.3.3)* — à la création (`"email"` dans le corps
ci-dessus), ou ensuite :

```bash
vlt api PATCH /api/v1/users/carla.martin '{"email": "carla.martin@acme.fr"}'
vlt api PATCH /api/v1/users/carla.martin '{"email": "auto"}'   # retour à compte@domaine
```

`GET /api/v1/users/{username}` rend l'adresse (`email`) et sa nature
(`email_custom` : `true` si elle a été choisie). Une adresse déjà portée par un
autre compte est refusée (**422** `action_failed`, sans nommer ce compte).

Les paramètres portent **les mêmes noms** que les champs du portail et les
paramètres des actions. Un booléen JSON vaut `oui`/`non` (`"temporary": false`
pour un mot de passe définitif).

---

## 2. Les réponses

Toutes les réponses — succès comme erreurs — ont la même enveloppe :

| Champ | |
|---|---|
| `ok` | `true` / `false` |
| `action` | l'action du registre appelée (`user.create`…) |
| `message` | le message de l'action, celui qu'affiche `vlt` |
| `data` | les données de l'action, **toujours présent** sur un succès (`null` si l'action n'en rend pas) |
| `error` | sur un échec : `code`, `message`, et selon le cas `key`, `replay` |
| `request_id` | l'en-tête `X-Request-ID` reçu, renvoyé tel quel |

`data` est le résultat de l'action, converti en JSON propre :

- les champs sont en `snake_case` (`GroupName` → `group_name`, `UserID` → `user_id`) ;
- les **clés** d'un dictionnaire (un nom de compte, un domaine) ne sont jamais renommées ;
- une liste vide vaut `[]`, jamais `null` ; une date est en RFC 3339 ;
- une liste est **réduite au périmètre** de l'appelant, comme `vlt get`.

### Codes d'erreur

Le `code` est stable : c'est lui qu'un programme aiguille ; le `message` est pour un humain.

| Statut | `code` | Quand |
|---|---|---|
| 400 | `bad_request` | corps qui n'est pas un objet JSON ; paramètre du chemin contredit par le corps |
| 401 | `unauthenticated` | signature absente ou fausse, compte inconnu, révoqué ou sans clé (un seul message pour tous), horodatage hors fenêtre, nonce rejoué |
| 403 | `forbidden` | droit refusé ; `key` nomme le droit manquant (`write:create:user`) |
| 404 | `not_found` | route inconnue, ou objet introuvable (« groupe … introuvable ») |
| 404 | `unknown_action` | `/actions/{action}` : action absente du registre |
| 405 | `method_not_allowed` | une écriture demandée en `GET` sur la route générique |
| 409 | `confirmation_required` | l'action demande confirmation ; `replay` donne les paramètres à renvoyer (avec `confirm`) |
| 413 | `payload_too_large` | corps de plus de 64 Kio |
| 422 | `action_failed` | l'action a refusé (mot de passe trop faible, date invalide…) — le message dit pourquoi |
| 429 | `too_many_requests` | débit dépassé (`api.limite_rafale`, `api.limite_par_seconde`) ; `Retry-After` dit quand revenir |

---

## 3. Les routes

### Ressources

| Méthode | Chemin | Action |
|---|---|---|
| GET | `/api/v1/users` | `user.list` |
| POST | `/api/v1/users` | `user.create` — `username`, `domain`, `password`, `birthdate`, [`firstname`, `lastname`, `temporary`, `group`, `email`] |
| GET | `/api/v1/users/{username}` | `user.get` |
| PATCH | `/api/v1/users/{username}` | `user.update` — `new_username`, `firstname`, `lastname`, `email` (`"auto"` : retour à `compte@domaine`) |
| DELETE | `/api/v1/users/{username}` | `user.delete` |
| PUT | `/api/v1/users/{username}/password` | `user.change_password` — `password`, [`temporary`] |
| DELETE | `/api/v1/users/{username}/mfa` | `user.reset_mfa` |
| GET · POST | `/api/v1/users/{username}/keys` | `user.list_keys` · `user.add_key` (`key`, `label`) |
| DELETE | `/api/v1/users/{username}/keys/{key_id}` | `user.remove_key` |
| GET · POST | `/api/v1/groups` | `group.list` · `group.create` (`group`, `domain`) |
| GET · DELETE | `/api/v1/groups/{group}` | `group.get` · `group.delete` |
| PUT | `/api/v1/groups/{group}/mfa` | `group.set_mfa_required` (`mfa_required`) |
| GET | `/api/v1/groups/{group}/users` | `group.list_users` |
| PUT · DELETE | `/api/v1/groups/{group}/users/{username}` | `group.add_user` · `group.remove_user` |
| GET | `/api/v1/groups/{group}/clients` | `group.list_clients` |
| PUT · DELETE | `/api/v1/groups/{group}/clients/{computeur_id}` | `group.add_client` · `group.remove_client` |
| PUT · DELETE | `/api/v1/groups/{group}/permissions/{permission}` | `group.add_permission` · `group.remove_permission` |
| PUT · DELETE | `/api/v1/groups/{group}/client-permissions/{client_permission}` | `group.add_client_permission` · `…remove…` |
| PUT · DELETE | `/api/v1/groups/{group}/gpos/{gpo}` | `group.add_gpo` · `group.remove_gpo` |
| GET | `/api/v1/domains` · `/api/v1/domains/{domain}/groups` | `domain.list_tree` · `domain.list_groups` |
| GET · POST | `/api/v1/clients` | `client.list` · `client.create` (`is_serveur`) |
| GET · PATCH · DELETE | `/api/v1/clients/{computeur_id}` | `client.get` · `client.update` · `client.delete` |
| GET | `/api/v1/clients/{computeur_id}/compliance` | `gpo.get_compliance` |
| POST | `/api/v1/clients/{computeur_id}/gpo-refresh` | `gpo.refresh` (`motif`, `attendre`) |
| GET · POST | `/api/v1/permissions` | `permission.list` · `permission.create` (`name`, `web_admin`, `description`) |
| GET · DELETE | `/api/v1/permissions/{permission_name}` | `permission.get` · `permission.delete` |
| PATCH | `/api/v1/permissions/{permission_name}/actions` | `permission.update_action` (`field`, `op`, `domain`, `propagation`) |
| GET · POST | `/api/v1/client-permissions` | `client_permission.list` · `…create` (`name`, `is_admin`) |
| GET · PATCH · DELETE | `/api/v1/client-permissions/{permission_name}` | `client_permission.get` · `…update` · `…delete` |
| GET · POST | `/api/v1/gpos` | `gpo.list` · `gpo.create` (`name`, `scope`, `description`) |
| GET | `/api/v1/gpos/compliance` | `gpo.list_compliance` |
| GET · PATCH · DELETE | `/api/v1/gpos/{gpo}` | `gpo.get` · `gpo.update` · `gpo.delete` |
| POST | `/api/v1/gpos/{gpo}/modules` | `gpo.add_module` (`module_type` et ses paramètres) |
| PATCH · DELETE | `/api/v1/gpos/{gpo}/modules/{module_id}` | `gpo.update_module` · `gpo.delete_module` |

Les valeurs entre accolades sont des paramètres de l'action. Le **chemin désigne
la cible** : un corps qui donne une autre valeur au même paramètre est refusé
(`bad_request`).

### Toutes les actions : `/api/v1/actions/{action}`

Chaque action du registre — une centaine, DNS, cluster, réglages, MFA, enrôlement
compris — s'appelle par son nom :

```bash
vlt api GET  /api/v1/actions                                  # le catalogue : nom, droit, méthode
vlt api GET  /api/v1/actions/settings.list                    # une LECTURE : GET, paramètres en requête
vlt api POST /api/v1/actions/dns.add_record '{"zone":"acme.lan","name":"web","record_type":"A","data":"10.0.0.5"}'
```

Une écriture se fait en `POST` : en `GET`, elle est refusée (`method_not_allowed`).

### Les commandes : `/api/v1/command`

Pour ce qui n'est pas encore au registre (`status`, `eyes`, `logs`…), la
commande `vlt` elle-même ; sa sortie **texte** est dans `data.output` :

```bash
vlt api POST /api/v1/command '{"command":"status -c"}'
```

---

## 4. Authentification

Une requête est signée avec la clé SSH du compte (ed25519 ou RSA), celle de
`vlt` à distance (`add -u <compte> -k`). Aucun jeton, aucune session : chaque
requête porte sa signature.

```
Authorization: Vaultaire-SSH <signature>
X-Vaultaire-User: <compte>
X-Vaultaire-Timestamp: <secondes Unix>
X-Vaultaire-Nonce: <aléa>
```

La signature porte sur ces huit lignes, séparées par `\n`, sans saut final :

```
VAULTAIRE-REST-1
<MÉTHODE en majuscules>
<chemin, tel qu'envoyé>
<requête brute, sans « ? » — vide s'il n'y en a pas>
<compte>
<horodatage>
<nonce>
<SHA-256 du corps en hexadécimal minuscule — celui de la chaîne vide sans corps>
```

`<signature>` est la structure `ssh.Signature` sérialisée (`ssh.Marshal`), en
base64 standard — ce que rend `signer.Sign` en Go. Une requête est valable
**deux minutes**, et **une seule fois** (nonce mémorisé) : l'horloge du client
doit être à l'heure.

### Avec curl

`vlt api --headers` signe sans envoyer, et écrit les en-têtes :

```bash
CORPS='{"group":"compta","domain":"compta.local"}'
mapfile -t H < <(vlt api --headers POST /api/v1/groups "$CORPS")
curl --cacert ~/.vaultaire/api-cert.pem -X POST "https://<core>:6643/api/v1/groups" \
  "${H[@]/#/-H}" --data-raw "$CORPS"
```

Le corps doit être envoyé **octet pour octet** tel qu'il a été signé.

---

## 5. Ce qui ne change pas

- **Les droits** : un compte n'obtient rien de plus par l'API qu'avec `vlt`.
  L'authentification dit QUI appelle ; chaque action décide si elle le permet.
- **Le journal** : une ligne `api rest:` par appel (méthode, chemin, compte,
  action, statut — jamais le corps, qui peut porter un mot de passe), et la
  ligne d'audit de l'action pour toute écriture.
- **Les freins** : le débit par source et le frein des échecs répétés de
  `/api/command` s'appliquent aussi, avec les mêmes compteurs.
- **`/api/command`** reste en place, inchangée : les `vlt` déjà déployés
  continuent de fonctionner.
