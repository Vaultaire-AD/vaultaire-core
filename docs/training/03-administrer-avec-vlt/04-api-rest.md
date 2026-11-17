[⌂ Formation](../README.md) › [Chapitre 3 — Administrer Vaultaire via vlt](./README.md) › Jalon 3.4

# Jalon 3.4 — L'API REST

[← Le portail web](./03-portail-web.md) · [Chapitre 4 — Permissions et délégation →](../04-permissions-et-delegation/README.md)

---

## Objectif

Piloter Vaultaire depuis un script ou un autre programme, avec des réponses en
JSON — sans rien apprendre de nouveau sur les droits : l'API REST appelle les
mêmes actions que `vlt`.

## Ce qu'il faut savoir

- Les routes sont sous `https://<IP>:6643/api/v1/`, le port de `vlt` à distance.
- L'authentification est **la même** : la clé SSH de votre compte, celle du
  [jalon 3.2](./02-vlt-a-distance.md). `vlt api` signe pour vous.
- Toute réponse a la même forme : `ok`, `action`, `message`, `data` — ou
  `error.code` sur un échec (`forbidden`, `not_found`, `action_failed`…).
- Ce qui a une route lisible (`/users`, `/groups`, `/clients`, `/permissions`,
  `/gpos`, `/domains`), ce qui n'en a pas s'appelle par son nom
  (`/actions/<action>`), et le reste par la commande (`/command`).
- Référence complète : [`API_REST.md`](../../Utilisation/API_REST.md).

## Étapes

1. Lisez la description de l'API — elle est publique :

   ```bash
   vlt api GET /api/v1/openapi.json | head -30
   ```

2. Listez les comptes, puis un groupe et ses membres :

   ```bash
   vlt api GET /api/v1/users
   vlt api GET /api/v1/groups/Infra
   vlt api GET /api/v1/groups/Infra/users
   ```

3. Créez un groupe, un compte, et rattachez-le :

   ```bash
   vlt api POST /api/v1/groups '{"group":"Labo","domain":"infra.acme.lan"}'
   vlt api POST /api/v1/users '{"username":"lea.blanc","domain":"infra.acme.lan",
     "password":"Corail-Vent-Ruche-42","birthdate":"12/12/1995"}'
   vlt api PUT /api/v1/groups/Labo/users/lea.blanc
   vlt get -u lea.blanc            # le même compte, vu par la commande
   ```

4. Exploitez la sortie dans un script — ici avec `jq` :

   ```bash
   vlt api GET /api/v1/users | jq -r '.data[].username'
   ```

5. Une action sans route lisible, puis une commande :

   ```bash
   vlt api GET /api/v1/actions | jq -r '.data[] | "\(.method) \(.name)"' | head
   vlt api GET /api/v1/actions/settings.list
   vlt api POST /api/v1/command '{"command":"status -c"}' | jq -r .data.output
   ```

## ✅ Vous avez réussi si

`lea.blanc` existe dans `Labo`, créée par l'API et visible avec `vlt get -u` ;
le journal du serveur porte des lignes `api rest:` à votre nom.

## 🧪 Exercice

Avec le compte d'Alice (chapitre 4, quand il sera délégué à `infra.acme.lan`),
`vlt api POST /api/v1/users` sans `group` est refusé. Que dit la réponse, et
comment la corriger ?

<details><summary>Solution</summary>

Statut **403**, `error.code` = `forbidden`, `error.key` = `write:create:user` :
sans groupe, le compte n'aurait aucun domaine, et le droit est exigé sur `*`.
Ajouter `"group": "Infra"` (un groupe de son domaine) : la création devient
déléguée, comme `vlt create -u … -g Infra`. L'API n'ouvre aucun droit que la
commande n'ouvrait pas.
</details>

> 🔐 `vlt api --headers` produit les en-têtes signés pour `curl` : ils sont
> valables deux minutes et **une seule fois**.

---

[← Le portail web](./03-portail-web.md) · [Chapitre 4 — Permissions et délégation →](../04-permissions-et-delegation/README.md)
