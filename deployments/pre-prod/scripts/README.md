# Scripts pre-prod

Montés dans le conteneur `vaultaire-ad` sous `/opt/vaultaire/scripts`, en
lecture seule.

---

## `rbac_fixture.sh` — jeu d'essai RBAC

Construit une arborescence de domaines, groupes, permissions et utilisateurs où
**chaque compte isole un comportement du moteur de permissions**, puis produit
la matrice de vérification manuelle.

### Utilisation

```bash
docker exec -it vaultaire-ad /opt/vaultaire/scripts/rbac_fixture.sh
```

| Option | Effet |
|--------|-------|
| *(aucune)* | nettoie puis reconstruit le jeu d'essai, écrit le rapport |
| `--clean` | supprime le jeu d'essai et s'arrête |
| `--report-only` | régénère le rapport sans rien créer ni supprimer |
| `--keep` | construit sans nettoyer d'abord |

Le rapport est écrit dans `/opt/vaultaire/rbac_report.md`. Pour le récupérer :

```bash
docker cp vaultaire-ad:/opt/vaultaire/rbac_report.md .
```

Seules les entités préfixées `rbac_` sont touchées : un `--clean` ne peut pas
emporter de compte réel.

---

### Ce que le script vérifie, et ce qu'il ne peut pas vérifier

**À lire avant de s'en servir.**

Le socket local exécute toute commande sous l'identité `vaultaire`, sans
authentification. **Ce socket est un accès superadmin** — sa seule protection
est le mode `0600` du fichier.

Conséquence :

> **On ne peut pas tester un refus RBAC depuis le socket local.**
> Tout y passe, puisque tout y passe en superadmin.

Le script fait donc deux choses distinctes :

**1. Il provisionne et vérifie ce qui est vérifiable ici** — que les entités
existent, et surtout que les actions RBAC sont réellement **stockées** avec la
valeur voulue, propagation comprise. Ce n'est pas acquis : une clé d'action mal
orthographiée produit une permission qui ne s'appliquera jamais, sans que rien
ne le signale.

**2. Il produit une matrice de vérification manuelle** — pour chaque compte, son
mot de passe et la liste de ce qui doit marcher et de ce qui doit être refusé.
L'application effective se vérifie sur les chemins où l'appelant est un vrai
utilisateur soumis au RBAC :

| Chemin | Comment |
|--------|---------|
| Interface web | `https://<hôte>:4443` |
| LDAP | `ldapsearch -x -D "cn=<compte>,dc=..." -w <mot de passe>` |
| CLI distant | `vaultaire_ctl` avec la clé SSH du compte |

Automatiser le volet 2 supposerait de passer par `vaultaire_ctl` avec une clé
SSH par compte de test. C'est la suite logique ; ce n'est pas fait pour que le
script reste sans dépendance.

---

### Ce que couvre le jeu d'essai

Arborescence à **deux niveaux sous `paris`**, ce qui n'est pas décoratif : c'est
le seul moyen de distinguer une permission avec propagation d'une permission
sans. Avec un seul niveau, les deux se comportent pareil et le test ne prouve
rien.

```
rbac-test.fr
├── paris.rbac-test.fr
│   └── dev.paris.rbac-test.fr
└── lyon.rbac-test.fr
```

Douze comptes acteurs, un comportement chacun :

| Compte | Ce qu'il prouve |
|--------|-----------------|
| `rbac_t01` | témoin positif — s'il échoue, le problème est en amont du filtrage |
| `rbac_t02` / `rbac_t03` | **le couple qui teste la propagation** — à comparer |
| `rbac_t04` | écriture bornée à un domaine, lecture plus large |
| `rbac_t05` | `web_admin` est une porte distincte des droits RBAC |
| `rbac_t06` | l'inverse : franchit la porte, ne voit rien derrière |
| `rbac_t07` | `write:killswitch` sans `write:delete:user` → mode hard refusé |
| `rbac_t08` | les deux droits → mode hard accepté |
| `rbac_t09` | `read:log` sépare l'audit de l'administration |
| `rbac_t10` | `write:mfa` sépare le déblocage de la modification |
| `rbac_t11` | **l'asymétrie du moteur** : lecture = OU, écriture = ET |
| `rbac_t12` | **le piège des actions globales** — voir ci-dessous |

Plus quatre comptes cibles sans aucun droit, un par domaine, qui existent pour
être vus ou ne pas l'être.

### Le compte `rbac_t12`

Le plus instructif de la série, et un piège volontaire.

`web_admin` fait partie des actions à portée globale : elle est **toujours**
évaluée contre `*`. Lui donner une liste de domaines ne la restreint pas, elle
la **refuse** — aucun domaine nommé ne correspond à `*`.

C'est exactement le geste par lequel un administrateur se coupe l'accès à
lui-même. Si ce compte parvient à entrer dans `/admin`, la protection ne
fonctionne pas.

---

### Second facteur

**Aucun TOTP n'est activé.** Les groupes créés ont tous `mfa_required` à `FALSE`,
donc les comptes se connectent avec leur seul mot de passe — ce qui est le but
pour un jeu d'essai.

Pour tester `rbac_t10` (réinitialisation du second facteur), il faut d'abord en
activer un sur `rbac_cible_paris` depuis son propre profil.

---

### Ordre de passage conseillé

1. `t01` — témoin positif. S'il échoue, inutile d'aller plus loin.
2. `t02` puis `t03` — à la suite : c'est la comparaison qui fait le test.
3. `t05` et `t06` — les deux moitiés de la séparation porte / droits.
4. `t11` — l'asymétrie lecture/écriture.
5. `t12` — le piège des actions globales.
6. `t04`, `t07`, `t09`, `t10` — dans n'importe quel ordre.
7. **`t08` en dernier** : il supprime réellement un compte cible. Relancer le
   script ensuite pour reconstruire.
