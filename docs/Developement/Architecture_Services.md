# Architecture des services Vaultaire

> **Statut : validé. Le socle des clients service est IMPLÉMENTÉ** — catalogue
> des types, clés d'enrôlement, restriction des trames par sous-trame, enrôlement
> 01_03/01_04, cluster service 04_09 à 04_14.
>
> **Reste en proposition, non implémenté :** la sortie de l'interface web hors du
> serveur (§2) et le transport de commandes en catégorie 07. Le web tourne
> toujours dans le processus du core et accède directement à la base.

Ce document décrit la sortie de l'interface web hors du serveur central, le
catalogue des types de programmes, et la procédure pour en ajouter un.

Le transport des commandes est spécifié à part, dans
[`Tableau_Protocole_Réseau.md`](./Tableau_Protocole_Réseau.md), catégorie 07.

---

## 1. Le problème

`core/web_serveur` fait 4 524 lignes en 16 fichiers. Il n'a **aucune dépendance
externe**, mais il importe 30 paquets du core et fait **environ 80 appels directs
à la base**. Il n'utilise `command.ExecuteCommand` qu'à un seul endroit, la
console de la page d'administration.

Autrement dit : l'interface web n'est pas un client du serveur, c'est une
deuxième façade sur la même base, dans le même processus. Trois conséquences.

**Un durcissement doit être posé deux fois.** Le filtrage par domaine des vues
liste, la vérification RBAC par entité, l'anti-rejeu — chaque fois qu'un contrôle
est ajouté au chemin CLI, il faut penser à le porter au chemin web. L'audit
serveur de la 2.0 a trouvé exactement ce défaut : le web ignorait la délégation
par domaine que le CLI respectait déjà.

**Le web ne peut pas être déporté.** Il tourne où tourne le serveur, avec les
mêmes accès. Impossible de le placer en zone exposée et de garder l'annuaire
derrière.

**Une panne du web est une panne du serveur.** Même binaire, même espace mémoire.

---

## 2. Le découpage retenu

```
src/
├── vaultaire_serveur/     annuaire, base, protocole Ducky, commandes    (inchangé)
├── vaultaire_web/         NOUVEAU — interface web et console admin
├── vaultaire_client/      agent poste et serveur                        (inchangé)
├── vaultaire_proxy/       répartition de charge                         (inchangé)
├── vaultaire_ctl/         client de l'API signée                        (inchangé)
└── vaultaire_cli/         `vlt`                                         (inchangé)
```

`vaultaire_web` est un **module Go à part entière**, comme `vaultaire_client` :
son propre `go.mod`, son propre binaire, son propre cycle de vie.

### Ce qui déménage

| Source | Destination |
|---|---|
| `core/web_serveur/*.go` (16 fichiers) | `src/vaultaire_web/web/` |
| `core/web_serveur/session/` | `src/vaultaire_web/session/` |
| `web_packet/sso_WEB_page/` | `src/vaultaire_web/assets/` |
| `core/global/security/qrcode/` | `src/vaultaire_web/qrcode/` |

`core/api` **ne bouge pas** : c'est l'API signée destinée aux consommateurs
externes, elle n'a rien à voir avec l'interface.

### La frontière avec la base

Décision retenue : **le web garde un accès base pour le seul chemin
d'authentification.** Tout le reste passe par des commandes.

Ce qui reste en accès direct :

- vérification du mot de passe (`ComparePasswords`, sel et empreinte) ;
- état d'authentification (`GetAuthState`, `IsMFARequired`) ;
- enrôlement et validation du second facteur (`StartMFAEnrollment`,
  `ActivateMFA`, `ConsumeMFACounter`) ;
- lecture de la politique d'expiration ;
- sessions web.

**Pourquoi cette exception plutôt qu'un découplage total.** L'authentification
*est* le métier du serveur web : c'est lui qui reçoit le mot de passe et le code
TOTP. Les faire transiter en commandes signifierait poser un secret TOTP dans un
flux de commandes, alors que la commande `vlt mfa` exclut délibérément
l'enrôlement pour cette raison exacte. Et l'anti-rejeu du second facteur
(`mfa_last_counter`) doit être atomique avec la validation ; le passer par un
aller-retour réseau ouvrirait une fenêtre de rejeu.

Tout le reste — utilisateurs, groupes, clients, permissions, GPO, certificats,
DNS, cluster, révocation — passe par la catégorie 07.

### Le compte base du web

La frontière du paragraphe précédent n'est qu'une convention de code tant qu'elle
n'est pas imposée par la base. Le web se connecte donc avec un compte MySQL
**distinct**, `web-vaultaire`.

**Ce compte ne peut pas être strictement en lecture seule.** L'enrôlement du
second facteur écrit : `StartMFAEnrollment` pose le secret, `ActivateMFA` lève le
drapeau, et `ConsumeMFACounter` avance le compteur anti-rejeu à chaque connexion.
Un compte en lecture pure rendrait le MFA inutilisable — donc précisément la
fonction qu'on vient de câbler.

Le bon réglage n'est pas « lecture seule » mais **lecture partout, écriture sur
quatre colonnes nommées d'une seule table** :

```sql
GRANT SELECT ON vaultaire.users          TO 'web-vaultaire'@'%';
GRANT SELECT ON vaultaire.groups         TO 'web-vaultaire'@'%';
GRANT SELECT ON vaultaire.users_group    TO 'web-vaultaire'@'%';
GRANT SELECT ON vaultaire.server_settings TO 'web-vaultaire'@'%';

GRANT UPDATE (mfa_secret, mfa_enabled, mfa_enrolled_at, mfa_last_counter)
      ON vaultaire.users TO 'web-vaultaire'@'%';
```

Aucun `INSERT`, aucun `DELETE`, aucune écriture sur une autre table. MySQL sait
restreindre à la colonne : la frontière devient une contrainte du moteur, plus une
règle qu'un développeur pourrait oublier.

**Trois vérifications qui rendent ce périmètre suffisant :**

- **Les sessions web sont en mémoire**, pas en base — `session.go` porte un
  `map[string]Session`. Le compte n'a donc besoin d'aucun droit dessus. (Au
  passage : la table `sessions` du schéma n'est référencée nulle part dans le
  code. Elle est morte.)
- **Le changement de mot de passe passe par une commande**, pas par un accès
  direct. Le web vérifie l'ancien mot de passe en lecture, puis envoie
  `update -p` en 07. C'est la même règle que le reste de l'administration.
- **Les quatre tables en lecture sont exactement celles du chemin
  d'authentification** : `users` pour le sel et l'empreinte, `groups` et
  `users_group` pour `mfa_required`, `server_settings` pour la politique
  d'expiration.

### Créer le compte

`docker-entrypoint-initdb.d` accepte plusieurs fichiers et exécute aussi les
`.sh`, ce qui permet de lire le mot de passe depuis l'environnement plutôt que de
le figer dans un `.sql` versionné — ce que fait aujourd'hui `init-db.sql` pour
Keycloak, acceptable en dev, à ne pas reproduire.

Un second script est donc ajouté : `scripts/init-web-user.sh`.

> ⚠️ **`docker-entrypoint-initdb.d` ne s'exécute qu'à l'initialisation d'un
> volume vide.** `vaultaire_db_data` étant un volume nommé persistant, une
> installation existante **ne verra jamais** ce nouveau script. Le fichier porte
> donc les mêmes instructions en commentaire, à passer à la main sur les bases
> déjà en service — même approche que `migrations/rbac_groupes_stricts.md`.

---

## 3. Deux familles de clients

C'est la distinction structurante, et elle ne se lit nulle part dans le code
aujourd'hui : `logiciel_type` est un `VARCHAR(255)` libre, sans catalogue ni
validation.

| | **Client basic** | **Client service** |
|---|---|---|
| Exemples | `vaultaire_client` | `vaultaire_web`, extensions futures |
| Ce qu'il représente | une **machine** du parc | une **fonction** ajoutée au cluster |
| Création | d'abord sur le core (`vlt create`), la paire est générée côté serveur, la configuration est copiée sur la machine | **s'enrôle seul** à sa première connexion, avec une clé d'enrôlement ; il génère sa propre paire |
| Inventaire matériel (02_11/12/13) | oui | non — il n'a pas de matériel à déclarer |
| GPO (05), révocation (06) | oui | non — il ne reçoit pas de politique et n'a pas de compte local |
| Cluster (04) | non, sauf agent de serveur | oui — enregistrement et battement de cœur |
| Commandes (07) | non | oui, si le type porte `AssertsUser` |

**Le flux d'installation n'est pas le même, et c'est délibéré.** Un agent se
déploie en masse sur des machines qu'un administrateur possède déjà ; générer sa
paire côté serveur et la pousser avec le reste de la configuration est cohérent
avec l'auto-add SSH existant. Un service s'installe une fois, souvent sur un
hôte distinct, parfois par quelqu'un qui n'a pas d'accès au core : il doit pouvoir
se présenter tout seul.

### Le catalogue

Dans le **code**, paquet `core/clienttype`, et non en base.

Même raisonnement que le catalogue de modules GPO : la *structure* est du code,
les *valeurs* sont en base. Un type détermine quelles trames un programme peut
émettre — c'est une frontière de privilège, elle ne doit pas être éditable depuis
une interface d'administration.

```go
type Family string

const (
    FamilyAgent   Family = "agent"   // créé sur le core, représente une machine
    FamilyService Family = "service" // s'enrôle seul, ajoute une fonction au cluster
)

type Definition struct {
    Name        string
    Label       string
    Description string
    Family      Family

    // Frames liste les trames que ce type peut ÉMETTRE, en "CC_SS".
    // Granularité à la sous-trame et non à la catégorie : le web utilise 02
    // pour s'authentifier mais n'a rien à faire de 02_11/12/13, qui sont
    // l'inventaire matériel d'une machine.
    Frames []string

    // AssertsUser : le programme peut déclarer agir au nom d'un utilisateur
    // qu'il a lui-même authentifié. Voir §5.
    AssertsUser bool
}
```

### Le catalogue

| Type | Famille | Trames émises | Assertion |
|---|---|---|---|
| `vaultaire_client` | agent | `01_01`, `02_01`, `02_03`, `02_05`, `02_12`, `03_01`, `03_04`, `03_06`, `05_01`, `05_05`, `05_09`, `05_12`, `06_02`, `06_03`, `06_04` | non |
| `vaultaire_proxy` | service | `01_01`, `01_03`, `04_01`, `04_03`, `04_07` | non |
| `vaultaire_web` | service | `01_01`, `01_03`, `02_01`, `02_03`, `02_05`, `04_09`, `04_12`, `04_14`, `07_01`, `07_04` | **oui** |

**LE CORE N'Y FIGURE PAS, et ne peut pas y figurer.** C'est lui qui juge la
légitimité des trames qu'il reçoit en fonction du type de leur émetteur : il ne
peut pas se juger lui-même. Il n'est d'ailleurs jamais enregistré comme client —
`GenerateClientSoftware` ne sert qu'à créer un agent, et l'enrôlement qu'à créer
un service.

**Il n'y a qu'un seul type d'agent.** Le drapeau `isServeur` d'un client ne crée
pas un second type : c'est le même binaire, qui émet les mêmes trames et se
contente d'ouvrir un tunnel machine en plus. Une machine serveur n'est pas plus
digne de confiance qu'un poste, elle a seulement plus de tâches — ce n'est pas
une frontière de privilège.

**Les listes sont relevées sur ce que les programmes émettent réellement**, et
non sur la table du protocole, qui décrit aussi des trames restées à l'état
d'intention. L'agent émet `02_12` et jamais `02_13` ; le proxy n'émet pas encore
`04_05`. Elles seront ajoutées ici le jour où elles le seront là-bas, pas avant :
déclarer un droit qui ne sert pas, c'est ouvrir une porte que personne ne
surveille.

**Le web utilise 02 mais pas son inventaire.** Il s'authentifie comme service et
ferme sa session, mais n'émet pas `02_12` : il n'a ni processeur ni mémoire à
déclarer. Il n'émet pas non plus 05 ni 06 — il n'est pas une machine du parc, il
n'a aucune raison de demander des GPO ni d'acquitter une révocation.

**La liste est exhaustive, sous-trame par sous-trame.** C'est verbeux, et c'est
voulu : une sous-trame ajoutée au protocole n'est émissible par personne tant
qu'elle n'a pas été déclarée. Un défaut de mise à jour produit un refus visible,
jamais une ouverture silencieuse.

### Créer un agent

`create -c <yes|not>` ne demande plus de type : ce chemin ne peut produire qu'un
client basic. Le paramètre restant indique seulement si l'agent tourne sur un
serveur membre.

Le type était auparavant une chaîne libre saisie à la main — le formulaire web
proposait « client » en simple exemple, et le seul fichier de configuration du
dépôt porte `logiciel_type: administration`. Rien ne la validait et rien n'en
dépendait. La laisser ouverte alors qu'une seule valeur est correcte n'offrait
aucun choix, seulement l'occasion d'une faute de frappe — qui produit désormais
un client incapable d'émettre la moindre trame.

---

## 4. Enrôlement d'un client service

### Clés d'enrôlement

Le core émet des clés d'enrôlement portant **un type, une expiration et un
quota** :

```
vlt enroll create --type vaultaire_web --uses 1 --expires 30m
→ VLT-ENR-3f9a2c...   (affichée une seule fois)
```

**La clé porte le type.** Le client n'a donc rien à déclarer d'autre, et surtout
il ne peut pas choisir son propre type : une clé émise pour `vaultaire_probe` ne
peut pas enrôler un `vaultaire_web`. C'est ce qui empêche un service de
s'accorder des privilèges que l'administrateur n'a pas voulu lui donner.

**Seul le condensat est stocké**, jamais le secret — comme un mot de passe. Une
fuite de la base ne rend aucune clé utilisable.

```sql
CREATE TABLE IF NOT EXISTS service_enrollment_key (
    id_key      INT AUTO_INCREMENT PRIMARY KEY,
    key_hash    CHAR(64) NOT NULL UNIQUE,   -- SHA-256 du secret
    client_type VARCHAR(64) NOT NULL,
    max_uses    INT NOT NULL,
    used_count  INT NOT NULL DEFAULT 0,
    expires_at  DATETIME NOT NULL,
    created_by  VARCHAR(255) NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at  DATETIME NULL
);

CREATE TABLE IF NOT EXISTS service_enrollment_use (
    id_use       INT AUTO_INCREMENT PRIMARY KEY,
    d_id_key     INT NOT NULL,
    computeur_id VARCHAR(255) NOT NULL,
    source_ip    VARCHAR(45) NULL,
    used_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (d_id_key) REFERENCES service_enrollment_key(id_key) ON DELETE CASCADE
);
```

La table d'usages n'est pas un luxe : sans elle, on ne peut pas répondre à
« quels services sont entrés par cette clé ? » le jour où l'on découvre qu'elle a
fuité. `ON DELETE CASCADE` est ici acceptable, contrairement à la révocation —
supprimer une clé d'enrôlement est une décision d'administration, pas la
destruction du sujet d'une trace d'audit.

**L'émission exige l'appartenance au groupe `vaultaire`** quand le type visé
porte `AssertsUser`. Un jeton `vaultaire_web` donne le pouvoir d'agir au nom de
n'importe quel utilisateur : il ne se délègue pas par une clé RBAC ordinaire.

### Le flux complet

```
service                                          core
  |
  |-- askkey (non authentifié) ----------------->  |
  |<-- clé publique du serveur -------------------  |
  |
  |   génère sa paire RSA-4096 localement          |
  |   (la clé privée ne quitte JAMAIS l'hôte)      |
  |
  |-- 01_03 enroll_request --------------------->  |  vérifie la clé : validité,
  |   { clé d'enrôlement, sa clé publique }        |  expiration, quota, révocation
  |                                                |  crée le client du TYPE DE LA CLÉ
  |<-- 01_04 enroll_ok ---------------------------  |  chiffrée avec la clé publique
  |   { computeur_id attribué, type }              |  que le service vient d'envoyer
  |
  |========= à partir d'ici, flux classique =======|
  |-- 01_01 ------------------------------------>  |  authentification du client
  |<-- 01_02 -------------------------------------  |
  |-- 02_01 ------------------------------------>  |  authentification du service
  |<-- 02_04 -------------------------------------  |
  |-- 04_09 register_service ------------------->  |  entrée dans le cluster
  |-- 04_12 service_heartbeat ------------------>  |  (périodique)
  |-- 07_01 command_request -------------------->  |  (web uniquement)
```

**La preuve de possession est gratuite.** La réponse `01_04` est chiffrée avec la
clé publique que le service vient de soumettre : seul le détenteur de la privée
correspondante peut lire son `computeur_id`. C'est exactement le mécanisme de
`01_02`, et votre audit 2.0 avait déjà établi qu'il rend un défi explicite
inutile.

**La clé privée ne voyage jamais.** C'est la différence de fond avec l'enrôlement
des agents, où `GenerateClientSoftware` produit la paire sur le serveur et écrit
`private_key.pem` dans un dossier qu'on copie ensuite.

### Ce qui reste ouvert

L'enrôlement des agents **ne change pas**. Deux chemins coexistent donc, et c'est
assumé : l'auto-add SSH en dépend, et rien ne justifie de rebasculer un parc
déployé pour une amélioration qui ne concerne que les nouveaux services. À
reconsidérer si l'auto-add est un jour repris.

---

## 4 bis. Restriction des trames

### Où le contrôle est posé

Dans `Split_Action`, **immédiatement après** le contrôle `clientMatchesSession`
qui existe déjà.

C'est délibérément le même endroit, pour la même raison, et le commentaire du
code la donne déjà : « Le contrôle est ici plutôt que dans chaque handler : un
point unique couvre les catégories 02, 03, 04 et 05, et couvrira aussi celles qui
seront ajoutées plus tard sans que personne n'ait à y penser. »

```go
if !clienttype.MayEmit(duckysession.BoundClientType, messageOrder) {
    logs.Write_Log("SECURITY", ...)
    duckysession.Conn.Close()
    return
}
```

`messageOrder` est déjà calculé juste au-dessus (`strings.Join(Message_Order, "_")`),
donc le contrôle porte sur la sous-trame sans travail supplémentaire.

### Le type est figé à la poignée de main

`BoundClientType` est résolu **une fois**, en `01_01`, en même temps que
`BoundClientSoftwareID`, et posé sur la session.

Deux raisons. La première est de correction : relire le type en base à chaque
trame permettrait à une modification concurrente de changer les droits d'une
session en cours. La seconde est que l'identifiant machine est **déjà prouvé** à
ce moment — la réponse `01_02` est chiffrée avec la clé publique de cet
identifiant. Le type dérivé de cet identifiant hérite de cette preuve.

Les trames d'enrôlement `01_03`/`01_04` échappent nécessairement à ce contrôle :
elles précèdent l'existence du client. C'est la clé d'enrôlement qui les autorise,
et son type qui décide de ce que le client pourra émettre ensuite.

### Fail-closed, et la migration qu'il impose

Un type absent du catalogue n'émet **rien**.

C'est volontairement brutal, et les bases existantes contiennent des clients dont
le `logiciel_type` a été saisi librement. Il faut donc **une requête de diagnostic
avant bascule**, sur le modèle de `migrations/rbac_groupes_stricts.md` :

```sql
SELECT logiciel_type, COUNT(*) AS clients
FROM id_logiciels
GROUP BY logiciel_type
ORDER BY clients DESC;
```

Tout type sans équivalent au catalogue est soit à ajouter, soit à corriger en
base — mais **avant** la mise en service, sinon les machines concernées ne se
connectent plus du tout.

---

## 5. Ce que ce modèle ne protège pas

**Le web reste un délégué de confiance.** Quand il envoie une commande au nom de
`alice`, rien ne prouve cryptographiquement qu'alice est derrière : elle s'est
authentifiée par mot de passe et second facteur auprès du web, pas auprès du
serveur central. Une preuve de bout en bout demanderait que l'utilisateur détienne
une clé, ce qu'un navigateur ne permet pas sans matériel dédié.

La conséquence doit être dite clairement : **un `vaultaire_web` compromis peut
agir au nom de n'importe quel utilisateur.**

Trois choses limitent le rayon de souffle, et aucune ne l'annule :

1. **Le RBAC est évalué sur l'utilisateur déclaré, pas sur le web.** Le web ne
   peut donc rien faire qu'aucun utilisateur ne pourrait faire. Il doit choisir
   une identité, et il hérite de ses limites.
2. **Tout est journalisé sous l'identité déclarée**, avec le
   `ClientSoftwareID` du web dans la même ligne. Une usurpation laisse une trace
   nommée.
3. **Le type `vaultaire_web` n'émet que 01 et 07.** Il ne peut pas se faire
   passer pour une machine du parc et tirer des GPO.

C'est le même modèle de confiance que n'importe quel portail d'authentification,
et il vaut la peine d'être écrit plutôt que découvert. Il justifie aussi le compte
MySQL restreint du §2 : sans lui, la compromission du web donne l'écriture
directe sur la base, ce qui contourne les trois limites ci-dessus d'un coup.

---

## 6. Ordre de réalisation proposé

Chaque étape laisse le dépôt compilable et fonctionnel.

1. **Enveloppe de sortie structurée** (§ dédié dans
   `Tableau_Protocole_Réseau.md`). `ExecuteCommand` reçoit un format ; le texte
   reste le défaut. Aucun appelant existant ne change.
2. **Catalogue `core/clienttype`** et validation à la création d'un client, sans
   encore restreindre les trames. Plus la requête de diagnostic de migration.
3. **Restriction dans `Split_Action`**, après traitement des types inconnus
   trouvés en production.
4. **Catégorie 07** côté serveur. Premier consommateur de test : un type
   `vaultaire_probe` déclaré au catalogue, sans `AssertsUser` et limité aux
   commandes de lecture. `vaultaire_ctl` ne convient pas — il parle à l'API
   signée en HTTPS, pas au tunnel Ducky.
5. **Extraction de `vaultaire_web`** en module séparé, encore en accès base
   direct.
6. **Bascule page par page** vers la catégorie 07, en commençant par les vues en
   lecture seule, qui sont les moins risquées et les plus nombreuses.

Le point 5 est celui qui déplace le plus de fichiers et le moins de logique ; le
point 6 est celui qui demande le plus d'attention. Les inverser ferait porter les
deux risques en même temps.

---

## Voir aussi

- [`Tableau_Protocole_Réseau.md`](./Tableau_Protocole_Réseau.md) — catégorie 07 et format des trames
- [`Architecture_Multi_Programmes.md`](./Architecture_Multi_Programmes.md) — le découpage existant
- [`Permissions.md`](./Permissions.md) — le modèle RBAC appliqué à l'utilisateur déclaré

---

## Annexe — Enveloppe de sortie structurée

Le retour d'une commande est aujourd'hui du texte mis en forme par
`core/command/display` : 19 fichiers, 1 198 lignes de colonnes alignées. C'est
bon pour un terminal, inexploitable par un programme — la première colonne
ajoutée casserait tout analyseur.

### La forme

```go
// core/command/output
type Format string

const (
    FormatText Format = "text" // défaut : ce que voit un terminal
    FormatJSON Format = "json"
)

type Result struct {
    Status  string          `json:"status"`         // ok | error | denied
    Message string          `json:"message"`        // destiné à un humain
    Data    json.RawMessage `json:"data,omitempty"` // structuré, facultatif
}
```

`ExecuteCommand` prend le format en paramètre. **Le texte reste le défaut** :
aucun appelant existant ne change de comportement, et le CLI n'a rien à savoir de
cette annexe.

### Pourquoi `Data` est facultatif

Convertir les 19 fichiers de `display` avant que la première page web fonctionne
ferait porter tout le risque d'un coup, pour un bénéfice différé.

À la place, `Message` est toujours renseigné — c'est la sortie texte existante,
telle quelle — et `Data` se remplit commande par commande, en commençant par
celles dont le web a besoin. Une commande non encore convertie reste utilisable :
le web affiche son `Message`, sans le décomposer.

`Status` est en revanche renseigné **dès le départ, pour toutes les commandes**.
C'est lui qui permet au web de distinguer un refus d'une panne, ce qu'un texte
libre ne permet jamais de faire de façon fiable.

### Ordre de conversion proposé

1. `get` — c'est ce que les vues liste consomment, et c'est en lecture seule.
2. `status` — le tableau de bord.
3. `create`, `add`, `remove`, `delete`, `update` — les écritures, dont le `Data`
   se limite le plus souvent à l'entité touchée.
4. `gpo`, `mfa`, `kill`, `dns`, `cluster` — au fil des pages qui basculent.

### Le piège à éviter

`Message` ne doit pas devenir un JSON encodé dans une chaîne. Si une commande a
besoin de rendre une structure, elle remplit `Data`. Un `Message` qui contiendrait
du JSON obligerait chaque appelant à deviner s'il doit le décoder, et c'est
exactement le genre d'ambiguïté qui finit en analyse syntaxique conditionnelle
chez le consommateur.
