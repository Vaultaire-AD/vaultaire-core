# Journalisation du serveur

> **Public : développeurs.** Ce que le serveur écrit, à quel niveau, et pourquoi.
> Pour l'usage au quotidien, voir [`docs/Utilisation/`](../../Utilisation/).

Ce que le serveur écrit, à quel niveau, et pourquoi.

---

## La règle

> **Une consultation n'écrit rien. Une modification écrit une ligne.**

Tout le reste découle de là. Un journal d'exploitation répond à « qui a changé
quoi, et qu'est-ce qui a échoué ». Qui a *regardé* quoi est une autre question,
qui appelle un autre volume et une autre rétention.

---

## Les niveaux

| Niveau | Ce qu'on y met | Visible par défaut |
| --- | --- | --- |
| `CRITICAL` | le service ne peut plus rendre son office | oui |
| `ERROR` | un vrai problème système : base injoignable, écriture impossible | oui |
| `SECURITY` | une décision de droits refusée, une tentative | oui |
| `WARNING` | une écriture tentée qui n'aboutit pas, un état inattendu mais géré | oui |
| `INFO` | une écriture **réussie**, un démarrage, une connexion | oui |
| `DEBUG` | le verdict d'un contrôle de droit, **une ligne par opération** d'un échange | non — réglage `debug`, ou détail du sous-système |
| `TRACE` | le déroulé pas à pas : paquets reçus, entrées retenues | non — **jamais** par `debug` ; se demande par sous-système |

`TRACE` n'a pas de sévérité à lui — la RFC 5424 s'arrête à 7, celle du `DEBUG`.
Il la partage, et se distingue par son nom de niveau. Comme le `DEBUG`, il ne
part jamais dans le journal commun en base.

Le niveau `DATABASE` **n'existe plus**. Il ne correspondait à aucune sévérité
RFC 5424 et `Write_LogCode` ne le filtrait pas : ses lignes étaient émises quel
que soit le réglage et impossibles à écarter.

---

## La ligne d'audit

Écrite à **un seul endroit** : `action.Executer`, dans `core/action/action.go`.

```
alice a fait group.add_user sur username bob
alice a tenté user.delete sur username bob : compte introuvable
```

C'est le passage obligé du portail, de la ligne de commande et de l'API depuis
l'unification des actions. Une ligne écrite là couvre les trois façades sans
rien recopier, et une action ajoutée demain est tracée sans qu'on y pense.

**Seules les écritures sont tracées.** La distinction se fait par la clé RBAC —
`write:` — et non par le nom de l'action : le nom est une convention que rien ne
contraint, la clé est obligatoire et vérifiée à l'enregistrement. Une action
sans clé mais réservée au groupe protégé compte aussi pour une écriture : la
suppression d'un certificat interrompt un service.

**La cible** est déduite d'une liste ordonnée de noms de paramètres —
`username`, `group`, `computeur_id`, `permission_name`… Le premier présent gagne.
Un rattachement porte deux cibles ; c'est l'utilisateur qui est nommé, parce que
c'est lui qui change de situation.

> ⚠️ **Cette liste se tient à jour avec les PARAMÈTRES, pas avec les noms
> d'entités.** Sa première version avait été écrite d'après le vocabulaire du
> modèle : elle déclarait `certificate` et `record` là où les actions lisent
> `certificate_id` et `record_name`, et ignorait `permission_name`, que huit
> actions emploient. Toutes les écritures sur les permissions, les certificats et
> les zones DNS étaient donc journalisées « sur le serveur » — la ligne existait,
> elle ne nommait rien. Le défaut ne se voit pas en relisant le code qui écrit la
> ligne, seulement en confrontant les deux listes. `cible_test.go` fait cette
> confrontation en lisant les sources du paquet.

Quand le paramètre est un **identifiant** et le nom connu seulement après lecture
en base, l'action renseigne `Resultat.Cible`, qui l'emporte. C'est le cas de la
suppression d'un certificat : « certificat 3 supprimé » obligerait à retrouver
l'identifiant 3 dans une table d'où la ligne vient de disparaître, alors que le
nom — `ldaps`, `web`, `api` — désigne le service interrompu. Ce champ n'est pris
en compte qu'en cas de succès : sur un échec, l'audit retombe sur les paramètres,
c'est-à-dire sur ce qui a réellement été demandé.

**Réussite et échec ne passent pas par la même porte** : `Journal.Execution` en
`INFO`, `Journal.Echec` en `WARNING`. Les deux passaient par `Execution`, donc au
même niveau — un échec d'écriture se lisait comme une réussite dans un journal
filtré sur `INFO`.

---

## Les contrôles de droits

Une ligne par contrôle, portant le **motif décisif** :

```
droit read:get:user sur paris : accordé (all via le groupe 4)
droit write:add:user sur lyon : accordé (propagation depuis example.fr via le groupe 7)
```

Le déroulé pas à pas a été retiré. Il écrivait deux lignes par groupe et par
domaine — « Vérification de la permission pour le groupe ID 4 », puis
« Permission brute pour le groupe 4 » — plus une troisième à l'acceptation, et
la liste des groupes du compte à chaque appel. Pour un compte membre de trois
groupes, l'ouverture d'une page d'administration produisait une quinzaine de
lignes dont aucune ne disait quelle règle avait tranché.

| | Avant | Après |
| --- | --- | --- |
| `permission-manager.go` | 6 instructions DEBUG | 2 |
| `pre-permission-check.go` | 1 par appel | 0 |
| Lignes par contrôle accordé | 3 à 7 | **1** |

Les groupes examinés avant celui qui accorde n'ont, par construction, rien
accordé : les énumérer n'apprenait rien.

**Les refus gardent tout leur détail**, en `WARNING`, avec les groupes examinés
et le domaine manquant. C'est ce qu'on cherche dans un journal.

---

## Le détail par sous-système *(TO-DO 145)*

`debug` était **un** booléen pour tout le serveur. L'allumer pour suivre une GPO
ouvrait aussi le robinet de l'annuaire, et le reste du journal disparaissait
dessous. Le détail se règle maintenant **par sous-système**, en plus ou en moins
du réglage général :

| Sous-système | Ce qu'il couvre |
| --- | --- |
| `ldap` | `core/ldap`, `core/database/db_ldap` |
| `ducky` | `ducky-network`, hors politiques |
| `gpo` | `ducky-network/gpo_manager`, `core/gpo`, `core/database/db_gpo` |
| `base` | le reste de `core/database` |

| Niveau | Effet |
| --- | --- |
| *(aucun réglage)* | le sous-système suit `debug` |
| `off` | rien sous `INFO`, **même avec `debug: true`** |
| `debug` | ses lignes `DEBUG`, **même avec `debug: false`** |
| `trace` | `DEBUG` et `TRACE` |

Les deux usages attendus : le debug partout **sauf** l'annuaire (`debug: true`,
`ldap: off`), et l'annuaire **seul** sur un serveur silencieux (`debug: false`,
`ldap: debug`).

```yaml
debug:
  debug: false
  detail:
    ldap: debug
```

```text
vlt update -debug                   # relit l'état
vlt update -debug ldap trace        # règle un sous-système, à chaud
vlt update -debug ldap defaut       # le rend au réglage général
```

Le portail porte le même réglage, page d'accueil de l'administration. La
commande et le portail règlent **ce core, jusqu'à son redémarrage** — comme
`update -debug true` ; le fichier est la forme durable. Un nom de sous-système
ou un niveau inconnu est **refusé** partout, et arrête le démarrage quand il est
dans le fichier : une faute de frappe laisserait le détail éteint pendant qu'on
cherche pourquoi la panne n'écrit rien.

### Le sous-système est celui du code qui écrit

Il n'est **pas** passé en argument : il est déduit du **fichier** de l'appelant
(`runtime.Caller`), d'après la table `rangement` de `core/logs/detail.go`. Une
ligne `DEBUG` ajoutée demain dans `core/ldap` est une ligne de l'annuaire sans
que personne y pense — et une ligne écrite par `core/permission` pendant un bind
reste une ligne des permissions : c'est ce code-là qui parle.

Trois choses à savoir avant d'y toucher :

- `Write_Log`, `Write_LogCode` et `Write_LogCodeMeta` lisent la pile à une
  **profondeur fixe**. Aucune ne doit appeler l'autre, et une fonction
  d'écriture ajoutée ne doit pas les emballer sans passer la profondeur :
  toutes ses lignes seraient rangées avec le paquet de l'emballage.
  `TestLesTroisEcrituresLisentLeBonCadre` le garde ;
- la table désigne des **dossiers**. Un dossier renommé perdrait son rangement
  en silence ; `TestLeRangementDesigneDesDossiersQuiExistent` échoue alors ;
- le coût — un `runtime.Caller` par ligne `DEBUG` ou `TRACE` — n'est payé **que
  si un réglage par sous-système existe**. Sans aucun, le chemin est celui de
  toujours : un booléen lu.

Pour garder un message coûteux à construire : `logs.DebugActif(logs.SousLDAP)`,
`logs.TraceActive(…)`. `Write_Log` écarte la ligne, mais **après** que
l'appelant l'a formatée.

---

## Le journal de l'annuaire *(TO-DO 145)*

Avec `debug` actif, une recherche LDAP écrivait une ligne à l'arrivée du paquet,
une au décodage, plusieurs à la résolution, **trois par entrée candidate** au
filtrage et une par attribut de chaque entrée rendue. Mesuré sur un annuaire de
12 500 comptes : une connexion, un bind et trois recherches produisaient **plus
de 250 000 lignes** — 15 Mo — et la conversation n'était pas terminée au bout de
deux minutes. La même, aujourd'hui :

```
INFO   ldap conn=1 ouverte LDAP depuis 127.0.0.1:51428
DEBUG  droit auth sur acme.lan : accordé (propagation depuis acme.lan via le groupe 4)
INFO   ldap conn=1 msg=1 bind: success user=svc_keycloak domain=acme.lan from 127.0.0.1:51428 (LDAP)
DEBUG  ldap conn=1 msg=1 BIND dn="uid=svc_keycloak,ou=users,dc=acme,dc=lan" → 0 success, 53 ms
DEBUG  ldap conn=1 msg=2 SEARCH base="dc=acme,dc=lan" scope=sub filtre="(&(objectClass=inetOrgPerson)(uid=alice.dupont))" attrs="uid mail givenName sn entryUUID modifyTimestamp" → 0 success, 1 entrée(s), 440 ms ; candidats=13011
DEBUG  ldap conn=1 msg=3 SEARCH base="uid=alice.dupont,ou=users,dc=acme,dc=lan" scope=base filtre="(objectClass=*)" attrs="memberOf" → 0 success, 1 entrée(s), 2 ms ; candidats=1
DEBUG  ldap conn=1 msg=4 SEARCH base="dc=acme,dc=lan" scope=sub filtre="(&(objectClass=groupOfNames)(cn=Dev))" attrs="cn" → 0 success, 1 entrée(s), 369 ms ; candidats=13011
DEBUG  ldap conn=1 msg=5 UNBIND → sans réponse, 0 ms
DEBUG  ldap conn=1 fermée (unbind) après 865 ms : 5 opération(s), 3 entrée(s), compte svc_keycloak
```

Neuf lignes, en une seconde. La deuxième n'est pas de l'annuaire : c'est le
contrôle de droits, écrit par `core/permission` — elle suit `debug`, pas `ldap`.

Trois règles, tenues par le paquet `core/ldap/LDAP_Journal` :

1. **Une ligne par opération**, en `DEBUG`, écrite quand l'opération est finie :
   la demande, le code rendu au client, le nombre d'entrées, la durée, et ce qui
   explique le résultat (`candidats=`, `hors-droits=`, `total=`, `suite=`,
   `matchedDN=`).
2. **Toute ligne écrite pour une connexion commence par `ldap conn=N`**, et
   `msg=M` quand elle appartient à une opération — avertissements, refus et
   erreurs compris. `grep 'conn=17 '` rend une conversation entière. `conn` est
   un compteur du processus : il repart de 1 au redémarrage et n'a de sens que
   sur **ce** core. `msg` est le messageID du protocole, celui que le client
   écrit dans ses propres journaux.
3. **Le déroulé est en `TRACE`** : paquets reçus (le bind reste masqué — point
   121), découpage du DN, entrées retenues par le filtre **avec leur contenu**,
   entrées écartées par les droits **sans** leur contenu. Borné aux vingt
   premières entrées d'une opération (`EntreesTracees`).

Ce qui n'y figure **jamais** : le mot de passe d'un bind, le contenu d'une
opération étendue. `Decrire` ne lit ni l'un ni l'autre, et un test le vérifie
sur la ligne produite.

**Le code rendu vient de ceux qui l'écrivent.** La ligne porte le code *envoyé* :
ce sont les fonctions qui écrivent sur la connexion qui le notent
(`ldapjournal.Resultat`, `EntreeEnvoyee`). Une fonction de réponse ajoutée sans
le faire donnerait des lignes « sans réponse » pour des opérations répondues —
`TestTouteEcritureSurUneConnexionEstNoteeAuJournal` lit le paquet et l'interdit.

**Ce qui a changé de niveau.** La ligne d'ouverture d'une connexion reste en
`INFO` — c'est la seule trace d'une connexion qui ne se lie jamais. Ses deux
doublons (« Nouvelle session LDAP créée », « Session LDAP supprimée ») ont
disparu ; la fermeture est en `DEBUG`, avec son motif et son bilan. La ligne de
bind réussi dit maintenant **LDAP ou LDAPS**. Une connexion fermée par son délai
d'inactivité, ou après un unbind, n'écrit plus de ligne `ERROR` : ce n'en était
pas une.

---

## Un message ne peut pas forger une ligne

Un message reprend souvent ce qu'un client a envoyé — le nom d'un compte tiré
d'un DN de bind. Un DN portant un retour à la ligne, une date et un niveau
écrivait, sur la sortie du core, une ligne que rien ne distinguait d'une vraie.
Sans authentification.

`logs.SurUneSeuleEntree` décale d'une tabulation les lignes de suite d'un
message, à l'**affichage** : sur la sortie standard et dans `vlt logs`. Une vraie
ligne commence par sa date en première colonne ; une ligne de suite ne peut plus
passer pour telle. Le format JSON et la table en base ne sont pas concernés — un
message y est une seule valeur.

Dans le code neuf, ce qui vient d'un client s'écrit avec `%q`.

---

## Réglages

| | |
| --- | --- |
| `debug: true` dans `serveur_conf.yaml` | active `DEBUG` pour tout le serveur |
| `debug.detail` dans `serveur_conf.yaml` | détail par sous-système : `off`, `debug`, `trace` |
| `vlt update -debug …`, accueil de l'administration | les mêmes, à chaud, sur ce core |
| `VAULTAIRE_LOG_PATH` | répertoire des journaux de fichier |
| `log_retention_days`, `log_purge_hours` | rétention et purge du journal commun (`settings`) |

La sortie principale est **stdout**, au format RFC 5424 ou JSON — voir
`core/logs/rfc5424.go`. `WriteLog` ne sert plus qu'aux quelques familles qui ont
un fichier dédié : `date`, `SQL_Injection`.

---

## Le journal commun des cores (TO-DO 91)

Chaque ligne émise par `writeEntry` part, en plus de la sortie standard et de
la mémoire, vers une **sortie branchée** (`logs.BrancherSortie`). Le core y
branche au démarrage l'écrivain de `core/database/db_journaux`, qui l'insère
dans la table `server_logs`, **signée du nom du core** (`logs.NomDuCore()`, le
même `os.Hostname()` que l'inscription au cluster).

Pourquoi une base et pas un service de journalisation : la base est déjà le
point de rendez-vous du cluster. Un service de plus serait à installer, à
authentifier, à superviser — et tomberait au moment où l'on a besoin de lui.

### Ce qu'il ne faut pas casser

| Invariant | Pourquoi | Tenu par |
| --- | --- | --- |
| **La sortie ne bloque jamais** | appelée depuis toutes les goroutines, souvent au milieu d'une requête ; une base lente ralentirait chaque requête, une base arrêtée figerait le core | file bornée (`CapaciteFile`), `select` non bloquant — `TestUneFilePleineNeBloquePasEtCompte` |
| **Le paquet `logs` n'importe pas la base** | la base importe `logs` : cycle | une fonction branchée par `main`, comme `permission.SetRevokedChecker` |
| **Une perte se dit** | un trou dans le journal commun se lirait comme une période calme | `WARNING` `VLT-LOG001` au plus une fois par minute, avec le compte et la cause |
| **Le DEBUG ne part pas en base** | c'est le niveau le plus bavard ; chaque séance de diagnostic ferait grossir la table | `dbjournaux.VaEnBase` |
| **Filtre SQL = filtre mémoire** | le repli sur la mémoire du core doit rendre les mêmes lignes que la base | `TestLeFiltreSQLEtLeFiltreMemoireConcordent` |

Le signalement des pertes passe par le journal ordinaire, donc revient dans la
file : base rétablie, il est inséré à l'endroit du trou. Base toujours arrêtée,
il est perdu à son tour et compté au suivant — une ligne par minute, pas une
boucle.

### Seuil : tout sauf DEBUG

Un seuil plus haut rendrait le journal commun muet sur la question qu'on lui
pose le plus : l'audit des écritures (« alice a fait group.add_user… ») est en
`INFO`.

### Ce qui n'y est pas

- les lignes émises **avant** le branchement : lecture de la configuration,
  ouverture de la base. Elles sont sur la sortie standard ;
- les journaux des **agents**, du proxy et de Nexus : chacun a son propre
  paquet de journalisation, hors de ce module.

### Lecture et rétention

Une seule action, `log.list` (`read:log`), sert `vlt logs` et la page
`/admin/logs` — filtre par seuil de gravité, core, code et période, pagination
sans `COUNT(*)` (une ligne témoin dit s'il y a une suite). Base injoignable :
l'action se replie sur `logs.EntreesEnMemoire()` et le **dit**.

La rétention est le réglage `log_retention_days` ; chaque core purge au
démarrage puis à la cadence de `log_purge_hours`, par lots bornés
(`dbjournaux.Purger`). Voir [`Reglages_de_duree.md`](./Reglages_de_duree.md).

---

## Ce qui reste à faire

Le point 26 de [`TO-DO.md`](../TO-DO.md) demandait aussi :

- **Ducky** : « user X connecté au client X via le groupe suivant, en tant
  qu'admin ou non » — la trame `02` journalise l'authentification, mais sans le
  groupe ni la qualité d'administrateur. Cela demande de toucher au chemin
  d'authentification, et mérite d'être traité séparément.

Le second — « user X s'est connecté en LDAPS via le compte X » — est fait
depuis le TO-DO 145 : la ligne de bind réussi porte le canal.

Un reste relevé en traitant le 145 : des écritures directes sur la sortie
standard, hors du journal (**TO-DO 153**).

Le second est traité *(2.3, TO-DO 154)* : le tampon mémoire — les 10 000
dernières lignes de ce core, repli de `vlt logs` quand la base ne répond pas —
était **recopié en entier à chaque ligne** une fois plein, sous son verrou :
3,5 ms et 3 Mo par ligne de journal, pour tout ce qui journalise. C'est un
anneau (`core/logs/tampon.go`) : une ligne de plus écrase la plus ancienne, sans
allocation, et l'ordre se reconstitue à la lecture.
