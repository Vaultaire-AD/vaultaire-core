# Journalisation du serveur

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
| `DEBUG` | le verdict d'un contrôle de droit, le détail d'un échange | non — réglage `debug` |

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

## Réglages

| | |
| --- | --- |
| `debug: true` dans `serveur_conf.yaml` | active `DEBUG` |
| `VAULTAIRE_LOG_PATH` | répertoire des journaux de fichier |

La sortie principale est **stdout**, au format RFC 5424 ou JSON — voir
`core/logs/rfc5424.go`. `WriteLog` ne sert plus qu'aux quelques familles qui ont
un fichier dédié : `date`, `SQL_Injection`.

---

## Ce qui reste à faire

Le point 26 de [`TO-DO.md`](./TO-DO.md) demandait aussi :

- **Ducky** : « user X connecté au client X via le groupe suivant, en tant
  qu'admin ou non » — la trame `02` journalise l'authentification, mais sans le
  groupe ni la qualité d'administrateur ;
- **LDAP** : « user X s'est connecté en LDAPS via le compte X » — le bind
  journalise, mais ne distingue pas LDAP de LDAPS dans le message.

Ces deux-là demandent de toucher aux chemins d'authentification, et méritent
d'être traités séparément de la mise au propre décrite ici.
