[⌂ Ducky Network](../README.md) › [Chapitre 5 — Transport des GPO (05)](./README.md) › 5.2

# 5.2 — Les trames 05_01 à 05_18

[← Principe, numérotation et séquence](./01-principe-et-sequence.md) · [Charge utile, état local, application en scope user →](./03-charge-utile-et-etat.md)

---


Rappel : client → serveur = 5 lignes d'en-tête (`action`, `destination`,
`session_key`, `username`, `client_software_id`), serveur → client = 3 lignes
(`action`, `destination`, `session_key`). Ce qui suit décrit le **contenu**, ligne
par ligne.

### 05_01 — ask_gpo_machine (client → serveur)

```
<empreinte_appliquée>
```

Empreinte SHA-256 (hex) de la politique machine actuellement appliquée, lue dans
l'état local. `none` au premier démarrage ou après remise à zéro de l'état.

### 05_02 — gpo_machine_manifest (serveur → client)

```
<version>            somme des versions des GPO contributrices
<empreinte>          SHA-256 hex de la politique effective
<nb_fragments>
<taille_totale>      octets de texte clair
<nb_modules>
<somme_de_controle>  SHA-256 hex de la charge transmise
refresh:<minutes>    cadence de rafraîchissement machine — FACULTATIVE, en queue
```

> **Ajout par rapport à la v2 validée : la ligne `<somme_de_controle>`.**
> Deux empreintes distinctes cohabitent, et les confondre serait une source de
> bugs difficiles à diagnostiquer :
>
> - `<empreinte>` identifie la **configuration voulue**. C'est elle qui décide
>   s'il y a quelque chose à appliquer, et elle ne dépend pas du format de
>   livraison — ajouter un champ de transport ne provoque donc pas une
>   réapplication sur tout le parc ;
> - `<somme_de_controle>` porte sur les **octets réellement transmis** et ne sert
>   qu'à valider le réassemblage des fragments. Chaque trame est déjà
>   authentifiée par AES-GCM en transit : ce qui est vérifié ici, c'est
>   l'assemblage côté agent, pas l'intégrité réseau.
>
> Sans elle, un défaut de réassemblage produirait un JSON syntaxiquement valide
> mais amputé, appliqué sans que rien ne le signale.

**La ligne `refresh:`** porte le réglage `gpo_refresh_minutes` du core, qui
pilote la boucle de rafraîchissement de l'agent. Elle est **ajoutée en queue et
reconnue à son préfixe, jamais à son rang** : un agent d'une version antérieure
lit les six champs qu'il connaît et ignore celle-ci, un core d'une version
antérieure ne l'envoie pas et l'agent garde son défaut d'une heure. Même
arbitrage que le port et l'empreinte dans `04_01`, et même recette que `sync:`
dans `03_09`.

Elle ne voyage **que** dans les réponses de scope machine. Un cycle utilisateur
est déclenché par une ouverture de session, pas par une boucle : il n'y a aucune
cadence à régler de ce côté.

### 05_03 — gpo_machine_unchanged (serveur → client)

```
<empreinte>
refresh:<minutes>    même ligne facultative qu'en 05_02
```

« Rien à faire » est le cas le plus fréquent sur un parc stable : c'est donc le
seul chemin par lequel une cadence modifiée atteint des machines dont la
politique ne bouge pas. L'omettre ici rendrait le réglage inopérant là où il
sert le plus.

### 05_04 — gpo_machine_error (serveur → client)

```
<code>
<message lisible>
```

Codes : `no_groups`, `resolve_conflict`, `restrictions_unavailable`,
`unknown_client`, `internal`.

`resolve_conflict` correspond à deux GPO du même scope réglant la même clé : le
serveur refuse de livrer plutôt que d'en choisir une arbitrairement.
`restrictions_unavailable` correspond au mode fail-closed des restrictions.

### 05_05 — ask_gpo_user (client → serveur)

```
<username_cible>
<empreinte_appliquée>
```

Le `username` de l'en-tête reste `vaultaire` (identité du client sur le tunnel) ;
`<username_cible>` est l'utilisateur qui vient de s'authentifier. Les séparer évite
de faire dépendre l'authentification du tunnel de l'utilisateur du moment.

### 05_06 — gpo_user_manifest (serveur → client)

```
<username_cible>
<version>
<empreinte>
<nb_fragments>
<taille_totale>
<nb_modules>
<somme_de_controle>
```

`<username_cible>` est repris dans la réponse : plusieurs connexions peuvent être
en cours sur la même machine, le client doit savoir à qui rattacher le manifeste.

### 05_07 — gpo_user_unchanged (serveur → client)

```
<username_cible>
<empreinte>
```

### 05_08 — gpo_user_error (serveur → client)

```
<username_cible>
<code>
<message lisible>
```

Codes : ceux de 05_04, plus `unknown_user` et `no_shared_group` (aucun groupe
commun entre la machine et l'utilisateur).

### 05_09 — ask_gpo_chunk (client → serveur)

```
<scope>            machine | user
<username_cible>   vide pour le scope machine
<empreinte>        celle du manifeste — sert de jeton de cohérence
<index_fragment>   0-based
```

L'empreinte est renvoyée à chaque fragment : si la politique change côté serveur
pendant le transfert, le serveur détecte l'écart et répond `05_11` plutôt que de
livrer un assemblage de deux politiques différentes.

### 05_10 — gpo_chunk (serveur → client)

```
<scope>
<username_cible>   vide pour le scope machine
<empreinte>
<index_fragment>
<nb_fragments>
<données...>       tout le reste de la trame, y compris les \n
```

### 05_11 — gpo_chunk_error (serveur → client)

```
<scope>
<username_cible>
<code>             stale_fingerprint | bad_index | unknown_transfer | internal
<message lisible>
```

Sur `stale_fingerprint`, le client abandonne le transfert en cours et repart d'une
demande `05_01` ou `05_05` : c'est plus simple et plus sûr que de tenter de
raccorder deux versions.

### 05_12 — gpo_apply_report (client → serveur)

```
<scope>
<username_cible>   vide pour le scope machine
<empreinte>
<statut_global>    applied | partial | failed
<module_type>|<identité>|<résultat>|<détail>     une ligne par module
```

`<résultat>` : `applied`, `unchanged`, `skipped` ou `failed`. Sans ce rapport, le
serveur n'a aucun moyen de savoir si une politique a réellement atterri sur le
parc — l'interface afficherait la configuration voulue en la faisant passer pour
la configuration réelle.

### 05_13 — gpo_apply_report_ack (serveur → client)

```
<scope>
<username_cible>
<empreinte>
```

### 05_14 — gpo_apply_report_error (serveur → client)

```
<scope>
<username_cible>
<code>             malformed_report | unknown_fingerprint | internal
<message lisible>
```

Le rapport n'est pas rejoué en cas d'erreur : il est journalisé côté client et
l'application reste valide. Un rapport perdu est un défaut d'observabilité, pas un
défaut de configuration.

### 05_15 — gpo_drift_report (client → serveur)

```
<scope>
<username_cible>   vide pour le scope machine
<nb_fichiers_vérifiés>
<nb_écarts>
<identité_module>|<type_écart>|<chemin>|<détail>     une ligne par écart
```

`<type_écart>` : `modified`, `missing`, `unreadable`, `permissions`,
`reappeared`, `system_state` ou `unverifiable`.

**Les deux scopes l'émettent.** Elle ne partait que du scope machine jusqu'à la
2.2 (TO-DO 33) ; l'agent l'émet désormais aussi pour un compte, à l'ouverture de
session et au plus une fois par cadence GPO. Rien n'a changé dans la trame : le
`<username_cible>` était déjà prévu, et le serveur rangeait déjà par
`(machine, scope, utilisateur)`.

**Pourquoi une trame distincte de 05_12.** 05_12 rapporte une *application* : ce
que l'agent vient de faire. 05_15 rapporte une *vérification* : ce qu'il
constate sans rien changer. Une machine peut avoir appliqué parfaitement il y a
trois semaines et avoir été modifiée à la main depuis — sans 05_15, elle reste
verte au tableau de bord. Confondre les deux rendrait impossible de distinguer
« appliqué avec succès » de « toujours conforme aujourd'hui ».

**Le nombre de fichiers vérifiés est envoyé même quand il n'y a aucun écart.**
Zéro écart sur zéro fichier vérifié ne veut pas dire « conforme », il veut dire
« rien n'était inventorié ». Sans ce compte, une machine dont l'inventaire est
vide s'afficherait comme parfaitement conforme.

**Le contenu des fichiers ne voyage jamais**, ni l'ancien ni le nouveau. Un
fichier géré par une GPO peut porter des clés ou des jetons ; un rapport de
conformité n'est pas un canal d'exfiltration. Seuls le chemin, le type d'écart
et un détail court sont transmis.

**Séparateur `|`.** Chemin et détail sont assainis côté agent avant l'envoi. Le
serveur découpe en quatre champs au maximum : le détail est le dernier et peut
donc contenir des séparateurs résiduels sans rendre la ligne ambiguë.

### 05_16 — gpo_drift_report_ack (serveur → client)

```
<scope>
<username_cible>
<nb_écarts_enregistrés>
```

### 05_17 — gpo_drift_report_error (serveur → client)

```
<scope>
<username_cible>
<code>             malformed_report | storage | internal
<message lisible>
```

À la différence de 05_12, un échec d'enregistrement **est** signalé ici (`storage`).
L'application, elle, est faite : la rejouer n'apporterait rien. Un scan, au
contraire, est bon marché et sera refait au cycle suivant — dire à l'agent que
le constat n'a pas été conservé lui évite de croire le serveur informé.

**La correction est locale et n'attend pas l'accusé.** L'agent efface les
empreintes des modules concernés dès le scan terminé, et les réapplique au cycle
suivant, que le rapport soit parti ou non. Une panne du serveur ne doit pas
laisser une machine en dérive.

### 05_18 — gpo_refresh_now (serveur → client)

```
<motif>            texte libre, journalisé par l'agent
```

**La seule trame 05 que le serveur émet de lui-même.** Tout le reste de la
catégorie est tiré par le client. Elle ne transporte **aucune politique** :
l'agent repart sur une `05_01` ordinaire, et tout le chemin habituel — calcul
serveur, empreinte, fragments, rapport — reste identique. Une trame de réveil
ne pouvait pas devenir un second chemin d'application, qu'il aurait fallu tenir
d'accord avec le premier.

**Rien n'est mis en file.** Une machine hors ligne ne la reçoit pas et n'en
garde aucune trace, contrairement à un ordre de révocation qui reste `pending`
en base. C'est délibéré : une machine qui revient fait de toute façon un cycle à
la reconnexion, donc rejouer la demande ferait un cycle de plus pour rien.

L'agent n'accuse pas réception : l'issue du cycle part dans les rapports `05_12`
et `05_15`, qui en disent bien plus qu'un accusé.

Émetteurs : `vlt gpo refresh <machine|--all>`, et l'action `gpo.refresh` — dont
le droit est `write:update:client` sur les domaines de la machine visée, et non
`write:update:gpo` : ce qu'on engage est le poste, pas la politique.

---

[← Principe, numérotation et séquence](./01-principe-et-sequence.md) · [Charge utile, état local, application en scope user →](./03-charge-utile-et-etat.md)
