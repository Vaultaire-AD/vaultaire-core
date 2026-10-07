[⌂ Ducky Network](../README.md) › [Chapitre 6 — Révocation — kill switch (06)](./README.md) › 6.2

# 6.2 — Les trames 06_01 à 06_06

[← Principe et séquence](./01-principe-et-sequence.md) · [RBAC, schéma de base et décisions →](./03-rbac-schema-et-decisions.md)

---


### 06_01 — revoke_order (serveur → client)

```
06_01
serveur_central
<session_integrity_key>
<order_id>            identifiant unique de l'ordre
<mode>                soft | unlock | hard
<username>            nom d'annuaire (bob.durand) ou forme complète (bob.durand@acme.lan)
<reason_code>         compromised | offboarding | admin_request
```

`<username>` est ce que l'exploitant a tapé à l'émission, et le nom d'annuaire —
court — quand l'ordre est rejoué par `06_05`. Cette page exigeait « la forme
complète, domaine compris » ; rien ne la garantissait, et un nom court ne
verrouillait rien (TO-DO 133). L'agent résout désormais les deux : voir
[Quel compte, sur la machine](./01-principe-et-sequence.md#quel-compte-sur-la-machine).

`reason_code` est un code fermé, jamais du texte libre : le motif détaillé reste
côté serveur. Une raison saisie par un administrateur n'a pas à voyager jusqu'à
une machine potentiellement compromise, et du texte libre sur le fil est une
surface d'injection dans les journaux de l'agent.

### 06_02 — revoke_ack (client → serveur)

```
06_02
serveur_central
<session_integrity_key>
<username_de_session>
<client_software_id>
<order_id>
<result>              applied | already_absent | not_applicable
```

`already_absent` (compte local inexistant) et `not_applicable` sont des succès,
pas des erreurs : une machine où l'utilisateur ne s'est jamais connecté n'a rien
à faire, et le signaler comme un échec provoquerait des réessais sans fin.

`applied` veut dire, en mode `soft` comme en `hard`, que le compte est verrouillé
**et** qu'il ne lui reste aucun processus sur la machine. Un compte verrouillé
dont des processus survivent est un `06_03` (`command_failed`), pas un `06_02`.

### 06_03 — revoke_error (client → serveur)

```
06_03
...
<order_id>
<code>                unknown_mode | command_failed | permission_denied | internal
<message>
```

### 06_04 — ask_revocations (client → serveur)

```
06_04
serveur_central
<session_integrity_key>
<username_de_session>
<client_software_id>
```

Aucun contenu : le serveur connaît déjà la machine, puisque le
`ClientSoftwareID` est figé à la poignée de main et vérifié à chaque trame.

Émise au démarrage de l'agent, à chaque tunnel rétabli, puis toutes les dix
minutes (TO-DO 134) — voir
[Quand l'agent réclame ses ordres](./01-principe-et-sequence.md#quand-lagent-réclame-ses-ordres).
Un agent antérieur à la 2.2 ne l'émet qu'à son démarrage.

### 06_05 — revocations_list (serveur → client)

```
06_05
serveur_central
<session_integrity_key>
<nombre_d_ordres>
<order_id>|<mode>|<username>|<reason_code>
<order_id>|<mode>|<username>|<reason_code>
...
```

Plafonné à 200 ordres par trame ; au-delà, le client rappelle 06_04. Un ordre
pèse une centaine d'octets, la limite utile d'une trame est d'environ 48 Kio.

**Réponse à une `06_04`, ou poussée** *(TO-DO 49)*. Le core l'envoie aussi de
lui-même quand il rejoue : voir
[Quand le core rejoue de lui-même](./01-principe-et-sequence.md#quand-le-core-rejoue-de-lui-même).
La trame est la même dans les deux cas, et l'agent ne les distingue pas : il
applique la liste dans l'ordre et acquitte chaque ordre. C'est ce qui permet au
rejeu d'atteindre un agent antérieur, sans trame nouvelle.

Elle ne porte que ce qui reste **à rejouer** : les cibles `pending` ou `failed`.
Un verrouillage levé avant d'avoir été acquitté (`lifted`) n'y figure plus.

### 06_06 — revocations_error (serveur → client)

```
06_06
serveur_central
<session_integrity_key>
<code>
<message>
```

## Idempotence

Un ordre peut arriver deux fois — et, depuis que le core rejoue, bien plus :
poussé, rejoué par le core, redemandé par l'agent, réémis après un acquittement
perdu. Les trois modes sont naturellement
idempotents (`usermod -L` deux fois de suite, `userdel` sur un compte absent),
et l'agent tient la liste des `order_id` déjà appliqués dans son état local, à
côté de `applied_policies.json`. Un ordre déjà appliqué est ré-acquitté sans
être rejoué.

---

[← Principe et séquence](./01-principe-et-sequence.md) · [RBAC, schéma de base et décisions →](./03-rbac-schema-et-decisions.md)
