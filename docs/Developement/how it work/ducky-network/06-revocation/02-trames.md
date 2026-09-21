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
<username>            forme complète, domaine compris (admin@vaultaire.fr)
<reason_code>         compromised | offboarding | admin_request
```

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

### 06_06 — revocations_error (serveur → client)

```
06_06
serveur_central
<session_integrity_key>
<code>
<message>
```

## Idempotence

Un ordre peut arriver deux fois : poussé puis rejoué après une reconnexion, ou
réémis après un acquittement perdu. Les trois modes sont naturellement
idempotents (`usermod -L` deux fois de suite, `userdel` sur un compte absent),
et l'agent tient la liste des `order_id` déjà appliqués dans son état local, à
côté de `applied_policies.json`. Un ordre déjà appliqué est ré-acquitté sans
être rejoué.

---

[← Principe et séquence](./01-principe-et-sequence.md) · [RBAC, schéma de base et décisions →](./03-rbac-schema-et-decisions.md)
