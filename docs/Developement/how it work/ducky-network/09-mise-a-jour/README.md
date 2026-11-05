[⌂ Ducky Network](../README.md) › Chapitre 9

# Chapitre 9 — Ordre de mise à jour d'un agent (09)

[← Chapitre 8 — Authentification par un service (08)](../08-authentification-service/README.md) · [Index →](../README.md)

---

Comment le core dit à un agent quelle version prendre, et comment l'agent en
rend compte *(TO-DO 115, 116)* ; et le compte rendu de sa configuration
système *(TO-DO 117)*. La conception d'ensemble — signature, dépôt,
basculement — est dans [`Mise_a_jour_du_parc.md`](../../../Mise_a_jour_du_parc.md).

## Principe

Le modèle de la révocation (`06`), repris tel quel :

- **rattrapage par demande** : l'agent demande son ordre (`09_01`) à chaque
  connexion — au démarrage et à chaque tunnel rétabli ;
- **poussée opportuniste** (`09_06`) : chaque core, toutes les minutes, pousse
  l'ordre aux agents **connectés à lui** qui en ont un. Un échec d'envoi n'est
  pas une erreur ; personne ne tient de file. La base est commune : une cible
  posée sur un core atteint en une minute une machine tenue par un autre.

**Il n'y a pas de table d'ordres.** L'ordre se déduit de la version attendue
(dérogation, groupes, parc — point 111), de la version déclarée (`02_12`) et du
dernier compte rendu. Décision : `core/miseajour.Decider`.

## Les trames

| Trame | Sens | Contenu |
|---|---|---|
| `09_01` | agent → core | *(vide)* — la machine est celle de l'en-tête authentifié |
| `09_02` | core → agent | `<version>` · `<dépôt>` · `oui`\|`non` (rétrogradation) |
| `09_03` | core → agent | `<motif>` — rien à faire |
| `09_04` | agent → core | `<version>` · `<résultat>` · `<motif>` |
| `09_05` | core → agent | *(vide)* — accusé |
| `09_06` | core → agent | comme `09_02`, sans demande |
| `09_07` | agent → core | `<état>` · `<motif>` — la configuration système (TO-DO 117) |
| `09_08` | core → agent | *(vide)* — accusé de la `09_07` |
| `09_09` | agent → core | `<numéro du jeu de clés tenu>` (TO-DO 207) |
| `09_10` | core → agent | `a_jour`, ou `<numéro>` · `<corps en base64>` · `<enveloppe en base64>` — le jeu suivant |

Résultats : `installe`, `echec` (tentée, revenue en arrière), `refuse` (rien
tenté : rétrogradation non demandée, signature…), `non_pris_en_charge`
(l'agent ne sait pas se mettre à jour : l'agent Windows, un agent Linux hors
systemd ou pas en root).
Les mêmes chaînes dans le core et les deux agents, figées par des tests.

## Les règles

| Situation de la machine | Réponse à `09_01` / poussée |
|---|---|
| aucune cible | `09_03` « aucune version attendue » — **le défaut** |
| à jour | `09_03` |
| en avance | `09_03` — **jamais rétrogradée d'office** |
| en retard, ou version inconnue | `09_02` / `09_06` |
| en retard, et le dernier compte rendu **de cette version** est un échec | `09_03` « dernier essai… » — sinon elle retenterait à chaque reconnexion un basculement qui casse |

`vlt agent update <machine>` efface le compte rendu et pousse l'ordre ;
`--downgrade` y vaut poussé, à une machine connectée à ce core. La
rétrogradation **durable** est portée par la dérogation (TO-DO 204) :
`vlt agent pin <machine> <version> --downgrade` pose
`id_logiciels.agent_target_downgrade`, et la `09_02` porte alors `oui` tant que
la machine est en avance sur sa dérogation — à sa prochaine demande, depuis
n'importe quel core. Le drapeau tombe au compte rendu `installe` de cette
version. Une cible de groupe ou de parc ne rétrograde jamais.

| Situation de la machine | Réponse |
|---|---|
| en avance, cible = dérogation **avec** `--downgrade` | `09_02` / `09_06` avec `oui` (journal `SECURITY`) |
| la même, dernier compte rendu de cette version en échec | `09_03` « dernier essai… » |

L'agent, lui, **refuse toute version inférieure à la sienne** sans le drapeau de
rétrogradation (`SECURITY` des deux côtés) : il faudrait le dépôt **et** le
tunnel pour lui faire installer une version ancienne.

## Quand part le compte rendu

L'agent ne répond **pas** en `09_04` à l'ordre qui lance une installation :
elle prend des minutes et redémarre l'agent. Le déroulé (point 116) :

| Étape | Compte rendu |
|---|---|
| version déjà en place, rétrogradation non demandée, agent qui ne peut pas se remplacer | **immédiat**, en réponse à l'ordre |
| une mise à jour déjà en cours (verrou) | aucun — l'ordre est ignoré |
| téléchargement impossible (dépôt muet, TLS) | **aucun** : transitoire, le core redonnera l'ordre (poussée horaire, ou à la prochaine connexion) |
| refus de la préparation (signature, empreinte, `ldd`, `--check`, distribution) | `refuse`, dès que l'agent tient une session |
| bascule : porte de santé franchie / retour arrière | `installe` / `echec`, envoyé **par l'agent qui redémarre** |

Le résultat différé passe par `/var/lib/vaultaire/updates/etat.json`, écrit par
celui qui le connaît (l'agent ou l'updater) et marqué `rapporte` une fois la
`09_04` émise. Il part avant la demande `09_01` de la nouvelle session : le
core range le compte rendu, puis répond « à jour » à la demande.

## Qui émet quoi, et vers qui

| | |
|---|---|
| `09_01`, `09_04` | accordées au type `vaultaire_client` (`core/clienttype`) |
| poussée `09_06` | seulement aux agents qui déclarent au moins **2.3.0** (`miseajour.VersionQuiComprend`) : un plus ancien n'a pas de gestionnaire |
| émission par l'agent | seulement vers un core qui annonce la capacité **`miseajour`** dans sa `02_11` — un core plus ancien **fermerait la connexion** sur une trame qu'il ne connaît pas. Vaut aussi pour la `04_15` des dépôts (TO-DO 114) |
| agent Windows | ne demande pas ; reçoit les poussées et répond `non_pris_en_charge` (point 118) |
| `09_07` | accordée au type `vaultaire_client` ; émise seulement vers un core qui annonce **`confsys`** — une capacité à part : un core du 115 ou du 116 connaît `miseajour` sans connaître la `09_07` |

| `09_09` | accordée au type `vaultaire_client` ; émise seulement vers un core qui annonce **`clespaquets`** |

## Les clés de confiance des paquets — `09_09`, `09_10`

La rotation de `pkg_signing` (TO-DO 207). Le **jeu** est la liste complète des
clés de confiance et un numéro croissant, signés (RSA-PSS, même enveloppe que
les manifestes, en-tête `vaultaire-pkg-trust-v1` distinct) :

```
vaultaire-pkg-trust-v1
3
cle <DER PKIX en base64>
cle <DER PKIX en base64>
```

- L'agent dit le numéro qu'il tient (`09_09`) ; le core le range
  (`id_logiciels.agent_pkg_trust`) et répond le **plus petit** jeu au-dessus, ou
  `a_jour`. Le core garde tous les jeux (`pkg_trust_sets`) : chaque jeu est signé
  par l'active du jeu précédent, l'agent remonte la chaîne seul.
- L'agent n'applique qu'un jeu plus haut que le sien, signé par une clé qu'il
  tient : un proxy, un réseau, un core sans la clé ne peuvent rien y ajouter.
  Après un jeu appliqué, sa réponse est la `09_09` suivante, avec son nouveau
  numéro.
- Demande à chaque session neuve et toutes les heures.
- Une clé **compromise** ne passe pas par ce canal : son jeu est signé par une
  clé que l'agent ne tient pas, il est refusé (`SECURITY`) — réinstallation.
- Format jumeau : `core/paquetagent/jeu.go` et `vaultaire_client/paquet/jeu.go`,
  figés par un vecteur commun.

## La configuration système — `09_07`

Une fois par démarrage, l'agent Linux remet ses piles PAM, `sshd_config`,
`nsswitch.conf` et la liste de l'écran de connexion à la version de son code
(`vaultaire_client/confsys`), puis rend compte :

| État | Sens |
|---|---|
| `conforme` | rien à écrire |
| `reconciliee` | fichiers réécrits — le motif les nomme, `ssh/sshd_config v0→v1` |
| `ecart` | un contrôle a refusé (`sshd -t`, porte de secours, pile non branchable) : rien d'écrit pour le groupe en cause |
| `desactivee` | `reconcile_system_config: false` sur la machine |
| `non_pris_en_charge` | agent pas en root, distribution inconnue |

Les mêmes chaînes côté core (`core/miseajour/configuration.go`) et agent,
figées par des tests. L'état est gardé dans `/var/lib/vaultaire/confsys/etat.json` ;
le même constat qu'au démarrage précédent, déjà rapporté, ne repart pas. Rangé
dans `id_logiciels.agent_conf_{state,reason,at}` ; colonne CONFIGURATION de
`vlt agent`.

## Code

| Côté | Où |
|---|---|
| décision | `vaultaire_serveur/core/miseajour` |
| trames et poussée | `vaultaire_serveur/ducky-network/miseajour_manager` |
| compte rendu en base | `id_logiciels.agent_update_{version,result,reason,at}` |
| agent Linux | `vaultaire_client/miseajour` — `ordre.go` (trames), `appliquer.go` (lancement, compte rendu différé), `preparation.go`, `bascule.go` |
| sonde de la porte de santé | `vaultaire_client/pam_communication/ping.go` — `{"ping":{}}` sur le socket PAM |
| agent Windows | `vaultaire_client_windows/gpo/ignore.go` |
| configuration système | `vaultaire_client/confsys` ; côté core, `miseajour_manager` (`09_07`) et `id_logiciels.agent_conf_*` |
| jeux de clés des paquets | `core/paquetagent` (`jeu.go`, `rotation.go`), `key_management/rotation_paquets.go`, `miseajour_manager` (`09_09`) ; agent : `vaultaire_client/miseajour/cles.go`, `paquet/jeu.go` |

---

[← Chapitre 8 — Authentification par un service (08)](../08-authentification-service/README.md) · [Index →](../README.md)
