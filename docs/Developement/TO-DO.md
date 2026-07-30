

[FAIT] GPO -> Faire en sorte que toutes les restrictions ne soit pas stocké en JSON mais dans le DB et puisse etre editable (uniquement par les membres du groupe vaultaire)
       Tables gpo_restriction + gpo_field_rule, page /admin/gpo/restrictions réservée au groupe vaultaire.
       Modes par champ : liste / motif (regex) / libre, avec motif d'exclusion prioritaire — c'est ce qui
       permet à un client de déclarer un service de monitoring maison sans toucher au code.
       Socle par défaut = anciennes listes en dur, réécrivable via « Réinitialiser ».
[FAIT] Immuabilité de l'identité d'amorçage : user vaultaire, groupe vaultaire, permissions vaultaire_all
       et vaultaire_admin non supprimables / non renommables (core/database/protected.go, refus posés dans
       la couche base pour couvrir CLI, web, LDAP et API par construction).
PAM -> Verification du module login (pb pour la création des users si il existe pas)
PAM -> Ajout d'une mecanique pour mettre a jour le mot de passe de l'utilisateur en local
PAM -> Verification de l'expiration des comptes sur les clients
GPO -> Gère la transmission des GPO au client (quand un user se co on applique les GPO user liées a son groupe) (quand un client se connecte on applique toutes les GPO machine via ses differenet groupe ATTNETION bonne pratique il faudrai dans l'ideal pour les GPO machine quelle soit toutes regroupe dans un groupe sans user qui sert juste a appliquer les GPO machine pour l'organistion)