package action

import "vaultaire/core/permission"

// Les huit lectures de domaines dont dépendent les portées, isolées derrière des
// variables.
//
// # Ce que cela débloque
//
// Une portée répond à « sur quels domaines la clé est-elle exigée ? », et la
// réponse se lit en base : les domaines d'un compte, d'un groupe, d'une
// permission. Tant que ces lectures étaient appelées en dur, **aucune portée ne
// pouvait être éprouvée sans conteneur** — et `database.GetDatabase()` rendant
// un `*sql.DB` nul, l'appel ne rendait pas une erreur mais PANIQUAIT, emportant
// le binaire de test du paquet entier.
//
// Les écritures avaient déjà été affranchies (voir `bases_simulees_test.go`).
// Les portées restaient le dernier chemin qui exigeait une base, et c'est le
// plus gênant des deux : la portée EST le mécanisme de délégation. La règle
// « une écriture exige le droit sur TOUS les domaines de la cible » est ce qui
// empêche un délégué de Paris d'agir sur un compte à cheval sur Lyon, et elle
// n'était vérifiée par aucun test.
//
// # Pourquoi des variables et non une interface
//
// `Executeur` porte déjà `Portees ResolveurPortee`, qui substitue la résolution
// **au niveau de l'exécuteur**. C'est ce qu'emploie le testrunner pour sa
// matrice RBAC, et cela reste la bonne voie pour éprouver le CONTRÔLE.
//
// Ce qu'elle ne permet pas, c'est d'éprouver les fonctions de portée
// elles-mêmes — l'union de deux ensembles de domaines, le repli sur « * » quand
// la cible n'en a aucun. Or ce repli est une décision de sécurité : sans lui,
// `CheckPermissionsAllDomains` sur une liste vide n'a rien à vérifier et
// autorise tout le monde. L'entité la moins rattachée serait alors la plus
// accessible.
//
// Ces variables ouvrent ce niveau-là, sans rien changer à l'autre.
//
// # Le champ d'application, et sa limite
//
// Seules les lectures atteintes par une PORTÉE sont ici. Le paquet compte
// soixante-seize points d'entrée vers la base ; poser une variable sur chacun
// serait un remaniement massif pour couvrir un besoin qui en concerne huit. Le
// critère retenu, ici comme pour les écritures, est : **ce qu'un test traverse
// réellement**.
//
// `perimetre.go` n'est pas concerné : le filtrage passe par l'interface
// `Perimetre`, que les tests implémentent déjà.
var (
	domainesDeLUtilisateur     = permission.GetDomainListFromUsername
	domainesDuGroupe           = permission.GetDomainsFromGroupName
	domainesDeLaMachine        = permission.GetDomainsFromClientByComputerID
	domainesDeLaPermissionUtil = permission.GetDomainslistFromUserpermission
	domainesDeLaPermissionCli  = permission.GetDomainslistFromClientpermission
	domainesDeLaGPO            = permission.GetDomainslistFromGPO
	groupesDeLUtilisateur      = permission.GetGroupIDsFromUsername
	domainesDesGroupes         = permission.GetDomainListsFromGroupIDs
)
