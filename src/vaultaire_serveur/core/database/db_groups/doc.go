// Package dbgroups porte les groupes et les appartenances.
//
// IsUserInGroup n'est PAS ici mais dans le socle, à contre-courant du reste :
// les gardes d'immuabilité en ont besoin, et le socle ne peut importer aucun
// sous-paquet sans créer un cycle. Voir la documentation du paquet database.
package dbgroups

// Fonction retirée, conservée en mémoire.
//
// DeleteGroup a été supprimée : code mort ET cassé. Aucun appelant dans tout le
// dépôt, et surtout elle visait deux tables qui n'existent pas —
// `group_permission` et `groupe`. Le schéma réel porte `group_user_permission`,
// `group_permission_logiciel` et `groups`. Elle aurait échoué à la première
// exécution, sur une erreur MySQL de table inconnue.
//
// C'est le danger de ce genre de reste : le nom est parfaitement plausible, la
// signature aussi, et quiconque aurait cherché « comment supprimer un groupe »
// l'aurait appelée en toute confiance. La suppression d'un groupe passe par
// Command_DELETE_GroupWithGroupName, qui connaît le vrai schéma.
