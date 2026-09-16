// Package dbldap porte les lectures dédiées au module LDAP.
//
// Elles sont séparées parce qu'elles retournent des structures ldapstorage et
// non les structures d'affichage du CLI : ce sont les mêmes données, façonnées
// pour un consommateur différent. Voir le point de vigilance de
// TO-DO_Database.md sur les trois « utilisateurs d'un groupe », qui ne sont pas
// des doublons.
package dbldap

// Fonction retirée, conservée en mémoire.
//
// GetUsersByGroups (au pluriel) a été supprimée : aucun appelant. Elle bouclait
// sur GetUsersByGroup en dédoublonnant par nom d'utilisateur — donc N requêtes
// pour N groupes. Si le besoin revient, il vaudra mieux une seule requête avec
// une clause IN qu'une boucle : c'est la même donnée en un aller-retour au lieu
// de N.
