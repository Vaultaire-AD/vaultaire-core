// Package dbsettings lit et écrit les réglages serveur de la table
// server_settings.
//
// # Pourquoi ce paquet existe
//
// server_settings est une table clé/valeur générique : le projet n'avait aucun
// endroit où poser un réglage serveur, et il en vient d'autres. Son seul
// accesseur vivait pourtant dans dbauthpolicy, le paquet du second facteur et de
// l'expiration des mots de passe. Y ajouter un réglage de cluster aurait fait
// dépendre le cluster de l'authentification pour une raison qui n'a rien à voir.
//
// # Le typage est ici, pas en base
//
// La contrepartie d'une table clé/valeur est l'absence de typage. Elle est
// absorbée ici : chaque lecture est bornée, chaque écriture validée. Aucun
// appelant ne lit cette table directement, et une valeur aberrante trouvée en
// base — saisie à la main, écrite par une version antérieure — retombe sur le
// défaut plutôt que de se propager.
package dbsettings
