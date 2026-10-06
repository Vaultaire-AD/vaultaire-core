// Package dbjournaux tient le journal COMMUN des cores, en base (TO-DO 91).
//
// # Le problème
//
// Chaque core journalisait chez lui : sur sa sortie standard et dans une
// mémoire de dix mille lignes. Avec plusieurs cores, il fallait deviner lequel
// avait traité une requête avant de pouvoir lire quoi que ce soit, et le
// portail n'affichait que les journaux du core qui le servait — c'est-à-dire,
// derrière une répartition de charge, un core au hasard.
//
// # Pourquoi la base, et pas un service de journalisation
//
// La base est déjà le point de rendez-vous du cluster : tous les cores la
// joignent, et elle est sauvegardée. Un service de plus serait à installer, à
// authentifier et à superviser — et sa panne ferait perdre les journaux au
// moment précis où l'on en a besoin. Décision du 24/09.
//
// # Ce qui part en base
//
// Tout, SAUF le DEBUG. Le DEBUG n'est émis qu'en mode debug, un réglage de
// diagnostic qu'on allume quelques minutes ; c'est aussi, et de loin, le niveau
// le plus bavard — une ligne par contrôle de droit. Le centraliser ferait de
// chaque séance de diagnostic une croissance brutale de la table.
//
// Pas de seuil plus haut : l'audit des écritures (« alice a fait
// group.add_user… ») est en INFO. Un seuil à WARNING rendrait le journal commun
// muet sur la seule question qu'on lui pose le plus souvent — qui a changé quoi.
//
// # Ce qui tient la table
//
//   - la RÉTENTION, réglable (`log_retention_days`), purgée au démarrage puis à
//     la cadence de `log_purge_hours`. Ce n'est pas une commodité d'affichage :
//     une table de journaux sans borne remplit le disque de la base, et
//     emporte l'annuaire avec elle ;
//   - la FILE BORNÉE de l'écrivain : un core qui s'emballe perd des lignes en
//     base (en le disant) plutôt que de saturer la base ou sa propre mémoire.
//
// La sortie standard, elle, reste complète : c'est toujours la source d'un
// core pris isolément.
package dbjournaux
