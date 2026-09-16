// Package dbusers porte les utilisateurs de l'annuaire : cycle de vie, lecture,
// mot de passe et clés publiques SSH.
//
// Les clés viennent de l'ancien paquet db-user, qui n'avait pas de raison
// d'exister à part : une clé publique est un attribut de compte, et la séparer
// obligeait à connaître deux paquets pour répondre à « que sait-on de cet
// utilisateur ».
//
// Dépend de dbdomains (domaine principal) et du socle.
package dbusers
