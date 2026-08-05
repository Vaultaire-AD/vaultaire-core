// Package dbenrollment porte les clés d'enrôlement des clients service.
//
// Un client SERVICE — interface web, proxy, extensions futures — n'est pas créé
// à l'avance sur le core comme un agent de poste. Il s'enrôle seul à sa première
// connexion : il génère sa paire de clés localement, puis présente une clé
// d'enrôlement pour faire enregistrer sa clé publique.
//
// # Ce que la clé porte
//
// Un TYPE, une EXPIRATION et un QUOTA d'utilisations.
//
// Le type est le point de sécurité central. Le client ne le déclare pas : il le
// reçoit de la clé. S'il l'annonçait, n'importe quel service enrôlé pourrait se
// dire `vaultaire_web` et obtenir avec lui le droit d'agir au nom de n'importe
// quel utilisateur de l'annuaire. Le type vient de la clé, la clé vient d'un
// administrateur : le service n'a aucune prise sur ses propres privilèges.
//
// # Seul le condensat est stocké
//
// Comme un mot de passe. Le secret est affiché une fois à l'émission et n'est
// jamais réécrit nulle part. Une fuite de la base ne rend aucune clé utilisable.
package dbenrollment
