// Package dbsessions porte les sessions ouvertes et leur expiration : table
// did_login, rattachement utilisateur ↔ machine, et l'état « qui est connecté ».
//
// Dépend de dbclients et dbusers pour résoudre les identifiants.
package dbsessions

// Fonction retirée, conservée en mémoire.
//
// get_id_logiciel a été retirée au profit de dbclients.Get_ClientID_By_ComputerID.
// Elle posait la même requête, mais avec trois défauts que le helper n'a pas :
// pas de sanitisation de l'entrée, une chaîne vide indistinctement retournée
// pour « introuvable » et pour « erreur de base », et une variable de retour
// nommée `publicKey` alors qu'elle contient un identifiant.
