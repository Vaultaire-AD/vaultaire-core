// Package session assemble le reste du dossier en un cycle de vie utilisable.
//
// # Ce que ce paquet fait à votre place
//
//	connexion TCP → clé publique du core → enrôlement si nécessaire
//	→ poignée de main 01 → boucle de réception → reconnexion → réenrôlement
//
// Un programme hôte n'a en principe qu'à construire une Config, brancher ses
// gestionnaires de trames sur le Spliter, et appeler Run.
//
// # Ce qu'il ne fait PAS
//
// Il n'émet aucune trame métier. Ce que votre programme a à dire au core — un
// enregistrement de service, un battement de cœur, une demande de politique — se
// branche par un rappel OnReady et par des gestionnaires sur le Spliter. Le
// paquet session ne sait rien de ce que vous êtes.
package session
