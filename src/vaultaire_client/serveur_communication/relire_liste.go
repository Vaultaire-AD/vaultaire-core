package serveurcommunication

import (
	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/logs"
	"vaultaire_client/serveur_communication/module"
)

// Relire la liste des nœuds quand elle a pu changer — TO-DO 187.
//
// # Le défaut
//
// La liste (04_03 -> 04_04) n'était demandée qu'au démarrage, puis à sa
// cadence — 30 minutes par défaut. Un proxy, premier de la liste d'un poste,
// change d'adresse de publication : le tunnel tombe, l'agent essaie l'ancienne
// adresse, échoue, se rabat sur un pair suivant… et garde jusqu'au tour
// suivant une liste dont le premier nœud est mort. Pendant ce temps, chaque
// `--fetch-key` de sshd — un processus neuf, qui lit la liste persistée —
// recommençait par ce pair mort (TO-DO 186, recette du 12/10).
//
// # Quand redemander
//
//   - à toute RECONNEXION : la coupure peut venir d'un changement dans le
//     cluster, et c'est le moment où l'agent a le moins de raison de croire sa
//     liste ;
//   - à la première connexion, si le nœud joint N'EST PAS le premier essayé : un
//     pair a été sauté, la liste est fausse au moins pour lui.
//
// Pas à la première connexion ordinaire : la boucle de découverte demande déjà
// la liste à son démarrage, et une seconde demande serait un doublon.
//
// La réponse remplace la liste apprise en mémoire ET persistée
// (config.MettreAJourAppris) : l'ancienne adresse d'un pair qui a changé n'y
// reste pas. Elle ne reste que si elle figure dans la liste d'installation
// (« servers »), qui n'est jamais réécrite — c'est le dernier recours.
var demanderListe = decouverte.DemanderMaintenant

func relireListeSiBesoin(e module.EtatConnexion) {
	if motif := motifDeRelecture(e); motif != "" {
		logs.Write_log("INFO", "découverte : liste redemandée ("+motif+")")
		demanderListe()
	}
}

// motifDeRelecture dit pourquoi relire la liste, ou "" s'il n'y a pas lieu.
func motifDeRelecture(e module.EtatConnexion) string {
	switch {
	case e.Etablissements > 1:
		return "reconnexion"
	case len(e.Essayees) > 0 && e.Adresse != e.Essayees[0]:
		return "le premier nœud de la liste (" + e.Essayees[0] + ") n'a pas répondu"
	}
	return ""
}
