package sshclient

import (
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbgroups "vaultaire/core/database/db_groups"
	"vaultaire/core/logs"
	"vaultaire/core/reglages"
	"vaultaire/core/storage"
)

// Synchronisation des groupes du domaine sur une machine du parc.
//
//	03_08  demande            (agent → core)   contenu vide
//	  03_09  liste            (core → agent)   sync:<minutes> puis <nom>:<id_group>
//	  03_10  refus            (core → agent)   <raison>
//
// # Pourquoi la catégorie 03
//
// La catégorie 01 traite l'identité de la MACHINE — enrôlement, authentification
// du poste. La catégorie 03 traite les identités qu'elle porte : les
// utilisateurs, et maintenant les groupes. Un groupe est un objet d'annuaire,
// pas un attribut du poste.
//
// # Ce que la trame porte, et ce qu'elle ne porte pas
//
// Des `id_group`, PAS des GID. Le calcul appartient au code des deux côtés (voir
// dbgroups.GIDDeGroupe). Envoyer le numéro déjà calculé aurait laissé un serveur
// en imposer un arbitraire — dont 0, qui est `root`.
//
// # La cadence voyage avec la liste
//
// `group_sync_minutes` est un réglage du core (voir core/reglages), mais la
// boucle qu'il pilote tourne sur l'AGENT. Deux façons de l'y faire arriver :
// une constante côté agent, ou la valeur dans la réponse.
//
// La constante aurait reproduit un défaut déjà nommé dans ce dépôt —
// `IntervalleRapportAgent` duplique `gpo.MachineRefreshInterval`, et allonger
// l'un sans l'autre fait apparaître tout le parc en retard du jour au lendemain.
// Surtout, un réglage qui s'affiche dans l'interface sans rien changer au
// comportement est plus trompeur que pas de réglage du tout.
//
// La valeur part donc dans `03_09`. Une machine hors ligne l'applique à son
// retour, pas avant : c'est écrit dans la conséquence du réglage.

// PrefixeCadence ouvre la ligne de cadence dans la réponse 03_09.
//
// Comme `PrefixeGroupes`, cette chaîne est déclarée des deux côtés et figée par
// des tests jumeaux : rien ne peut la tenir liée à la compilation.
const PrefixeCadence = "sync:"

// SSH_SEND_GroupSync répond à une demande de synchronisation des groupes.
//
// # Ce que la demande ne contient pas
//
// Rien. L'identifiant de la machine est lu dans l'en-tête de la trame, où il a
// été posé par la couche de session — donc authentifié. Le lire dans le contenu
// aurait laissé n'importe quel agent réclamer les groupes d'un autre, c'est-à-dire
// la structure d'un domaine auquel il n'appartient pas.
func SSH_SEND_GroupSync(trames_content storage.Trames_struct_client) string {
	machine := trames_content.ClientSoftwareID
	if strings.TrimSpace(machine) == "" {
		logs.Write_Log("ERROR", "03_08 sans identifiant de machine : demande ignorée")
		return refusGroupSync(trames_content, "identifiant de machine absent")
	}

	db := database.GetDatabase()
	groupes, err := dbgroups.GroupesDesDomainesDeLaMachine(db, machine)
	if err != nil {
		logs.Write_Log("ERROR", "03_08 de "+machine+" : lecture des groupes impossible : "+err.Error())
		// Un refus EXPLICITE plutôt que le silence. L'agent qui ne reçoit rien
		// attend puis abandonne son cycle sans rien pouvoir en dire ; l'agent qui
		// reçoit un refus le journalise et garde ses groupes actuels, ce qui est
		// exactement la bonne conduite devant une base indisponible.
		return refusGroupSync(trames_content, "liste des groupes indisponible")
	}

	lignes := make([]string, 0, len(groupes)+1)
	lignes = append(lignes, PrefixeCadence+strconv.Itoa(minutesDeSynchro()))

	var ecartes int
	for _, g := range groupes {
		ligne, err := dbgroups.LigneDeGroupe(g)
		if err != nil {
			// Écarté, pas fatal : un groupe hors borne ou au nom impossible ne
			// doit pas emporter la synchronisation des autres. En ERROR parce que
			// c'est une anomalie de la base, pas un cas de fonctionnement.
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"03_09 : groupe non annonçable à "+machine+" : "+err.Error())
			ecartes++
			continue
		}
		lignes = append(lignes, ligne)
	}

	if ecartes > 0 {
		logs.Write_Log("WARNING", machine+" : "+strconv.Itoa(ecartes)+
			" groupe(s) écarté(s) de la synchronisation — la machine ne les créera pas")
	}
	logs.Write_Log("INFO", "Synchronisation des groupes pour "+machine+" : "+
		strconv.Itoa(len(lignes)-1)+" groupe(s), cadence "+
		strconv.Itoa(minutesDeSynchro())+" min")

	return "03_09\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" +
		strings.Join(lignes, "\n")
}

// refusGroupSync rend une 03_10.
//
// Le motif est volontairement GROSSIER — « indisponible », jamais le détail de
// l'erreur SQL. La trame part vers une machine du parc, dont le journal est
// lisible par qui a un accès local ; y écrire la structure de la base ou le nom
// d'une table est un renseignement gratuit.
func refusGroupSync(trames_content storage.Trames_struct_client, motif string) string {
	return "03_10\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + motif
}

// minutesDeSynchro lit la cadence, en repliant sur le défaut du catalogue.
//
// reglages.Valeur applique déjà ses bornes et son défaut ; l'appel est isolé ici
// pour que la trame ne dépende que d'un entier, et pour qu'un test puisse la
// vérifier sans base.
func minutesDeSynchro() int {
	return reglages.Valeur(reglages.CleSynchroGroupes)
}
