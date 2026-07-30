package gpomanager

import (
	"fmt"

	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// GPO_Manager répond à une demande de GPO d'un client (trame 02_16).
//
// La transmission au client n'est pas encore implémentée : l'ancien mécanisme
// envoyait une commande shell par distribution, que le client exécutait en root.
// Le modèle déclaratif (core/gpo) le remplace, mais son transport exige d'abord
// deux briques qui n'existent pas encore :
//
//   - une catégorie de trame dédiée (04_XX) transportant la politique fusionnée
//     par scope avec sa version, plutôt qu'une liste de commandes ;
//   - la signature de la politique par le serveur central, vérifiée par l'agent
//     avant toute application.
//
// Tant que ces deux points ne sont pas en place, on répond explicitement au
// client plutôt que de lui transmettre quelque chose qu'il ne saurait pas
// vérifier. Le côté serveur (catalogue, stockage, résolution, RBAC) est en
// revanche complet : Get_GPO_forClient calcule déjà la politique effective.
func GPO_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	machine, user, err := Get_GPO_forClient(trames_content.Username, trames_content.ClientSoftwareID)
	if err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("gpo: résolution impossible pour le client %s (utilisateur %s) : %v",
			trames_content.ClientSoftwareID, trames_content.Username, err))
		return "02_16\nserveur_central\n" + trames_content.SessionIntegritykey + "\nfailed to resolve GPO"
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"gpo: politique effective résolue pour %s sur %s — %d module(s) machine, %d module(s) user ; transmission non encore implémentée",
		trames_content.Username, trames_content.ClientSoftwareID, len(machine.Modules), len(user.Modules)))

	return "02_16\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" +
		trames_content.Username + "\ngpo transport not implemented"
}
