package gpo

import (
	"duckynetworkclient/V1/duckynetwork/storage"
)

// HandleTrameGPO branche la catégorie 05 sur le registre du socle.
//
// # Ce que l'adaptateur préserve
//
// Le contrôle `len(Message_Order) > 1`, qui vivait dans l'ancien Spliter de
// l'agent. Sans lui, une trame « 05 » sans sous-ordre — malformée, tronquée,
// forgée — indexerait hors bornes et ferait paniquer la boucle de réception,
// donc tomber le processus entier : plus de GPO, plus de révocation, plus de
// canal PAM.
//
// # Pourquoi la réponse est vide
//
// Les réponses GPO sont traitées de façon ASYNCHRONE : le paquet réveille le
// cycle en attente et enchaîne lui-même les demandes de fragments. Répondre ici
// enverrait une trame de plus, non attendue par le core.
//
// Le socle n'émet rien sur une chaîne vide — voir sendmessage.SendMessage —,
// donc rendre « » est bien « ne rien répondre », et non « répondre du vide ».
func HandleTrameGPO(trames storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(trames.Message_Order) <= 1 {
		return ""
	}
	HandleTrame(trames.Message_Order[1], trames.SessionIntegritykey, trames.Content)
	return ""
}
