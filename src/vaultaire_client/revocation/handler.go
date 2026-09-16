package revocation

import (
	"duckynetworkclient/V1/duckynetwork/storage"
)

// HandleTrameRevocation branche la catégorie 06 sur le registre du socle.
//
// # Synchrone, contrairement aux GPO
//
// L'agent applique l'ordre puis acquitte IMMÉDIATEMENT, et le core compte sur
// cet acquittement pour cesser de rejouer. La réponse de HandleTrame part donc
// telle quelle, là où le gestionnaire GPO rend toujours « ».
//
// Même garde que pour les GPO : une trame « 06 » sans sous-ordre indexerait hors
// bornes et ferait tomber tout le processus.
func HandleTrameRevocation(trames storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(trames.Message_Order) <= 1 {
		return ""
	}
	return HandleTrame(trames.Message_Order[1], trames.SessionIntegritykey, trames.Content)
}
