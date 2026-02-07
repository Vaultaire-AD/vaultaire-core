package sync

import (
	networksecurity "vaultaire/serveur/ducky-network/networkSecurity"
	"vaultaire/serveur/logs"
	"fmt"
)

func UpdateConnectionTrame(key string, newTrame string) error {
	value, exists := SyncMapDuckyIntegrity.Load(key)
	if !exists {
		return fmt.Errorf("clé %s introuvable", key)
	}

	connData, ok := value.(ConnData)
	if !ok {
		return fmt.Errorf("erreur de conversion des données pour la clé %s", key)
	}

	if connData.IsSafe {
		return nil
	}

	// Vérifier si la nouvelle trame suit bien l'ordre défini
	if !networksecurity.IsValidNextTrame(connData.ActualTrame, newTrame) {
		return fmt.Errorf("ordre de trame invalide : reçu %s après %s", newTrame, connData.ActualTrame)
	}

	// Mise à jour de la trame
	connData.ActualTrame = newTrame

	// Vérification si la connexion est maintenant sécurisée
	if newTrame == networksecurity.ExpectedTrames[len(networksecurity.ExpectedTrames)-1] {
		connData.IsSafe = true
		logs.Write_Log("INFO", "Connexion sécurisée pour la clé : "+key)
	}

	// Sauvegarde des mises à jour dans la SyncMap
	SyncMapDuckyIntegrity.Store(key, connData)
	return nil
}
