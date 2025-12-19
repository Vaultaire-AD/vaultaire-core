package sync

import (
	"DUCKY/serveur/logs"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

var SyncMapDuckyIntegrity *sync.Map

type ConnData struct {
	ActualTrame string
	ComputeurID string
	IsSafe      bool
}

func Sync_InitMapDuckyIntegrity() {
	// Initialisation correcte de la sync.Map
	SyncMapDuckyIntegrity = &sync.Map{}
}

func generateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

func AddConnectionToMap(actualTrame string, computeurID string) (string, error) {
	var key string
	const maxRetries = 5

	for i := 0; i < maxRetries; i++ {
		var err error
		key, err = generateRandomKey(10) // Génère une clé de 10 caractères
		if err != nil {
			logs.Write_Log("WARNING", "erreur lors de la génération de la clé LMBD : "+err.Error())
			return "", fmt.Errorf("erreur lors de la génération de la clé : %v", err)
		}

		// Vérifie si la clé existe déjà
		if _, exists := SyncMapDuckyIntegrity.Load(key); !exists {
			// Clé unique, on ajoute l'entrée
			connData := ConnData{
				ActualTrame: actualTrame,
				ComputeurID: computeurID,
				IsSafe:      false,
			}
			SyncMapDuckyIntegrity.Store(key, connData)
			fmt.Println("Entrée ajoutée avec la clé :", key)
			return key, nil
		}
	}

	// Si après 5 essais on n'a pas trouvé de clé unique, on abandonne
	logs.Write_Log("WARNING", "échec de la génération d'une clé unique après tentatives : "+fmt.Sprint(maxRetries))
	return "", fmt.Errorf("échec de la génération d'une clé unique après %d tentatives", maxRetries)
}
