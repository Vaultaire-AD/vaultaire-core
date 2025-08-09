package yaml

import (
	"fmt"
	"os"
	"vaultaire_client/logs"
	"vaultaire_client/storage"

	"gopkg.in/yaml.v2"
)

// Fonction pour lire et analyser un fichier YAML
func ReadYAMLFile(filename string) {
	dbConfig, _ := readConfig[storage.ClientSoftware](filename)
	storage.Computeur_ID = dbConfig.NewClient.Computeur_id
	storage.LogicielType = dbConfig.NewClient.Logiciel_type
	storage.IsServeur = dbConfig.NewClient.IsServeur
}

func readConfig[T any](filePath string) (*T, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		logs.WriteLog("error", "erreur lors de la lecture du fichier de configuration: %v")
		return nil, fmt.Errorf("erreur lors de la lecture du fichier de configuration: %v", err)
	}

	var config T
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("erreur lors du décodage du fichier de configuration: %v", err)
	}

	return &config, nil
}
