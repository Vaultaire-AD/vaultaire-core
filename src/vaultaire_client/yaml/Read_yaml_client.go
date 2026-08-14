package yaml

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"os"

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
	// Write_log et non WriteLog : le second prend une FAMILLE de journal, pas un
	// niveau. Les deux appels déposaient un fichier nommé « error » dans un
	// répertoire que rien ne surveillait — et leur message portait un « %v » qui
	// n'était jamais formaté, donc ne disait pas la cause.
	data, err := os.ReadFile(filePath)
	if err != nil {
		logs.Write_log("ERROR", "lecture du fichier de configuration "+filePath+" : "+err.Error())
		return nil, fmt.Errorf("erreur lors de la lecture du fichier de configuration: %v", err)
	}

	var config T
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		logs.Write_log("ERROR", "décodage du fichier de configuration "+filePath+" : "+err.Error())
		return nil, fmt.Errorf("erreur lors du décodage du fichier de configuration: %v", err)
	}

	return &config, nil
}
