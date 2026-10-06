package yaml

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ReadYAMLFile lit l'identité de la machine et la pose dans le socle.
//
// Rend faux quand le fichier est absent ou illisible — l'appelant décide alors
// quoi en faire.
//
// # Le défaut que le retour ferme
//
// L'erreur de lecture était ignorée (`dbConfig, _ :=`) et le pointeur NUL
// déréférencé juste après : l'agent PANIQUAIT au démarrage quand
// client_software.yaml manquait, avec une trace d'exécution pour seule
// explication — alors que la ligne juste au-dessus, dans le journal, disait
// précisément quel fichier n'avait pas pu être lu.
//
// Le cas n'a rien d'exotique : c'est celui d'une machine dont l'identité n'a pas
// encore été déposée, ou effacée par un nettoyage. Relevé en portant l'agent
// sous Windows, où l'installation manuelle rend le cas fréquent.
func ReadYAMLFile(filename string) bool {
	dbConfig, err := readConfig[storage.ClientSoftware](filename)
	if err != nil || dbConfig == nil {
		return false
	}
	storage.Computeur_ID = dbConfig.NewClient.Computeur_id
	storage.LogicielType = dbConfig.NewClient.Logiciel_type
	storage.IsServeur = dbConfig.NewClient.IsServeur
	return true
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
