package config

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"encoding/json"
	"fmt"
	"os"
)

type ServerConfig struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type Config struct {
	Servers []ServerConfig `json:"servers"`
}

var configPath string

// LoadConfig charge le fichier JSON et met à jour la configuration globale
func LoadConfig(filePath string) error {

	configPath = filePath

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	defer func() {
		if err := file.Close(); err != nil {
			logs.Write_log("ERROR", fmt.Sprintf(
				"Erreur fermeture fichier configuration: %v",
				err,
			))
		}
	}()

	var config Config

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return err
	}

	Configuration = config

	return nil
}

// SaveConfig écrit une nouvelle configuration dans le fichier JSON
func SaveConfig(newConfig Config) error {

	data, err := json.MarshalIndent(
		newConfig,
		"",
		"    ",
	)

	if err != nil {
		return err
	}

	err = os.WriteFile(
		configPath,
		data,
		0640,
	)

	if err != nil {
		return err
	}

	return nil
}

// ReloadConfig recharge la configuration depuis le fichier actuel
func ReloadConfig() error {

	if configPath == "" {
		return fmt.Errorf("aucun fichier de configuration chargé")
	}

	return LoadConfig(configPath)
}
