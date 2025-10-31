package configuration_file

import (
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"os"

	yaml "gopkg.in/yaml.v3"
)

func ReadConfigUser[T any](filePath string) (*T, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		logs.Write_Log("WARNING", "erreur lors de la lecture du fichier de configuration: "+err.Error())
	}

	var config T
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		logs.Write_Log("WARNING", "erreur lors du décodage du fichier de configuration: "+err.Error())
	}

	return &config, nil
}

func LoadConfig(filePath string) error {
	// Ouvrir le fichier
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture de la connexion : %v", err))
		}
	}()

	// Initialiser une variable pour stocker les données du fichier
	var config storage.Config

	// Décoder le fichier YAML dans la structure Config
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return err
	}

	if config.Database.Database_iPDatabase != "" {
		storage.Database_iPDatabase = config.Database.Database_iPDatabase
	}
	if config.Database.Database_databaseName != "" {
		storage.Database_databaseName = config.Database.Database_databaseName
	}
	if config.Database.Database_portDatabase != "" {
		storage.Database_portDatabase = config.Database.Database_portDatabase
	}
	if config.Database.Database_password != "" {
		storage.Database_password = config.Database.Database_password
	}
	if config.Database.Database_username != "" {
		storage.Database_username = config.Database.Database_username
	}
	if config.Path.SocketPath != "" {
		storage.SocketPath = config.Path.SocketPath
	}
	if config.Path.Client_Conf_path != "" {
		storage.Client_Conf_path = config.Path.Client_Conf_path
	}
	if config.Path.LogPath != "" {
		storage.LogPath = config.Path.LogPath
	}
	if config.ServerListenPort != "" {
		storage.ServeurLisetenPort = config.ServerListenPort
	}
	if config.Path.PrivateKeyPath != "" {
		storage.PrivateKeyPath = config.Path.PrivateKeyPath
	}
	if config.Path.PublicKeyPath != "" {
		storage.PublicKeyPath = config.Path.PublicKeyPath
	}
	if config.Path.PrivateKeyforlogintoclient != "" {
		storage.PrivateKeyforlogintoclient = config.Path.PrivateKeyforlogintoclient
	}
	if config.Path.PublicKeyforlogintoclient != "" {
		storage.PublicKeyforlogintoclient = config.Path.PublicKeyforlogintoclient
	}

	if config.Ldap.Ldap_Debug {
		storage.Ldap_Debug = config.Ldap.Ldap_Debug
	}
	if config.Ldap.Ldap_Enable {
		storage.Ldap_Enable = config.Ldap.Ldap_Enable
	}
	if config.Dns.Dns_Enable {
		storage.Dns_Enable = config.Dns.Dns_Enable
	}
	if condition := config.Ldap.Ldaps_Enable; condition {
		storage.Ldaps_Enable = config.Ldap.Ldaps_Enable
	}
	if config.Ldap.Ldap_Port != 0 {
		storage.Ldap_Port = config.Ldap.Ldap_Port
	}
	if config.Ldap.Ldaps_Port != 0 {
		storage.Ldaps_Port = config.Ldap.Ldaps_Port
	}
	if config.Website.Website_Enable {
		storage.Website_Enable = config.Website.Website_Enable
	}
	if config.Website.Website_Port != 0 {
		storage.Website_Port = config.Website.Website_Port
	}
	if config.Api.API_Enable {
		storage.API_Enable = config.Api.API_Enable
	}
	if config.Api.API_Port != 0 {
		storage.API_Port = config.Api.API_Port
	}
	if config.Debug.Debug {
		storage.Debug = config.Debug.Debug
	}
	if config.Path.ServerCheckOnlineTimer != 0 {
		storage.ServerCheckOnlineTimer = config.Path.ServerCheckOnlineTimer
	}
	// Retourner la configuration lue
	return nil
}
