package configuration_file

import (
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"fmt"
	"os"

	yaml "gopkg.in/yaml.v3"
)

func ReadConfigUser[T any](filePath string) (*T, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		logs.Write_Log("WARNING", "erreur lors de la lecture du fichier de configuration: "+err.Error())
		return nil, err
	}

	var config T
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		logs.Write_Log("WARNING", "erreur lors du décodage du fichier de configuration: "+err.Error())
		return nil, err
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
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur lors de la fermeture du fichier : %v", err))
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

	// Load configuration with env overrides for sensitive data
	if val := os.Getenv("VAULTAIRE_DB_USERNAME"); val != "" {
		storage.Database_username = val
	} else if config.Database.Database_username != nil {
		storage.Database_username = *config.Database.Database_username
	}

	if val := os.Getenv("VAULTAIRE_DB_PASSWORD"); val != "" {
		storage.Database_password = val
	} else if config.Database.Database_password != nil {
		storage.Database_password = *config.Database.Database_password
	}

	if config.Database.Database_iPDatabase != nil {
		storage.Database_iPDatabase = *config.Database.Database_iPDatabase
	}
	if config.Database.Database_portDatabase != nil {
		storage.Database_portDatabase = *config.Database.Database_portDatabase
	}
	if config.Database.Database_databaseName != nil {
		storage.Database_databaseName = *config.Database.Database_databaseName
	}

	if config.Path.SocketPath != nil {
		storage.SocketPath = *config.Path.SocketPath
	}
	if config.Path.Client_Conf_path != nil {
		storage.Client_Conf_path = *config.Path.Client_Conf_path
	}
	if config.Path.LogPath != nil {
		storage.LogPath = *config.Path.LogPath
	}
	if config.ServerListenPort != nil {
		storage.ServeurLisetenPort = *config.ServerListenPort
	}
	if config.Path.PrivateKeyPath != nil {
		storage.PrivateKeyPath = *config.Path.PrivateKeyPath
	}
	if config.Path.PublicKeyPath != nil {
		storage.PublicKeyPath = *config.Path.PublicKeyPath
	}
	if config.Path.PrivateKeyforlogintoclient != nil {
		storage.PrivateKeyforlogintoclient = *config.Path.PrivateKeyforlogintoclient
	}
	if config.Path.PublicKeyforlogintoclient != nil {
		storage.PublicKeyforlogintoclient = *config.Path.PublicKeyforlogintoclient
	}

	if config.Ldap.Ldap_Debug != nil {
		storage.Ldap_Debug = *config.Ldap.Ldap_Debug
	}
	if config.Ldap.Ldap_Enable != nil {
		storage.Ldap_Enable = *config.Ldap.Ldap_Enable
	}
	if config.Dns.Dns_Enable != nil {
		storage.Dns_Enable = *config.Dns.Dns_Enable
	}
	if config.Ldap.Ldaps_Enable != nil {
		storage.Ldaps_Enable = *config.Ldap.Ldaps_Enable
	}
	if config.Ldap.Ldap_Port != nil {
		storage.Ldap_Port = *config.Ldap.Ldap_Port
	}
	if config.Ldap.Ldaps_Port != nil {
		storage.Ldaps_Port = *config.Ldap.Ldaps_Port
	}
	if config.Website.Website_Enable != nil {
		storage.Website_Enable = *config.Website.Website_Enable
	}
	if config.Website.Website_Port != nil {
		storage.Website_Port = *config.Website.Website_Port
	}
	if config.Api.API_Enable != nil {
		storage.API_Enable = *config.Api.API_Enable
	}
	if config.Api.API_Port != nil {
		storage.API_Port = *config.Api.API_Port
	}
	if config.Debug.Debug != nil {
		storage.Debug = *config.Debug.Debug
	}
	if config.Path.ServerCheckOnlineTimer != nil {
		storage.ServerCheckOnlineTimer = *config.Path.ServerCheckOnlineTimer
	}

	// Administrateur settings
	if config.Administrateur.Enable != nil {
		storage.Administrateur_Enable = *config.Administrateur.Enable
	}

	if val := os.Getenv("VAULTAIRE_ADMIN_USERNAME"); val != "" {
		storage.Administrateur_Username = val
	} else if config.Administrateur.Username != nil {
		storage.Administrateur_Username = *config.Administrateur.Username
	}

	if val := os.Getenv("VAULTAIRE_ADMIN_PASSWORD"); val != "" {
		storage.Administrateur_Password = val
	} else if config.Administrateur.Password != nil {
		storage.Administrateur_Password = *config.Administrateur.Password
	}

	if config.Administrateur.PublicKey != nil {
		storage.Administrateur_PublicKey = *config.Administrateur.PublicKey
	}

	// Retourner la configuration lue
	return nil
}
