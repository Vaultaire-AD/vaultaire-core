package config

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// ServerConfig est un core à joindre.
type ServerConfig struct {
	IP   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

// EnrollmentConfig porte de quoi s'enrôler au premier démarrage.
//
// # Ce qu'elle devient après l'enrôlement
//
// Rien : elle n'est plus lue. L'identité vit alors dans client_software.yaml, et
// la clé d'enrôlement peut être retirée du fichier. La laisser n'a pas d'effet
// mais garde un secret sur le disque sans raison.
type EnrollmentConfig struct {
	Key   string `yaml:"key"`
	Label string `yaml:"label"`
}

// Config est le fichier de configuration du service.
//
//	servers:
//	  - ip: 10.0.0.1
//	    port: 6666
//	enrollment:
//	  key: "..."
//	  label: "proxy-preprod-01"
//
// YAML et non JSON, pour être le même format que celui de vaultaire_client :
// deux formats de configuration dans un même produit obligent à se souvenir
// lequel s'applique où, et cette hésitation se paie à chaque intervention.
type Config struct {
	Servers    []ServerConfig   `yaml:"servers"`
	Enrollment EnrollmentConfig `yaml:"enrollment"`
}

var configPath string

// LoadConfig lit le fichier YAML, y superpose l'environnement, et met à jour la
// configuration globale.
//
// # Le fichier est FACULTATIF
//
// Son absence n'est pas une erreur si l'environnement porte le nécessaire :
// c'est le mode de déploiement en conteneur, où deux variables suffisent et où
// monter un fichier pour les tenir n'aurait rien à contenir de plus.
//
// Les autres erreurs de lecture — droits, fichier illisible — restent fatales :
// elles signalent un problème de déploiement, pas une intention.
func LoadConfig(filePath string) error {
	var config Config

	data, err := os.ReadFile(filePath)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("configuration %s illisible : %w", filePath, err)
		}
	case !os.IsNotExist(err):
		return fmt.Errorf("lecture de %s : %w", filePath, err)
	}

	if err := applyEnv(&config); err != nil {
		return err
	}

	// configPath n'est retenu QU'APRÈS une lecture réussie.
	//
	// Le retenir avant ferait qu'un ReloadConfig suivant un chargement échoué
	// tenterait de relire le même fichier fautif, en signalant cette fois une
	// erreur de rechargement — un symptôme qui ne désigne plus la vraie cause.
	configPath = filePath
	configMutex.Lock()
	Configuration = config
	configMutex.Unlock()
	return nil
}

// SaveConfig écrit une nouvelle configuration.
func SaveConfig(newConfig Config) error {
	if configPath == "" {
		return fmt.Errorf("aucun fichier de configuration chargé")
	}
	data, err := yaml.Marshal(newConfig)
	if err != nil {
		return err
	}
	// 0640 : la clé d'enrôlement est un secret. Un fichier lisible par tous
	// laisserait n'importe quel compte de la machine enrôler un service.
	if err := os.WriteFile(configPath, data, 0640); err != nil {
		return err
	}
	logs.Write_log("INFO", "configuration écrite dans "+configPath)
	return nil
}

// ReloadConfig recharge depuis le fichier courant.
func ReloadConfig() error {
	if configPath == "" {
		return fmt.Errorf("aucun fichier de configuration chargé")
	}
	return LoadConfig(configPath)
}

// GetEnrollment rend la section d'enrôlement.
func GetEnrollment() EnrollmentConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return Configuration.Enrollment
}
