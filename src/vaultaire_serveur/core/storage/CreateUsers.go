package storage

type NewClientSoftware struct {
	NewClient struct {
		Computeur_id  string `yaml:"computeur_id"`
		Logiciel_type string `yaml:"logiciel_type"`
		IsServeur     bool   `yaml:"isServeur"`
	} `yaml:"client_software"`
}

// Structure pour la configuration du serveur
type ServerConfig struct {
	Server struct {
		Port     int    `yaml:"port"`
		LogLevel string `yaml:"logLevel"`
	} `yaml:"server"`
}
