package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds vaultaire_proxy configuration.
type Config struct {
	CoreAddress string `yaml:"core_address"` // host:port du Core (ducky-network)
	Identity    struct {
		ComputeurID   string `yaml:"computeur_id"`    // ID logiciel (pré-enregistré sur le Core)
		PrivateKeyPEM string `yaml:"private_key_pem"` // Clé privée PEM (ou chemin vers fichier)
		ServerPubKey  string `yaml:"server_pub_key"`  // Clé publique du serveur Core PEM (ou chemin)
	} `yaml:"identity"`
	Proxy struct {
		Hostname string `yaml:"hostname"`
		FQDN     string `yaml:"fqdn"`
		Domain   string `yaml:"domain"` // ex: proxy.vaultaire.fr
		Role     string `yaml:"role"`   // ex: proxy
	} `yaml:"proxy"`
	LDAPListen  string `yaml:"ldap_listen"`  // ex: :3890
	DuckyListen string `yaml:"ducky_listen"` // ex: :6667
}

// Load reads config from path (YAML).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Proxy.Role == "" {
		c.Proxy.Role = "proxy"
	}
	return &c, nil
}
